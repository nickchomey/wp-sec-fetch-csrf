<?php
/**
 * Request validation and blocking for Sec-Fetch CSRF Protection.
 *
 * @package SecFetchCSRF
 */

namespace SecFetchCSRF;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Main CSRF validation - runs on every request.
 *
 * Blocks bad requests (dies), marks validated for allowed requests.
 *
 * @return void
 */
function validate_request(): void {
	// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- These are read-only checks on server headers.
	$method         = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
	$uri            = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
	$sec_fetch_site = isset( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ) : null;
	$sec_fetch_mode = isset( $_SERVER['HTTP_SEC_FETCH_MODE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_SEC_FETCH_MODE'] ) ) : null;
	$sec_fetch_dest = isset( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ) : null;
	$origin         = isset( $_SERVER['HTTP_ORIGIN'] ) ? sanitize_url( wp_unslash( $_SERVER['HTTP_ORIGIN'] ) ) : null;
	$host           = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '';
	// phpcs:enable

	// Normalize: browsers send lowercase per spec, but proxies may alter case
	// or pad whitespace. Compare canonically and stay fail-closed on unknown.
	if ( is_string( $sec_fetch_site ) ) {
		$sec_fetch_site = strtolower( trim( $sec_fetch_site ) );
	}

	$is_read_request = in_array( $method, array( 'GET', 'HEAD', 'OPTIONS' ), true );

	// Exempt internal WordPress operations that don't have Sec-Fetch headers.
    // wp-cron.php is triggered internally by WordPress and has no browser headers.
    if ( false !== strpos( $uri, 'wp-cron.php' ) ) {
        mark_validated();
        return;
    }

	// Quick exit for same-origin requests (most common case).
	// No need to load settings or do further checks.
	// 'none' is only ever sent for navigations, never for form submissions or
	// fetch(), so it fast-paths reads only: none writes fall through to the
	// Origin check below instead of being trusted unconditionally.
	if ( 'same-origin' === $sec_fetch_site || ( 'none' === $sec_fetch_site && $is_read_request ) ) {
		mark_validated();
		return;
	}

	$is_cross_site = null !== $sec_fetch_site && ! is_sec_fetch_site_allowed( $sec_fetch_site );

	// Check Sec-Fetch-Site header (primary method).
	if ( $is_cross_site ) {
		if ( $is_read_request ) {
			// Read requests: only block logged-in users accessing sensitive endpoints.
			if ( \is_user_logged_in() ) {
				if ( is_sensitive_endpoint( $uri ) && ! is_request_exempt( $uri, $origin ) ) {
					// Logout is core's state-changing GET: top-level navigations to
					// it are never allowed through here.
					$is_logout = false !== strpos( $uri, 'action=logout' );
					// Ordinary top-level document navigations (address bar, links,
					// new tabs, including ones driven by a cross-origin embedder)
					// are allowed only under the explicit opt-in: no header
					// distinguishes the operator's own embedder from an
					// attacker's page, so this stays off unless the site is
					// deliberately operated through one.
					$is_top_level_nav    = 'navigate' === $sec_fetch_mode && 'document' === $sec_fetch_dest;
					// The allowance is development-only: a cross-origin embedder is a
					// dev-panel shape, and the setting must be inert everywhere else
					// no matter how it is stored. The function_exists guard fails
					// closed when the function is unavailable.
					$development_only    = function_exists( 'wp_get_environment_type' ) && 'development' === wp_get_environment_type();
					$navigations_allowed = ! $is_logout && $is_top_level_nav && $development_only && get_plugin_settings()['allow_top_level_navigations'];
					if ( $navigations_allowed ) {
						log_request(
							"Cross-site {$method} top-level navigation allowed (opt-in): Sec-Fetch-Site={$sec_fetch_site}",
							$method,
							$uri,
							false
						);
						mark_validated();

						return;
					}
					block_request(
						"Cross-site {$method} to sensitive endpoint blocked: Sec-Fetch-Site={$sec_fetch_site}",
						$method,
						$uri
					);
				}
				// Log allowed cross-site read requests (blocked ones logged by block_request).
				if ( get_plugin_settings()['log_all_gets'] ) {
					log_request(
						"Cross-site {$method} allowed (logged-in): Sec-Fetch-Site={$sec_fetch_site}",
						$method,
						$uri,
						false
					);
				}
			}
		} elseif ( ! is_request_exempt( $uri, $origin ) ) {
			// Write requests: block unless exempt.
			block_request(
				"Cross-site {$method} blocked: Sec-Fetch-Site={$sec_fetch_site}",
				$method,
				$uri
			);
		}
	}

	// Fallback for write requests without a trustworthy Sec-Fetch-Site value.
	// Modern browsers send Sec-Fetch-Site, but we need to handle:
	// - 'none' (navigations, extensions): never sent for writes, so a write
	//   claiming it goes through the Origin check instead of being trusted.
	// - Browsers that don't support Sec-Fetch-Site (use Origin header).
	// - Non-browser clients (curl, scripts) - no headers at all.
	if ( ! $is_read_request && ( null === $sec_fetch_site || 'none' === $sec_fetch_site ) && ! is_request_exempt( $uri, $origin ) ) {
		if ( null === $origin ) {
			// No Sec-Fetch-Site AND no Origin - likely non-browser client or legacy browser.
			block_request(
				'Write request blocked: No Sec-Fetch-Site or Origin header (non-browser client or legacy browser)',
				$method,
				$uri
			);
		}

		// wp_parse_url() extracts components from a URL string.
		// PHP_URL_HOST returns just the hostname (e.g., 'example.com' from 'https://example.com:8080/path').
		$origin_host  = wp_parse_url( $origin, PHP_URL_HOST );
		$request_host = explode( ':', $host )[0]; // Strip port from Host header.

		if ( null === $origin_host || false === $origin_host ) {
			// Malformed Origin header (wp_parse_url returns null/false for invalid URLs).
			block_request(
				"Cross-origin request blocked: Malformed Origin header: {$origin}",
				$method,
				$uri
			);
		} elseif ( $origin_host !== $request_host ) {
			// Origin doesn't match Host - cross-origin request.
			block_request(
				"Cross-origin request blocked: Origin={$origin} does not match Host={$host}",
				$method,
				$uri
			);
		}
	}

	// If we reach here, request is allowed.
	// (block_request calls exit, so we only get here for allowed requests).
	mark_validated();
}

/**
 * Block a request and send appropriate error response.
 *
 * This function always exits (dies) - it never returns.
 *
 * @param string $reason The reason for blocking.
 * @param string $method The HTTP request method.
 * @param string $uri    The request URI.
 * @return void
 */
function block_request( string $reason, string $method, string $uri ): void {
	// Prevent caching of error responses.
	header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
	header( 'Pragma: no-cache' );

	log_request( $reason, $method, $uri, true );

	$type = determine_request_type( $uri );

	// JSON responses for AJAX/REST.
	if ( 'ajax' === $type || 'rest' === $type ) {
		$data = array(
			'message' => 'CSRF validation failed',
			'reason'  => $reason,
		);
		if ( 'rest' === $type ) {
			$data['code']   = 'csrf_validation_failed';
			$data['status'] = 403;
		}

		// wp_send_json_error sets 200 by default, so set 403 first.
		http_response_code( 403 );
		if ( function_exists( 'wp_send_json_error' ) ) {
			wp_send_json_error( $data ); // This calls exit.
		}
		header( 'Content-Type: application/json; charset=utf-8' );
		echo wp_json_encode(
			array(
				'success' => false,
				'data'    => $data,
			)
		);
		exit;
	}

	// HTML responses for admin/frontend - wp_die handles everything.
	$message = '<h1>CSRF Validation Failed</h1><p>' .
	( function_exists( 'esc_html' ) ? esc_html( $reason ) : htmlspecialchars( $reason, ENT_QUOTES, 'UTF-8' ) ) .
	'</p>';

	if ( function_exists( 'wp_die' ) ) {
		wp_die(
			wp_kses_post( $message ),
			'CSRF Validation Failed',
			array(
				'response'  => 403,
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Boolean value in array, not output.
				'back_link' => ( 'admin' === $type ),
			)
		); // This calls exit.
	}

	// Fallback if wp_die not available.
	http_response_code( 403 );
	header( 'Content-Type: text/html; charset=utf-8' );
	// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $message is already escaped above.
	echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>' . $message . '</body></html>';
	exit;
}
