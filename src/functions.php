<?php
/**
 * Core validation functions for Sec-Fetch CSRF Protection.
 *
 * @package SecFetchCSRF
 */

namespace SecFetchCSRF;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Load the State class.
require_once __DIR__ . '/class-state.php';

const VERSION     = '1.0.0';
const TABLE_NAME  = 'csrf_blocked_requests';
const CACHE_GROUP = 'sec_fetch_csrf';

// Sec-Fetch-Site values that indicate safe same-origin requests.
const ALLOWED_SEC_FETCH_SITE = array( 'same-origin', 'none' );

// Default sensitive endpoints where cross-site read requests should be blocked (for logged-in users).
// 'action=logout' is matched on the query string: with nonces inert, a
// cross-site navigation to a logout URL would otherwise log the user out
// with no protection. All state-changing endpoints must still use non-GET
// methods; this list only covers the GETs WordPress core itself emits.
const DEFAULT_SENSITIVE_ENDPOINTS = array(
	'/wp-admin/',
	'/wp-json/',
	'action=logout',
);

/**
 * Get settings with caching.
 *
 * @return array The plugin settings.
 */
function get_plugin_settings(): array {
	if ( null === State::$settings_cache ) {
		$defaults              = array(
			'trust_same_site'     => false,
			'bypass_patterns'     => array(),
			'trusted_origins'     => array(),
			'sensitive_endpoints' => DEFAULT_SENSITIVE_ENDPOINTS,
			'log_all_gets'        => true,
		);
		$saved                 = get_option( 'sec_fetch_csrf_settings', array() );
		State::$settings_cache = wp_parse_args( $saved, $defaults );
	}

	return State::$settings_cache;
}

/**
 * Reset settings cache (call after saving settings).
 *
 * @return void
 */
function reset_settings_cache(): void {
	State::$settings_cache = null;
}

/**
 * Check if URI matches a sensitive endpoint.
 *
 * @param string $uri The request URI to check.
 * @return bool True if URI matches a sensitive endpoint.
 */
function is_sensitive_endpoint( string $uri ): bool {
	$settings = get_plugin_settings();

	foreach ( $settings['sensitive_endpoints'] as $endpoint ) {
		if ( false !== strpos( $uri, $endpoint ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Check if request is exempt via bypass patterns or trusted origins.
 *
 * @param string      $uri    The request URI to check.
 * @param string|null $origin The Origin header value.
 * @return bool True if request is exempt from CSRF checks.
 */
function is_request_exempt( string $uri, ?string $origin ): bool {
	$settings = get_plugin_settings();

	// Check bypass patterns.
	foreach ( $settings['bypass_patterns'] as $pattern ) {
		if ( fnmatch( $pattern, $uri ) ) {
			return true;
		}
	}

	// Check trusted origins.
	if ( null !== $origin && in_array( $origin, $settings['trusted_origins'], true ) ) {
		return true;
	}

	return false;
}

/**
 * Check if Sec-Fetch-Site value is allowed.
 *
 * @param string $value The Sec-Fetch-Site header value.
 * @return bool True if the value indicates a safe request.
 */
function is_sec_fetch_site_allowed( string $value ): bool {
	if ( in_array( $value, ALLOWED_SEC_FETCH_SITE, true ) ) {
		return true;
	}

	// Handle same-site based on settings.
	if ( 'same-site' === $value ) {
		return (bool) get_plugin_settings()['trust_same_site'];
	}

	return false;
}

/**
 * Determine the type of request for response formatting.
 *
 * @param string $uri The request URI.
 * @return string The request type: 'ajax', 'rest', 'admin', or 'frontend'.
 */
function determine_request_type( string $uri ): string {
	if ( false !== strpos( $uri, 'admin-ajax.php' ) ) {
		return 'ajax';
	}
	if ( false !== strpos( $uri, '/wp-json/' ) || false !== strpos( $uri, 'rest_route=' ) ) {
		return 'rest';
	}
	if ( false !== strpos( $uri, '/wp-admin/' ) ) {
		return 'admin';
	}
	return 'frontend';
}

/**
 * Mark Sec-Fetch validation as complete (for wp_verify_nonce safety check).
 *
 * @return void
 */
function mark_validated(): void {
	State::$validated = true;
}

/**
 * Check if Sec-Fetch validation has completed.
 *
 * @return bool True if validation has completed.
 */
function is_validated(): bool {
	return State::$validated;
}
