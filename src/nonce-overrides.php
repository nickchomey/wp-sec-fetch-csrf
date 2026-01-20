<?php
/**
 * Pluggable function overrides for nonces
 *
 * Must be in global namespace to override WordPress pluggable functions.
 * These must be loaded BEFORE WordPress loads pluggable.php (during MU plugin load).
 *
 * @package SecFetchCSRF
 * @author  Nick Starter
 * @license GPL-2.0-or-later
 * @link    https://github.com/starter/sec-fetch-csrf
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! function_exists( 'wp_verify_nonce' ) ) {
	/**
	 * Override wp_verify_nonce - CSRF is handled by Sec-Fetch-Site.
	 *
	 * Since CSRF protection is handled by Sec-Fetch-Site headers at the request level,
	 * nonce verification becomes redundant. This enables HTML caching.
	 *
	 * @param string $nonce Nonce value to verify.
	 * @return int|false 1 if valid, false otherwise.
	 */
	function wp_verify_nonce( $nonce ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound -- Overriding pluggable function.
		if ( empty( $nonce ) ) {
			return false;
		}

		// Safety check: ensure Sec-Fetch-Site validation has run.
		// If it hasn't, something is wrong - fail closed.
		if ( ! SecFetchCSRF\is_validated() ) {
			// Log this unexpected situation. phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional logging for security monitoring.
			if ( function_exists( 'error_log' ) ) {
				error_log( 'SecFetchCSRF: wp_verify_nonce called before validate_request completed' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			}
			return false;
		}

		// CSRF protection handled by Sec-Fetch-Site validation.
		// Return valid (1 = generated 0-12 hours ago).
		return 1;
	}
}

if ( ! function_exists( 'wp_create_nonce' ) ) {
	/**
	 * Override wp_create_nonce - Simplified nonce generation.
	 *
	 * Generates a cacheable nonce that is only a hash of user id and action.
	 * No time component or session token - making it suitable for cached pages.
	 *
	 * @param string|int $action Scalar value to add context to the nonce. Default -1.
	 * @return string The generated nonce token.
	 */
	function wp_create_nonce( $action = -1 ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound -- Overriding pluggable function.
		static $nonce_cache = array();

		$user = wp_get_current_user();
		$uid  = (int) $user->ID;

		if ( ! $uid ) {
			$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );
		}

		$cache_key = $action . '|' . $uid;

		if ( isset( $nonce_cache[ $cache_key ] ) ) {
			return $nonce_cache[ $cache_key ];
		}

		// Simple hash of user id and action - no time/session components.
		$nonce                     = substr( wp_hash( $cache_key, 'nonce' ), -12, 10 );
		$nonce_cache[ $cache_key ] = $nonce;

		return $nonce;
	}
}
