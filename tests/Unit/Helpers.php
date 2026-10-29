<?php // phpcs:ignore WordPress.Files.Filename
/**
 * Centralized test helpers for Sec-Fetch CSRF Protection plugin tests.
 *
 * These helpers consolidate common mocking patterns used across test files
 * to reduce duplication and ensure consistent test setup.
 *
 * @package SecFetchCSRF
 */

namespace Tests;

use Brain\Monkey\Functions;
use Mockery;

// ============================================================================
// Request Setup Helpers
// ============================================================================

/**
 * Set up $_SERVER variables for a simulated HTTP request.
 *
 * @param string      $method         HTTP method (GET, POST, PUT, DELETE, etc.).
 * @param string      $uri            Request URI path.
 * @param string|null $sec_fetch_site Sec-Fetch-Site header value (null to omit).
 * @param string|null $origin         Origin header value (null to omit).
 * @param string      $host           Host header value.
 */
function setup_request(
	string $method,
	string $uri,
	?string $sec_fetch_site = null,
	?string $origin = null,
	string $host = 'example.com',
	?string $sec_fetch_mode = null,
	?string $sec_fetch_dest = null
): void {
	$_SERVER['REQUEST_METHOD'] = $method;
	$_SERVER['REQUEST_URI']    = $uri;
	$_SERVER['HTTP_HOST']      = $host;

	if ( null !== $sec_fetch_site ) {
		$_SERVER['HTTP_SEC_FETCH_SITE'] = $sec_fetch_site;
	} else {
		unset( $_SERVER['HTTP_SEC_FETCH_SITE'] );
	}

	if ( null !== $sec_fetch_mode ) {
		$_SERVER['HTTP_SEC_FETCH_MODE'] = $sec_fetch_mode;
	} else {
		unset( $_SERVER['HTTP_SEC_FETCH_MODE'] );
	}

	if ( null !== $sec_fetch_dest ) {
		$_SERVER['HTTP_SEC_FETCH_DEST'] = $sec_fetch_dest;
	} else {
		unset( $_SERVER['HTTP_SEC_FETCH_DEST'] );
	}

	if ( null !== $origin ) {
		$_SERVER['HTTP_ORIGIN'] = $origin;
	} else {
		unset( $_SERVER['HTTP_ORIGIN'] );
	}
}

// ============================================================================
// User Mocking Helpers
// ============================================================================

/**
 * Mock a WordPress user (logged-in or logged-out).
 *
 * Sets up is_user_logged_in(), wp_get_current_user(), and get_current_user_id()
 * to return appropriate values for the login state.
 *
 * @param bool $logged_in Whether the user should appear logged in.
 * @param int  $user_id   User ID (0 for logged-out, positive for logged-in).
 */
function setup_user( bool $logged_in, int $user_id = 1 ): void {
	$effective_user_id = $logged_in ? $user_id : 0;

	$user     = Mockery::mock( 'WP_User' );
	$user->ID = $effective_user_id;
	$user->shouldReceive( 'exists' )->andReturn( $logged_in );

	Functions\when( 'is_user_logged_in' )->justReturn( $logged_in );
	Functions\when( 'wp_get_current_user' )->justReturn( $user );
	Functions\when( 'get_current_user_id' )->justReturn( $effective_user_id );
}

// ============================================================================
// Settings Mocking Helpers
// ============================================================================

/**
 * Reset and mock plugin settings.
 *
 * Clears the settings cache and sets up get_option() to return the
 * specified settings (merged with defaults via wp_parse_args).
 *
 * @param array $overrides Settings to override defaults.
 */
function mock_settings( array $overrides = array() ): void {
	\SecFetchCSRF\State::$settings_cache = null;

	Functions\when( 'get_option' )->justReturn( $overrides );
	Functions\when( 'wp_parse_args' )->alias( fn( $args, $defaults ) => array_merge( $defaults, $args ) );
}

// ============================================================================
// Database Mocking Helpers
// ============================================================================

/**
 * Mock the global $wpdb object for database operations.
 *
 * Sets up a Mockery mock that accepts insert() calls (used by log_request).
 *
 * @return Mockery\MockInterface The mocked wpdb object.
 */
function mock_database(): Mockery\MockInterface {
	global $wpdb;
	$wpdb         = Mockery::mock( 'wpdb' ); // phpcs:ignore WordPress.Variables.GlobalVariables
	$wpdb->prefix = 'wp_';
	$wpdb->shouldReceive( 'insert' )->andReturn( true );
	$wpdb->shouldReceive( 'prepare' )->andReturnUsing( fn( $query ) => $query );
	$wpdb->shouldReceive( 'get_var' )->andReturn( 0 );

	return $wpdb;
}

// ============================================================================
// WordPress Function Mocking Helpers
// ============================================================================

/**
 * Mock cache functions (wp_cache_get, wp_cache_set, wp_cache_delete).
 *
 * Sets up no-op implementations that return expected values.
 */
function mock_cache_functions(): void {
	Functions\when( 'wp_cache_get' )->justReturn( false );
	Functions\when( 'wp_cache_set' )->justReturn( true );
	Functions\when( 'wp_cache_delete' )->justReturn( true );
}

/**
 * Mock sanitization functions used by log_request.
 *
 * Sets up pass-through implementations for sanitize_text_field, sanitize_url, wp_unslash, and wp_kses_post.
 */
function mock_sanitization_functions(): void {
	Functions\when( 'sanitize_text_field' )->alias( fn( $str ) => $str );
	Functions\when( 'sanitize_url' )->alias( fn( $str ) => $str );
	Functions\when( 'wp_unslash' )->alias( fn( $str ) => $str );
	Functions\when( 'wp_kses_post' )->alias( fn( $str ) => $str );
	// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Mocking wp_json_encode.
	Functions\when( 'wp_json_encode' )->alias( fn( $data ) => json_encode( $data ) );
	// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Mocking wp_parse_url.
	Functions\when( 'wp_parse_url' )->alias( fn( $url, $component = -1 ) => parse_url( $url, $component ) );
}

/**
 * Mock esc_html for output escaping.
 */
function mock_escape_function(): void {
	Functions\when( 'esc_html' )->alias( fn( $str ) => htmlspecialchars( $str, ENT_QUOTES, 'UTF-8' ) );
}

/**
 * Mock current_time for timestamps.
 *
 * @param string $time The time string to return (default: '2025-01-01 00:00:00').
 */
function mock_current_time( string $time = '2025-01-01 00:00:00' ): void {
	Functions\when( 'current_time' )->justReturn( $time );
}

// ============================================================================
// Blocking Behavior Helpers
// ============================================================================

/**
 * Mock wp_die to throw an exception instead of exiting.
 *
 * This allows tests to catch blocked requests and verify the blocking behavior.
 * The exception message includes the wp_die message for assertion.
 */
function mock_wp_die_throws(): void {
	Functions\when( 'wp_die' )->alias(
		function ( $message ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Test helper, message is for assertions only.
			throw new \RuntimeException( 'blocked: ' . strip_tags( $message ) );
		}
	);
}

/**
 * Set up all mocks needed when a request might be blocked.
 *
 * This is the "kitchen sink" helper for tests that verify blocking behavior.
 * It sets up: database, cache, sanitization, escaping, timestamps, and wp_die.
 */
function mock_blocking_behavior(): void {
	mock_settings();
	mock_database();
	mock_cache_functions();
	mock_sanitization_functions();
	mock_escape_function();
	mock_current_time();
	mock_wp_die_throws();
}

/**
 * Set up common mocks for tests that don't expect blocking.
 *
 * Lighter-weight setup for tests verifying allowed requests.
 * Sets up: settings, cache, database, sanitization, timestamps.
 */
function mock_allowed_request_behavior(): void {
	mock_settings();
	mock_cache_functions();
	mock_database();
	mock_sanitization_functions();
	mock_current_time();
}
