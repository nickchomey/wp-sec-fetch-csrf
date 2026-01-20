<?php
/**
 * Pest configuration with Brain Monkey setup for WordPress function mocking.
 *
 * This configuration applies to unit tests only (not E2E tests).
 * E2E tests make real HTTP requests and don't need Brain Monkey.
 *
 * @package SecFetchCSRF
 */

use Brain\Monkey;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;

// Apply Mockery integration to unit tests only (exclude E2E).
uses( MockeryPHPUnitIntegration::class )->in( 'Unit' );

// Check if we're running tests that include Unit tests.
// We need to load plugin code for Unit tests but NOT for E2E-only runs.
$running_e2e_only = false;
// phpcs:ignore WordPress.Security.ValidatedInput.InputNotSanitized -- $_SERVER['argv'] is safe in CLI context.
$argv = $_SERVER['argv'] ?? array();
foreach ( $argv as $arg ) {
	if ( str_contains( $arg, 'E2E' ) && ! str_contains( $arg, 'Unit' ) ) {
		$running_e2e_only = true;
		break;
	}
}

// Load plugin code for Unit tests (skip for E2E-only runs).
if ( ! $running_e2e_only ) {
	// Define ABSPATH to allow plugin to load.
	if ( ! defined( 'ABSPATH' ) ) {
		// Navigate up from tests/ -> sec-fetch-csrf/ -> mu-plugins/ -> wp-content/ -> wp/.
		$wp_root = dirname( __DIR__, 4 ) . '/';
		if ( file_exists( $wp_root . 'wp-settings.php' ) ) {
			define( 'ABSPATH', $wp_root );
		} else {
			// Fallback for CI environments or when wp files aren't present.
			define( 'ABSPATH', sys_get_temp_dir() . '/wordpress/' );
		}
	}

	// Define add_action stub before loading the plugin (it's called at file load time).
	if ( ! function_exists( 'add_action' ) ) {
		/**
		 * Stub for add_action.
		 *
		 * @param string   $hook          Hook name.
		 * @param callable $callback      Callback function.
		 * @param int      $priority      Priority.
		 * @param int      $accepted_args Accepted arguments.
		 */
		function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Stub function.
			// No-op stub for loading the plugin.
		}
	}

	// Load the package source files.
	require_once __DIR__ . '/../src/functions.php';
	require_once __DIR__ . '/../src/validation.php';
	require_once __DIR__ . '/../src/logging.php';
	require_once __DIR__ . '/../src/admin.php';
}

// Set up Brain Monkey before each unit test.
beforeEach(
	function () {
		Monkey\setUp();

		// Reset $_SERVER superglobal to clean state.
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['REQUEST_URI']    = '/';
		$_SERVER['HTTP_HOST']      = 'example.com';
		unset( $_SERVER['HTTP_SEC_FETCH_SITE'] );
		unset( $_SERVER['HTTP_SEC_FETCH_MODE'] );
		unset( $_SERVER['HTTP_SEC_FETCH_DEST'] );
		unset( $_SERVER['HTTP_ORIGIN'] );
		unset( $_SERVER['QUERY_STRING'] );

		// Reset plugin state (validation flag and settings cache).
		\SecFetchCSRF\State::reset();
	}
)->in( 'Unit' );

// Tear down Brain Monkey after each unit test.
afterEach(
	function () {
		Monkey\tearDown();
	}
)->in( 'Unit' );
