<?php
/**
 * Bootstrap for Sec-Fetch CSRF Protection
 *
 * This file loads all package components and provides the init() function.
 *
 * @package   SecFetchCSRF
 * @author    Nick Starter
 * @license   GPL-2.0-or-later
 * @link      https://github.com/starter/sec-fetch-csrf
 */

namespace SecFetchCSRF;

// Prevent direct access (skip check when running tests).
if ( ! defined( 'ABSPATH' ) && ! defined( 'SEC_FETCH_CSRF_TESTING' ) ) {
	exit;
}

// Load all component files.
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/validation.php';
require_once __DIR__ . '/logging.php';
require_once __DIR__ . '/admin.php';

/**
 * Register all plugin hooks.
 *
 * Called from the main plugin file with __FILE__ to properly register
 * activation/deactivation hooks. Uses __NAMESPACE__ to avoid hardcoding.
 *
 * @param string $plugin_file The main plugin file path (__FILE__ from sec-fetch-nonces.php).
 * @return void
 */
function register_hooks( string $plugin_file ): void {
	// Register activation hook - creates database table.
	register_activation_hook( $plugin_file, __NAMESPACE__ . '\activate' );

	// Register deactivation hook - cleanup if needed.
	register_deactivation_hook( $plugin_file, __NAMESPACE__ . '\deactivate' );

	// CSRF validation runs on plugins_loaded so is_user_logged_in() is available.
	add_action( 'plugins_loaded', __NAMESPACE__ . '\validate_request', 1 );

	// Admin UI hooks.
	add_action( 'admin_menu', __NAMESPACE__ . '\add_admin_menu' );
	add_action( 'admin_init', __NAMESPACE__ . '\register_settings' );
	add_action( 'admin_init', __NAMESPACE__ . '\handle_admin_actions' );
	add_action( 'admin_notices', __NAMESPACE__ . '\show_admin_notice' );
}

/**
 * Plugin activation hook - creates database table.
 *
 * Called when the plugin is activated via WordPress admin.
 * This is the proper place for one-time setup like table creation.
 *
 * @return void
 */
function activate(): void {
	// Create the database table.
	create_table();

	// Reset in-memory settings cache.
	State::reset();
}

/**
 * Plugin deactivation hook.
 *
 * Called when the plugin is deactivated via WordPress admin.
 * Note: We don't delete the table or settings here - that's for uninstall.php.
 *
 * @return void
 */
function deactivate(): void {
	// Reset in-memory state.
	State::reset();
}
