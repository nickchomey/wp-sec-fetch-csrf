<?php
/**
 * Plugin Name: Sec-Fetch CSRF Protection
 * Description: CSRF protection using Sec-Fetch-Site headers. Overrides WordPress nonces to enable HTML caching and sidesteps an entire common class of CSRF attacks.
 * Version: 1.0.0
 * Requires at least: 5.9
 * Requires PHP: 8.1
 * Author: Nick Chomey
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: sec-fetch-csrf
 *
 * @package SecFetchCSRF
 */

namespace SecFetchCSRF;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Load the nonce overrides BEFORE WordPress loads pluggable.php.
// This must happen during plugin load time (before pluggable.php is required).
// Regular plugins are loaded before pluggable.php in wp-settings.php.
require_once __DIR__ . '/src/nonce-overrides.php';

// Load the bootstrap which includes all package files.
require_once __DIR__ . '/src/bootstrap.php';

// Register hooks for validation and admin UI.
register_hooks( __FILE__ );
