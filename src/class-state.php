<?php
/**
 * Plugin state container class.
 *
 * @package SecFetchCSRF
 */

namespace SecFetchCSRF;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin state container.
 *
 * Uses static properties instead of globals for better encapsulation.
 */
class State {

	/**
	 * Whether Sec-Fetch-Site validation has completed.
	 *
	 * @var bool
	 */
	public static bool $validated = false;

	/**
	 * Cached settings array.
	 *
	 * @var array|null
	 */
	public static ?array $settings_cache = null;

	/**
	 * Reset all state (useful for testing).
	 *
	 * @return void
	 */
	public static function reset(): void {
		self::$validated      = false;
		self::$settings_cache = null;
	}
}
