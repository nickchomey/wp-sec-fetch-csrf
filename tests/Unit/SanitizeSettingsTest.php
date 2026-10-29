<?php
/**
 * Tests for sanitize_settings bypass-pattern guard.
 *
 * @package SecFetchCSRF
 */

use Brain\Monkey\Functions;
use function SecFetchCSRF\sanitize_settings;
use function Tests\mock_sanitization_functions;

beforeEach(
	function () {
		mock_sanitization_functions();
	}
);

describe(
	'sanitize_settings',
	function () {

		it(
			'refuses match-everything bypass patterns',
			function () {
				Functions\expect( 'add_settings_error' )
					->once()
					->with(
						'sec_fetch_csrf_settings',
						'sec_fetch_csrf_bypass_too_broad',
						Mockery::pattern( '/matches every request/' ),
						'error'
					);

				$result = sanitize_settings(
					array(
						'bypass_patterns' => "*\n/webhook/*",
					)
				);

				expect( $result['bypass_patterns'] )->toEqual( array( '/webhook/*' ) );
			}
		);

		it(
			'keeps scoped bypass patterns untouched',
			function () {
				// No add_settings_error stub: scoped patterns never trigger it.
				$result = sanitize_settings(
					array(
						'bypass_patterns' => "/webhook/*\n/wp-cron.php*",
					)
				);

				expect( $result['bypass_patterns'] )->toEqual( array( '/webhook/*', '/wp-cron.php*' ) );
			}
		);
	}
);
