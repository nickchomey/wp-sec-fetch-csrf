<?php
/**
 * Tests for is_sec_fetch_site_allowed function.
 *
 * @package SecFetchCSRF
 */

use function SecFetchCSRF\is_sec_fetch_site_allowed;
use function Tests\mock_settings;

beforeEach(
	function () {
		mock_settings();
	}
);

describe(
	'is_sec_fetch_site_allowed',
	function () {

		it(
			'allows same-origin requests',
			function () {
				expect( is_sec_fetch_site_allowed( 'same-origin' ) )->toBeTrue();
			}
		);

		it(
			'allows none (direct navigation)',
			function () {
				expect( is_sec_fetch_site_allowed( 'none' ) )->toBeTrue();
			}
		);

		it(
			'blocks cross-site by default',
			function () {
				expect( is_sec_fetch_site_allowed( 'cross-site' ) )->toBeFalse();
			}
		);

		describe(
			'same-site handling',
			function () {

				it(
					'blocks same-site when trust_same_site is false (default)',
					function () {
						expect( is_sec_fetch_site_allowed( 'same-site' ) )->toBeFalse();
					}
				);

				it(
					'allows same-site when trust_same_site is true',
					function () {
						mock_settings( array( 'trust_same_site' => true ) );

						expect( is_sec_fetch_site_allowed( 'same-site' ) )->toBeTrue();
					}
				);
			}
		);

		it(
			'blocks unknown Sec-Fetch-Site values',
			function () {
				expect( is_sec_fetch_site_allowed( 'unknown' ) )->toBeFalse();
				expect( is_sec_fetch_site_allowed( '' ) )->toBeFalse();
				expect( is_sec_fetch_site_allowed( 'SAME-ORIGIN' ) )->toBeFalse(); // Case sensitive.
			}
		);
	}
);
