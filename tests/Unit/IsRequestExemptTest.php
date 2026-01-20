<?php
/**
 * Tests for is_request_exempt function.
 *
 * @package SecFetchCSRF
 */

use function SecFetchCSRF\is_request_exempt;
use function Tests\mock_settings;

beforeEach(
	function () {
		mock_settings();
	}
);

describe(
	'is_request_exempt',
	function () {

		describe(
			'with default settings (no exemptions)',
			function () {

				it(
					'does not exempt regular requests',
					function () {
						expect( is_request_exempt( '/wp-admin/', null ) )->toBeFalse();
						expect( is_request_exempt( '/wp-json/wp/v2/posts', null ) )->toBeFalse();
						expect( is_request_exempt( '/', null ) )->toBeFalse();
					}
				);

				it(
					'does not exempt requests with unknown origin',
					function () {
						expect( is_request_exempt( '/wp-admin/', 'https://evil.com' ) )->toBeFalse();
					}
				);
			}
		);

		describe(
			'with bypass patterns',
			function () {

				beforeEach(
					function () {
						mock_settings(
							array(
								'bypass_patterns' => array(
									'/wp-json/webhook/*',
									'/api/callback',
									'*/payment-callback*',
								),
							)
						);
					}
				);

				it(
					'exempts URIs matching bypass patterns',
					function () {
						expect( is_request_exempt( '/wp-json/webhook/stripe', null ) )->toBeTrue();
						expect( is_request_exempt( '/wp-json/webhook/', null ) )->toBeTrue();
						expect( is_request_exempt( '/api/callback', null ) )->toBeTrue();
					}
				);

				it(
					'supports wildcard patterns',
					function () {
						expect( is_request_exempt( '/checkout/payment-callback', null ) )->toBeTrue();
						expect( is_request_exempt( '/payment-callback/success', null ) )->toBeTrue();
					}
				);

				it(
					'does not exempt URIs not matching patterns',
					function () {
						expect( is_request_exempt( '/wp-json/wp/v2/posts', null ) )->toBeFalse();
						expect( is_request_exempt( '/api/other', null ) )->toBeFalse();
					}
				);
			}
		);

		describe(
			'with trusted origins',
			function () {

				beforeEach(
					function () {
						mock_settings(
							array(
								'trusted_origins' => array(
									'https://trusted-partner.com',
									'https://payment-gateway.com',
								),
							)
						);
					}
				);

				it(
					'exempts requests from trusted origins',
					function () {
						expect( is_request_exempt( '/wp-admin/', 'https://trusted-partner.com' ) )->toBeTrue();
						expect( is_request_exempt( '/wp-json/api/', 'https://payment-gateway.com' ) )->toBeTrue();
					}
				);

				it(
					'does not exempt requests from untrusted origins',
					function () {
						expect( is_request_exempt( '/wp-admin/', 'https://evil.com' ) )->toBeFalse();
						expect( is_request_exempt( '/wp-admin/', 'https://trusted-partner.com.evil.com' ) )->toBeFalse();
					}
				);

				it(
					'does not exempt requests without origin header',
					function () {
						expect( is_request_exempt( '/wp-admin/', null ) )->toBeFalse();
					}
				);
			}
		);

		describe(
			'with both bypass patterns and trusted origins',
			function () {

				beforeEach(
					function () {
						mock_settings(
							array(
								'bypass_patterns' => array( '/api/webhook' ),
								'trusted_origins' => array( 'https://trusted.com' ),
							)
						);
					}
				);

				it(
					'exempts if URI matches bypass pattern',
					function () {
						expect( is_request_exempt( '/api/webhook', 'https://evil.com' ) )->toBeTrue();
					}
				);

				it(
					'exempts if origin is trusted',
					function () {
						expect( is_request_exempt( '/any/path', 'https://trusted.com' ) )->toBeTrue();
					}
				);

				it(
					'does not exempt if neither matches',
					function () {
						expect( is_request_exempt( '/other/path', 'https://evil.com' ) )->toBeFalse();
					}
				);
			}
		);
	}
);
