<?php
/**
 * Tests for is_sensitive_endpoint function.
 *
 * @package SecFetchCSRF
 */

use function SecFetchCSRF\is_sensitive_endpoint;
use function Tests\mock_settings;

beforeEach(
	function () {
		mock_settings();
	}
);

describe(
	'is_sensitive_endpoint',
	function () {

		describe(
			'with default sensitive endpoints',
			function () {

				it(
					'identifies wp-admin paths as sensitive',
					function () {
						expect( is_sensitive_endpoint( '/wp-admin/' ) )->toBeTrue();
						expect( is_sensitive_endpoint( '/wp-admin/admin.php' ) )->toBeTrue();
						expect( is_sensitive_endpoint( '/wp-admin/edit.php?post_type=page' ) )->toBeTrue();
					}
				);

				it(
					'identifies wp-json paths as sensitive',
					function () {
						expect( is_sensitive_endpoint( '/wp-json/' ) )->toBeTrue();
						expect( is_sensitive_endpoint( '/wp-json/wp/v2/posts' ) )->toBeTrue();
						expect( is_sensitive_endpoint( '/wp-json/wc/v3/orders' ) )->toBeTrue();
					}
				);

				it(
					'does not flag frontend paths as sensitive',
					function () {
						expect( is_sensitive_endpoint( '/' ) )->toBeFalse();
						expect( is_sensitive_endpoint( '/about/' ) )->toBeFalse();
						expect( is_sensitive_endpoint( '/blog/my-post/' ) )->toBeFalse();
					}
				);

				it(
					'does not flag wp-login as sensitive by default',
					function () {
						expect( is_sensitive_endpoint( '/wp-login.php' ) )->toBeFalse();
					}
				);
			}
		);

		describe(
			'with custom sensitive endpoints',
			function () {

				beforeEach(
					function () {
						mock_settings(
							array(
								'sensitive_endpoints' => array(
									'/wp-admin/',
									'/wp-json/',
									'/members/',
									'/api/private/',
								),
							)
						);
					}
				);

				it(
					'identifies custom endpoints as sensitive',
					function () {
						expect( is_sensitive_endpoint( '/members/profile/' ) )->toBeTrue();
						expect( is_sensitive_endpoint( '/api/private/data' ) )->toBeTrue();
					}
				);

				it(
					'still identifies default endpoints as sensitive',
					function () {
						expect( is_sensitive_endpoint( '/wp-admin/index.php' ) )->toBeTrue();
						expect( is_sensitive_endpoint( '/wp-json/wp/v2/users' ) )->toBeTrue();
					}
				);
			}
		);
	}
);
