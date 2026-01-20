<?php
/**
 * Tests for determine_request_type function.
 *
 * @package SecFetchCSRF
 */

use function SecFetchCSRF\determine_request_type;

describe(
	'determine_request_type',
	function () {

		it(
			'identifies admin-ajax.php as ajax',
			function () {
				expect( determine_request_type( '/wp-admin/admin-ajax.php' ) )->toBe( 'ajax' );
			}
		);

		it(
			'identifies admin-ajax.php with query string as ajax',
			function () {
				expect( determine_request_type( '/wp-admin/admin-ajax.php?action=my_action' ) )->toBe( 'ajax' );
			}
		);

		it(
			'identifies /wp-json/ paths as rest',
			function () {
				expect( determine_request_type( '/wp-json/wp/v2/posts' ) )->toBe( 'rest' );
			}
		);

		it(
			'identifies rest_route query parameter as rest',
			function () {
				expect( determine_request_type( '/?rest_route=/wp/v2/posts' ) )->toBe( 'rest' );
			}
		);

		it(
			'identifies /wp-admin/ paths as admin',
			function () {
				expect( determine_request_type( '/wp-admin/edit.php' ) )->toBe( 'admin' );
			}
		);

		it(
			'identifies /wp-admin/post.php as admin',
			function () {
				expect( determine_request_type( '/wp-admin/post.php?post=123&action=edit' ) )->toBe( 'admin' );
			}
		);

		it(
			'identifies frontend paths as frontend',
			function () {
				expect( determine_request_type( '/about-us/' ) )->toBe( 'frontend' );
			}
		);

		it(
			'identifies root path as frontend',
			function () {
				expect( determine_request_type( '/' ) )->toBe( 'frontend' );
			}
		);

		it(
			'identifies wp-login.php as frontend',
			function () {
				// wp-login.php is not in wp-admin, so it's frontend.
				expect( determine_request_type( '/wp-login.php' ) )->toBe( 'frontend' );
			}
		);

		it(
			'prioritizes ajax over admin for admin-ajax.php',
			function () {
				// admin-ajax.php is in wp-admin but should be identified as ajax.
				$result = determine_request_type( '/wp-admin/admin-ajax.php' );
				expect( $result )->toBe( 'ajax' );
			}
		);

		it(
			'prioritizes rest over admin for wp-json in wp-admin context',
			function () {
				// Edge case: wp-json path should be rest even if somehow in admin context.
				$result = determine_request_type( '/wp-json/wp/v2/posts' );
				expect( $result )->toBe( 'rest' );
			}
		);
	}
);
