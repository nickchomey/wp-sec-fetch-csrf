<?php
/**
 * Tests for validate_request() - GET/HEAD/OPTIONS request handling.
 *
 * @package SecFetchCSRF
 */

use function SecFetchCSRF\validate_request;
use function SecFetchCSRF\is_validated;
use function Tests\{setup_request, setup_user, mock_settings, mock_allowed_request_behavior, mock_blocking_behavior};
use Brain\Monkey\Functions;

beforeEach(
	function () {
		\SecFetchCSRF\State::reset();
		mock_allowed_request_behavior();
	}
);

describe(
	'validate_request GET requests',
	function () {

		it(
			'allows same-origin GET requests and marks validated',
			function () {
				setup_request( 'GET', '/wp-admin/', 'same-origin' );
				setup_user( true );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'allows GET to non-sensitive endpoints for logged-out users even if cross-site',
			function () {
				setup_request( 'GET', '/public/page/', 'cross-site' );
				setup_user( false );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'allows GET to non-sensitive endpoints for logged-in users even if cross-site',
			function () {
				setup_request( 'GET', '/public/page/', 'cross-site' );
				setup_user( true );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'blocks cross-site GET to sensitive endpoint for logged-in user',
			function () {
				mock_blocking_behavior();
				setup_request( 'GET', '/wp-admin/admin.php', 'cross-site' );
				setup_user( true );

				expect( fn() => validate_request() )
				->toThrow( RuntimeException::class, 'blocked' );
			}
		);

		it(
			'allows cross-site GET to sensitive endpoint for logged-out user',
			function () {
				setup_request( 'GET', '/wp-admin/admin.php', 'cross-site' );
				setup_user( false );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'allows HEAD requests same as GET',
			function () {
				setup_request( 'HEAD', '/wp-admin/', 'same-origin' );
				setup_user( true );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'allows OPTIONS requests same as GET',
			function () {
				setup_request( 'OPTIONS', '/wp-json/wp/v2/posts', 'cross-site' );
				setup_user( false );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'blocks cross-site logout GET for logged-in user',
			function () {
				setup_request( 'GET', '/wp-login.php?action=logout', 'cross-site' );
				setup_user( true );

				expect( fn() => validate_request() )
				->toThrow( RuntimeException::class, 'blocked' );
			}
		);

		it(
			'allows cross-site login page GET without logout action for logged-in user',
			function () {
				setup_request( 'GET', '/wp-login.php', 'cross-site' );
				setup_user( true );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'allows cross-site logout GET for logged-out user',
			function () {
				setup_request( 'GET', '/wp-login.php?action=logout', 'cross-site' );
				setup_user( false );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'allows logged-in cross-site top-level navigation when opted in on development',
			function () {
				Functions\when( 'wp_get_environment_type' )->justReturn( 'development' );
				mock_settings( array( 'allow_top_level_navigations' => true ) );
				setup_request( 'GET', '/wp-admin/update-core.php', 'cross-site', null, 'example.com', 'navigate', 'document' );
				setup_user( true );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'still blocks logged-in cross-site top-level navigation when opted in outside development',
			function () {
				Functions\when( 'wp_get_environment_type' )->justReturn( 'production' );
				mock_settings( array( 'allow_top_level_navigations' => true ) );
				setup_request( 'GET', '/wp-admin/update-core.php', 'cross-site', null, 'example.com', 'navigate', 'document' );
				setup_user( true );

				expect( fn() => validate_request() )
				->toThrow( RuntimeException::class, 'blocked' );
			}
		);

		it(
			'still blocks logged-in cross-site top-level navigation when opted out',
			function () {
				setup_request( 'GET', '/wp-admin/update-core.php', 'cross-site', null, 'example.com', 'navigate', 'document' );
				setup_user( true );

				expect( fn() => validate_request() )
				->toThrow( RuntimeException::class, 'blocked' );
			}
		);

		it(
			'still blocks logout top-level navigation when opted in',
			function () {
				mock_settings( array( 'allow_top_level_navigations' => true ) );
				setup_request( 'GET', '/wp-login.php?action=logout', 'cross-site', null, 'example.com', 'navigate', 'document' );
				setup_user( true );

				expect( fn() => validate_request() )
				->toThrow( RuntimeException::class, 'blocked' );
			}
		);

		it(
			'still blocks cross-site subresource reads when opted in',
			function () {
				mock_settings( array( 'allow_top_level_navigations' => true ) );
				setup_request( 'GET', '/wp-admin/admin.php', 'cross-site', null, 'example.com', 'no-cors', 'empty' );
				setup_user( true );

				expect( fn() => validate_request() )
				->toThrow( RuntimeException::class, 'blocked' );
			}
		);
	}
);
