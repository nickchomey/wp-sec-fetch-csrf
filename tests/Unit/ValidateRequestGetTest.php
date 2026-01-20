<?php
/**
 * Tests for validate_request() - GET/HEAD/OPTIONS request handling.
 *
 * @package SecFetchCSRF
 */

use function SecFetchCSRF\validate_request;
use function SecFetchCSRF\is_validated;
use function Tests\{setup_request, setup_user, mock_settings, mock_allowed_request_behavior, mock_blocking_behavior};

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
	}
);
