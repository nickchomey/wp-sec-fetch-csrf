<?php
/**
 * Tests for validate_request function - POST/PUT/DELETE requests.
 *
 * @package SecFetchCSRF
 */

use function SecFetchCSRF\validate_request;
use function SecFetchCSRF\is_validated;
use function Tests\{setup_request, setup_user, mock_settings, mock_blocking_behavior};

beforeEach(
	function () {
		mock_blocking_behavior();
	}
);

describe(
	'validate_request POST requests',
	function () {

		it(
			'allows same-origin POST requests',
			function () {
				setup_request( 'POST', '/wp-admin/admin-post.php', 'same-origin' );
				setup_user( true );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'blocks cross-site POST requests',
			function () {
				setup_request( 'POST', '/wp-admin/admin-post.php', 'cross-site' );
				setup_user( true );

				expect( fn() => validate_request() )
				->toThrow( RuntimeException::class, 'blocked' );
			}
		);

		it(
			'blocks cross-site PUT requests',
			function () {
				setup_request( 'PUT', '/wp-json/wp/v2/posts/1', 'cross-site' );
				setup_user( true );

				expect( fn() => validate_request() )
				->toThrow( RuntimeException::class, 'blocked' );
			}
		);

		it(
			'blocks cross-site DELETE requests',
			function () {
				setup_request( 'DELETE', '/wp-json/wp/v2/posts/1', 'cross-site' );
				setup_user( true );

				expect( fn() => validate_request() )
				->toThrow( RuntimeException::class, 'blocked' );
			}
		);

		it(
			'allows POST when bypass pattern matches',
			function () {
				mock_settings( array( 'bypass_patterns' => array( '/webhook/*' ) ) );
				setup_request( 'POST', '/webhook/stripe', 'cross-site' );
				setup_user( false );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		it(
			'allows POST when trusted origin matches',
			function () {
				mock_settings( array( 'trusted_origins' => array( 'https://trusted.com' ) ) );
				setup_request( 'POST', '/wp-admin/admin-post.php', 'cross-site', 'https://trusted.com' );
				setup_user( true );

				validate_request();

				expect( is_validated() )->toBeTrue();
			}
		);

		describe(
			'Origin header fallback (no Sec-Fetch-Site)',
			function () {

				it(
					'blocks POST when Origin does not match Host',
					function () {
						setup_request( 'POST', '/wp-admin/admin-post.php', null, 'https://evil.com', 'example.com' );
						setup_user( true );

						expect( fn() => validate_request() )
						->toThrow( RuntimeException::class, 'blocked' );
					}
				);

				it(
					'allows POST when Origin matches Host',
					function () {
						setup_request( 'POST', '/wp-admin/admin-post.php', null, 'https://example.com', 'example.com' );
						setup_user( true );

						validate_request();

						expect( is_validated() )->toBeTrue();
					}
				);

				it(
					'blocks POST when no Origin header and no Sec-Fetch-Site',
					function () {
						// Security: Requests without browser headers should be blocked.
						// This prevents CSRF via non-browser clients (curl, scripts).
						setup_request( 'POST', '/wp-admin/admin-post.php', null, null );
						setup_user( true );

						expect( fn() => validate_request() )
						->toThrow( RuntimeException::class, 'blocked' );
					}
				);

				it(
					'allows POST without headers when bypass pattern matches',
					function () {
						// Exempted endpoints (e.g., webhooks) can still receive requests without headers.
						mock_settings( array( 'bypass_patterns' => array( '/webhook/*' ) ) );
						setup_request( 'POST', '/webhook/stripe', null, null );
						setup_user( false );

						validate_request();

						expect( is_validated() )->toBeTrue();
					}
				);

				it(
					'allows POST when Origin mismatch but bypass pattern matches',
					function () {
						mock_settings( array( 'bypass_patterns' => array( '/webhook/*' ) ) );
						setup_request( 'POST', '/webhook/callback', null, 'https://external.com', 'example.com' );
						setup_user( false );

						validate_request();

						expect( is_validated() )->toBeTrue();
					}
				);

				it(
					'blocks POST with malformed Origin header',
					function () {
						// Malformed Origin that causes parse_url to return null.
						setup_request( 'POST', '/wp-admin/admin-post.php', null, 'not-a-valid-url', 'example.com' );
						setup_user( true );

						expect( fn() => validate_request() )
						->toThrow( RuntimeException::class, 'blocked' );
					}
				);

				it(
					'allows POST with malformed Origin when bypass pattern matches',
					function () {
						mock_settings( array( 'bypass_patterns' => array( '/webhook/*' ) ) );
						setup_request( 'POST', '/webhook/stripe', null, 'not-a-valid-url', 'example.com' );
						setup_user( false );

						validate_request();

						expect( is_validated() )->toBeTrue();
					}
				);
			}
		);
	}
);
