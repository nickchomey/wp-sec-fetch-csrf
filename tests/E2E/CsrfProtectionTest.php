<?php
/**
 * E2E tests for CSRF protection using real HTTP requests.
 *
 * These tests make actual HTTP requests to a WordPress instance and verify
 * that the plugin correctly blocks/allows requests based on Sec-Fetch headers.
 *
 * REQUIREMENTS:
 * - A running WordPress instance with this plugin activated.
 * - The WP_TEST_URL environment variable set to your instance URL.
 *
 * RUNNING E2E TESTS:
 *   WP_TEST_URL=https://your-site.test vendor/bin/pest tests/E2E
 *
 * RUNNING UNIT TESTS (no WordPress needed):
 *   vendor/bin/pest tests/Unit
 *
 * RUNNING ALL TESTS:
 *   WP_TEST_URL=https://your-site.test vendor/bin/pest
 *
 * @package SecFetchCSRF
 */

use GuzzleHttp\Client;

// Default test URL - override with WP_TEST_URL environment variable.
const DEFAULT_TEST_URL = 'http://localhost:8080';

// Skip E2E tests if WordPress instance is not running.
beforeAll(
	function () {
		$base_url = get_test_base_url();

		try {
			$client = new Client(
				array(
					'base_uri' => $base_url,
					'timeout'  => 5,
					'verify'   => false,
				)
			);
			$client->get( '/' );
		} catch ( \Exception $e ) {
			test()->markTestSkipped( 'WordPress test instance not available at ' . $base_url . ': ' . $e->getMessage() );
		}
	}
);

/**
 * Get the base URL for tests.
 */
function get_test_base_url(): string {
	$test_url = getenv( 'WP_TEST_URL' );
	if ( false === $test_url ) {
		return DEFAULT_TEST_URL;
	}
	return $test_url;
}

/**
 * Helper to create a configured Guzzle client.
 *
 * Includes XDEBUG_SESSION cookie to enable step debugging on the WordPress server
 * when xdebug is configured. This is a no-op if xdebug is not installed.
 */
function create_client(): Client {
	return new Client(
		array(
			'base_uri'    => get_test_base_url(),
			'timeout'     => 60,
			'verify'      => false,
			'http_errors' => false, // Don't throw on 4xx/5xx.
			'cookies'     => \GuzzleHttp\Cookie\CookieJar::fromArray(
				array( 'XDEBUG_SESSION' => 'PHPSTORM' ),
				// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- E2E tests run outside WordPress.
				parse_url( get_test_base_url(), PHP_URL_HOST )
			),
		)
	);
}

describe(
	'Cross-site POST requests',
	function () {
		it(
			'blocks cross-site POST to admin-ajax.php',
			function () {
				$client = create_client();

				$response = $client->post(
					'/wp-admin/admin-ajax.php',
					array(
						'headers'     => array(
							'Sec-Fetch-Site' => 'cross-site',
							'Sec-Fetch-Mode' => 'cors',
						),
						'form_params' => array(
							'action' => 'heartbeat',
						),
					)
				);

				expect( $response->getStatusCode() )->toBe( 403 );
				$body = json_decode( $response->getBody()->getContents(), true );
				expect( $body['success'] )->toBeFalse();
				expect( $body['data']['message'] )->toBe( 'CSRF validation failed' );
			}
		);

		it(
			'allows same-origin POST to admin-ajax.php',
			function () {
				$client = create_client();

				$response = $client->post(
					'/wp-admin/admin-ajax.php',
					array(
						'headers'     => array(
							'Sec-Fetch-Site' => 'same-origin',
							'Sec-Fetch-Mode' => 'cors',
						),
						'form_params' => array(
							'action' => 'heartbeat',
						),
					)
				);

				// Should not be 403 - might be 400 (bad request) or 200 depending on action.
				expect( $response->getStatusCode() )->not->toBe( 403 );
			}
		);

		it(
			'blocks cross-site POST to wp-json endpoint',
			function () {
				$client = create_client();

				$response = $client->post(
					'/wp-json/wp/v2/posts',
					array(
						'headers' => array(
							'Sec-Fetch-Site' => 'cross-site',
							'Sec-Fetch-Mode' => 'cors',
							'Content-Type'   => 'application/json',
						),
						'body'    => json_encode( array( 'title' => 'Test' ) ), // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
					)
				);

				expect( $response->getStatusCode() )->toBe( 403 );
			}
		);
	}
);

describe(
	'Cross-site GET requests',
	function () {
		it(
			'allows cross-site GET to frontend for logged-out users',
			function () {
				$client = create_client();

				$response = $client->get(
					'/',
					array(
						'headers' => array(
							'Sec-Fetch-Site' => 'cross-site',
							'Sec-Fetch-Mode' => 'navigate',
						),
					)
				);

				// Should redirect (301) or succeed (200), not block (403).
				expect( $response->getStatusCode() )->toBeIn( array( 200, 301, 302 ) );
			}
		);

		it(
			'allows same-origin GET to wp-admin (redirects to login)',
			function () {
				$client = create_client();

				$response = $client->get(
					'/wp-admin/',
					array(
						'headers'         => array(
							'Sec-Fetch-Site' => 'same-origin',
							'Sec-Fetch-Mode' => 'navigate',
						),
						'allow_redirects' => false,
					)
				);

				// Should redirect to login, not block.
				expect( $response->getStatusCode() )->toBe( 302 );
			}
		);
	}
);

describe(
	'Origin header fallback',
	function () {
		it(
			'blocks POST with mismatched Origin header (no Sec-Fetch headers)',
			function () {
				$client = create_client();

				$response = $client->post(
					'/wp-admin/admin-ajax.php',
					array(
						'headers'     => array(
							'Origin' => 'https://evil.com',
						),
						'form_params' => array(
							'action' => 'heartbeat',
						),
					)
				);

				expect( $response->getStatusCode() )->toBe( 403 );
			}
		);
	}
);

describe(
	'Origin header fallback (same-origin)',
	function () {
		it(
			'allows POST with same Origin header (no Sec-Fetch headers)',
			function () {
				$client = create_client();

				$response = $client->post(
					'/wp-admin/admin-ajax.php',
					array(
						'headers'     => array(
							'Origin' => get_test_base_url(),
						),
						'form_params' => array(
							'action' => 'heartbeat',
						),
					)
				);

				expect( $response->getStatusCode() )->toBeIn( array( 200, 301, 302 ) );
			}
		);
	}
);

describe(
	'Bypass patterns',
	function () {
		// This test requires a bypass pattern to be configured.
		// Skip if not configured.
		it( 'allows cross-site POST to bypassed endpoints' )->skip(
			'Requires bypass pattern configuration.'
		);
	}
);
