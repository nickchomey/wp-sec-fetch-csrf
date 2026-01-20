<?php
/**
 * Tests for the nonce overrides (wp_verify_nonce / wp_create_nonce).
 *
 * These overrides are the fragment-caching enabler: wp_verify_nonce returns
 * 1 whenever Sec-Fetch validation passed (fail-closed before), and
 * wp_create_nonce returns a stable, cacheable value keyed by action+uid.
 *
 * @package SecFetchCSRF
 */

use Brain\Monkey\Functions;
use Mockery;
use function Tests\setup_user;

beforeEach(
	function () {
		// Reset the validation state (State::$validated).
		\SecFetchCSRF\State::$validated = false;

		// Load the nonce overrides (defines global wp_verify_nonce /
		// wp_create_nonce when not already defined). Guarded so repeated
		// loads across test files are safe.
		require_once __DIR__ . '/../../src/nonce-overrides.php';

		// Mock the WP functions the overrides touch.
		Functions\when( 'wp_hash' )->alias(
			static function ( string $data, string $scheme = '' ): string {
				return hash( 'sha256', $data . '|' . $scheme );
			}
		);
	}
);

describe(
	'wp_verify_nonce override',
	function () {
		it(
			'returns false for an empty nonce',
			function () {
				\SecFetchCSRF\State::$validated = true;
				expect( wp_verify_nonce( '' ) )->toBeFalse();
			}
		);

		it(
			'returns false (fail-closed) when validation has not run',
			function () {
				\SecFetchCSRF\State::$validated = false;
				expect( wp_verify_nonce( 'abc123' ) )->toBeFalse();
			}
		);
	}
);

describe(
	'wp_create_nonce override',
	function () {
		it(
			'returns a deterministic, stable value for a given user+action',
			function () {
				setup_user( true, 42 );
				Functions\when( 'wp_get_current_user' )->alias(
					static function () {
						$u        = Mockery::mock( 'WP_User' );
						$u->ID    = 42;
						return $u;
					}
				);
				Functions\when( 'get_current_user_id' )->alias( static fn() => 42 );

				$n1 = wp_create_nonce( 'my-action' );
				$n2 = wp_create_nonce( 'my-action' );
				expect( $n1 )->toBe( $n2 );
				expect( strlen( $n1 ) )->toBe( 10 );
			}
		);

		it(
			'produces different values for different actions or users',
			function () {
				Functions\when( 'wp_get_current_user' )->alias(
					static function () {
						$u     = Mockery::mock( 'WP_User' );
						$u->ID = 1;
						return $u;
					}
				);
				$user1_action1 = wp_create_nonce( 'action-a' );

				Functions\when( 'wp_get_current_user' )->alias(
					static function () {
						$u     = Mockery::mock( 'WP_User' );
						$u->ID = 2;
						return $u;
					}
				);
				$user2_action1 = wp_create_nonce( 'action-a' );
				$user2_action2 = wp_create_nonce( 'action-b' );

				expect( $user1_action1 )->not->toBe( $user2_action1 );
				expect( $user2_action1 )->not->toBe( $user2_action2 );
			}
		);
	}
);
