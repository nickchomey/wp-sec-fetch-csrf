<?php
/**
 * Tests for log_request throttling.
 *
 * @package SecFetchCSRF
 */

use function SecFetchCSRF\log_request;
use function Tests\mock_blocking_behavior;

beforeEach(
	function () {
		mock_blocking_behavior();
	}
);

describe(
	'log_request throttle',
	function () {

		it(
			'logs normally under the throttle limit',
			function () {
				expect( log_request( 'test reason', 'POST', '/wp-admin/', true ) )->toBeTrue();
			}
		);

		it(
			'drops inserts over the throttle limit without inserting',
			function () {
				global $wpdb;
				$wpdb = Mockery::mock( 'wpdb' ); // phpcs:ignore WordPress.Variables.GlobalVariables
				$wpdb->prefix = 'wp_';
				$wpdb->shouldReceive( 'prepare' )->andReturnUsing( fn( $query ) => $query );
				$wpdb->shouldReceive( 'get_var' )->andReturn( 250 );
				$wpdb->shouldNotReceive( 'insert' );

				expect( log_request( 'flood', 'POST', '/wp-admin/', true ) )->toBeFalse();
			}
		);
	}
);
