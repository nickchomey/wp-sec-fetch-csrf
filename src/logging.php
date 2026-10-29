<?php
/**
 * Database logging functions for Sec-Fetch CSRF Protection.
 *
 * @package SecFetchCSRF
 */

namespace SecFetchCSRF;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Create the database table (used during activation).
 *
 * @return void
 */
function create_table(): void {
	global $wpdb;

	include_once ABSPATH . 'wp-admin/includes/upgrade.php';

	$table_name      = $wpdb->prefix . TABLE_NAME;
	$charset_collate = $wpdb->get_charset_collate();

	$sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        request_method VARCHAR(10) NOT NULL,
        request_uri TEXT NOT NULL,
        query_string TEXT,
        sec_fetch_site VARCHAR(50),
        sec_fetch_mode VARCHAR(50),
        sec_fetch_dest VARCHAR(50),
        origin_header VARCHAR(255),
        host_header VARCHAR(255),
        user_id BIGINT UNSIGNED DEFAULT 0,
        block_reason VARCHAR(255) NOT NULL,
        request_type VARCHAR(20),
        was_blocked TINYINT(1) DEFAULT 1,
        INDEX idx_blocked_at (blocked_at),
        INDEX idx_was_blocked (was_blocked),
        INDEX idx_request_method (request_method)
    ) {$charset_collate};";

	dbDelta( $sql );
}

/**
 * Log a request to the database.
 *
 * @param string $reason      The reason for logging/blocking.
 * @param string $method      HTTP method (GET, POST, etc.).
 * @param string $uri         Request URI.
 * @param bool   $was_blocked Whether the request was blocked.
 * @return bool True on success, false on failure.
 */
function log_request( string $reason, string $method, string $uri, bool $was_blocked = true ): bool {
	global $wpdb;

	// Throttle: forged cross-site writes can otherwise churn this table and
	// its cache invalidations without bound. Drop (don't queue) beyond 200
	// inserts per rolling 5 minutes; the gate decision is unaffected.
	$table_name = $wpdb->prefix . TABLE_NAME;
	$window     = gmdate( 'Y-m-d H:i:s', time() - 300 );
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table, intentionally uncached rate check.
	$recent = (int) $wpdb->get_var(
		$wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE blocked_at > %s", $window )
	);
	if ( $recent >= 200 ) {
		return false;
	}

	$user_id = 0;
	if ( function_exists( 'get_current_user_id' ) ) {
		$user_id = get_current_user_id();
	}

	// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Server headers sanitized below.
	$data = array(
		'blocked_at'     => current_time( 'mysql' ),
		'request_method' => sanitize_text_field( $method ),
		'request_uri'    => sanitize_text_field( $uri ),
		'query_string'   => isset( $_SERVER['QUERY_STRING'] ) ? sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '',
		'sec_fetch_site' => isset( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_SEC_FETCH_SITE'] ) ) : null,
		'sec_fetch_mode' => isset( $_SERVER['HTTP_SEC_FETCH_MODE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_SEC_FETCH_MODE'] ) ) : null,
		'sec_fetch_dest' => isset( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_SEC_FETCH_DEST'] ) ) : null,
		'origin_header'  => isset( $_SERVER['HTTP_ORIGIN'] ) ? sanitize_url( wp_unslash( $_SERVER['HTTP_ORIGIN'] ) ) : null,
		'host_header'    => isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : null,
		'user_id'        => $user_id,
		'block_reason'   => sanitize_text_field( $reason ),
		'request_type'   => determine_request_type( $uri ),
		'was_blocked'    => $was_blocked ? 1 : 0,
	);
	// phpcs:enable

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom table, no WP API available.
	$result = $wpdb->insert( $table_name, $data );

	if ( false === $result ) {
		// Log error if WP_DEBUG is enabled.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug logging.
			error_log(
				sprintf(
					'[Sec-Fetch-CSRF] Failed to log request: %s (Error: %s)',
					$reason,
					$wpdb->last_error
				)
			);
		}
		return false;
	}

	invalidate_cache();
	return true;
}

/**
 * Invalidate log-related caches.
 *
 * @return void
 */
function invalidate_cache(): void {
	wp_cache_delete( 'log_count_blocked', CACHE_GROUP );
	wp_cache_delete( 'log_count_all', CACHE_GROUP );
}

/**
 * Get count of logs.
 *
 * @param bool $blocked_only Whether to count only blocked requests.
 * @return int
 */
function get_log_count( bool $blocked_only = true ): int {
	global $wpdb;

	$cache_key = $blocked_only ? 'log_count_blocked' : 'log_count_all';
	$count     = wp_cache_get( $cache_key, CACHE_GROUP );

	if ( false !== $count ) {
		return (int) $count;
	}

	$table_name = $wpdb->prefix . TABLE_NAME;
	$where      = $blocked_only ? 'WHERE was_blocked = 1' : '';

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table with caching above, dynamic WHERE clause.
	// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name from constant, WHERE is safe static string.
	$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name} {$where}" );

	wp_cache_set( $cache_key, $count, CACHE_GROUP, 300 );

	return $count;
}

/**
 * Get logs with pagination and search.
 *
 * @param int         $page         Page number.
 * @param int         $per_page     Items per page.
 * @param bool        $blocked_only Whether to show only blocked requests.
 * @param string|null $search       Search term.
 * @return array
 */
function get_logs( int $page, int $per_page, bool $blocked_only, ?string $search = null ): array {
	global $wpdb;

	$table_name = $wpdb->prefix . TABLE_NAME;
	$offset     = ( $page - 1 ) * $per_page;

	$where_clauses = array();
	$where_values  = array();

	if ( $blocked_only ) {
		$where_clauses[] = 'was_blocked = 1';
	}

	if ( null !== $search && '' !== $search ) {
		$like            = '%' . $wpdb->esc_like( $search ) . '%';
		$where_clauses[] = '(request_uri LIKE %s OR block_reason LIKE %s OR origin_header LIKE %s OR sec_fetch_site LIKE %s)';
		$where_values[]  = $like;
		$where_values[]  = $like;
		$where_values[]  = $like;
		$where_values[]  = $like;
	}

	$where = '';
	if ( ! empty( $where_clauses ) ) {
		$where = 'WHERE ' . implode( ' AND ', $where_clauses );
	}

	// Get total count for this query.
	$count_sql = "SELECT COUNT(*) FROM {$table_name} {$where}";
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table, uncached for pagination accuracy.
	// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Table name from constant, dynamic WHERE with prepare when needed.
	if ( ! empty( $where_values ) ) {
		$total = (int) $wpdb->get_var( $wpdb->prepare( $count_sql, ...$where_values ) );
	} else {
		$total = (int) $wpdb->get_var( $count_sql );
	}

	// Get items.
	$sql        = "SELECT * FROM {$table_name} {$where} ORDER BY blocked_at DESC LIMIT %d OFFSET %d";
	$all_values = array_merge( $where_values, array( $per_page, $offset ) );

	$items = $wpdb->get_results(
		$wpdb->prepare( $sql, ...$all_values ),
		ARRAY_A
	);
	// phpcs:enable

	return array(
		'items' => ! empty( $items ) ? $items : array(),
		'total' => $total,
	);
}

/**
 * Delete logs by IDs.
 *
 * @param array $ids Array of log IDs to delete.
 * @return int Number of deleted rows.
 */
function delete_logs( array $ids ): int {
	global $wpdb;

	if ( empty( $ids ) ) {
		return 0;
	}

	$table_name   = $wpdb->prefix . TABLE_NAME;
	$ids          = array_map( 'intval', $ids );
	$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );

	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table, cache invalidated below.
	// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name from constant, placeholders built safely.
	$deleted = $wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$table_name} WHERE id IN ({$placeholders})",
			...$ids
		)
	);
	// phpcs:enable

	invalidate_cache();

	return (int) $deleted;
}

/**
 * Delete all logs.
 *
 * Uses TRUNCATE for performance.
 *
 * @return void
 */
function delete_all_logs(): void {
	global $wpdb;

	$table_name = $wpdb->prefix . TABLE_NAME;

	// TRUNCATE is faster than DELETE for clearing all rows.
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Custom table, no values to prepare.
	$wpdb->query( "TRUNCATE TABLE {$table_name}" );
	// phpcs:enable

	invalidate_cache();
}
