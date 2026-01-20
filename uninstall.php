<?php
/**
 * Uninstall script for Sec-Fetch CSRF Protection.
 *
 * This file is called when the plugin is deleted via WordPress admin.
 * It removes all plugin data including the database table and options.
 *
 * @package SecFetchCSRF
 */

// Exit if not called by WordPress uninstall.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// Delete the log table.
$table_name = $wpdb->prefix . 'csrf_blocked_requests';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Uninstall cleanup, table name is safe.
$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );

// Delete plugin options.
delete_option( 'sec_fetch_csrf_settings' );
