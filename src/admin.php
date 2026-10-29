<?php
/**
 * Admin UI functions for Sec-Fetch CSRF Protection
 *
 * @package SecFetchCSRF
 * @author  Nick Starter
 * @license GPL-2.0-or-later
 * @link    https://github.com/starter/sec-fetch-csrf
 */

namespace SecFetchCSRF;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Add admin menu item.
 *
 * @return void
 */
function add_admin_menu(): void {
	add_options_page(
		'CSRF Protection',
		'CSRF Protection',
		'manage_options',
		'sec-fetch-csrf',
		__NAMESPACE__ . '\render_admin_page'
	);
}

/**
 * Register settings.
 *
 * @return void
 */
function register_settings(): void {
	register_setting(
		'sec_fetch_csrf_settings',
		'sec_fetch_csrf_settings',
		array(
			'sanitize_callback' => __NAMESPACE__ . '\sanitize_settings',
		)
	);
}

/**
 * Sanitize settings before saving.
 *
 * @param array $input The input settings array.
 * @return array
 */
function sanitize_settings( array $input ): array {
	$sanitized = array();

	$sanitized['trust_same_site'] = ! empty( $input['trust_same_site'] );
	$sanitized['log_all_gets']    = ! empty( $input['log_all_gets'] );

	// Bypass patterns (one per line) - handle both string (from form) and array (from re-sanitization).
	$patterns = isset( $input['bypass_patterns'] ) ? $input['bypass_patterns'] : '';
	if ( is_array( $patterns ) ) {
		$patterns = array_filter( array_map( 'trim', $patterns ) );
	} else {
		$patterns = array_filter( array_map( 'trim', explode( "\n", $patterns ) ) );
	}
	$sanitized['bypass_patterns'] = array_values( $patterns );

	// A bare match-everything pattern silently disarms protection site-wide,
	// including this settings page. Refuse it loudly instead.
	foreach ( $sanitized['bypass_patterns'] as $index => $pattern ) {
		if ( '*' === $pattern || '**' === $pattern ) {
			unset( $sanitized['bypass_patterns'][ $index ] );
			add_settings_error(
				'sec_fetch_csrf_settings',
				'sec_fetch_csrf_bypass_too_broad',
				'Refused bypass pattern "' . $pattern . '": it matches every request. Scope webhooks and callbacks to their exact URIs instead.',
				'error'
			);
		}
	}
	$sanitized['bypass_patterns'] = array_values( $sanitized['bypass_patterns'] );

	// Trusted origins (one per line) - handle both string (from form) and array (from re-sanitization).
	$origins = isset( $input['trusted_origins'] ) ? $input['trusted_origins'] : '';
	if ( is_array( $origins ) ) {
		$origins = array_filter( array_map( 'sanitize_url', array_map( 'trim', $origins ) ) );
	} else {
		$origins = array_filter( array_map( 'sanitize_url', array_map( 'trim', explode( "\n", $origins ) ) ) );
	}
	$sanitized['trusted_origins'] = array_values( $origins );

	// Sensitive endpoints (one per line) - handle both string (from form) and array (from re-sanitization).
	$endpoints = isset( $input['sensitive_endpoints'] ) ? $input['sensitive_endpoints'] : '';
	if ( is_array( $endpoints ) ) {
		$endpoints = array_filter( array_map( 'trim', $endpoints ) );
	} else {
		$endpoints = array_filter( array_map( 'trim', explode( "\n", $endpoints ) ) );
	}
	// Use defaults if empty.
	$sanitized['sensitive_endpoints'] = ! empty( $endpoints ) ? array_values( $endpoints ) : DEFAULT_SENSITIVE_ENDPOINTS;

	reset_settings_cache();

	return $sanitized;
}

/**
 * Show admin notice when there are blocked requests.
 *
 * @return void
 */
function show_admin_notice(): void {
	// Don't show on our own settings page.
	$screen = get_current_screen();
	if ( $screen && 'settings_page_sec-fetch-csrf' === $screen->id ) {
		return;
	}

	$count = get_log_count( true );
	if ( 0 === $count ) {
		return;
	}

	$url = admin_url( 'options-general.php?page=sec-fetch-csrf' );
	?>
	<div class="notice notice-warning">
		<p>
			<strong>CSRF Protection:</strong>
	<?php echo esc_html( $count ); ?> blocked request(s) in log.
			<a href="<?php echo esc_url( $url ); ?>">View log →</a>
		</p>
	</div>
	<?php
}

/**
 * Handle bulk actions and form submissions.
 *
 * @return void
 */
function handle_admin_actions(): void {
	if ( ! isset( $_POST['sec_fetch_csrf_action'] ) ) {
		return;
	}

	check_admin_referer( 'sec_fetch_csrf_bulk', 'sec_fetch_csrf_nonce' );

	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized below.
	$action = isset( $_POST['sec_fetch_csrf_action'] ) ? sanitize_text_field( wp_unslash( $_POST['sec_fetch_csrf_action'] ) ) : '';

	if ( 'delete_selected' === $action && isset( $_POST['log_ids'] ) ) {
		$ids     = array_map( 'intval', (array) $_POST['log_ids'] );
		$deleted = delete_logs( $ids );
		add_settings_error( 'sec_fetch_csrf', 'deleted', sprintf( '%d log(s) deleted.', $deleted ), 'success' );
	} elseif ( 'delete_all' === $action ) {
		delete_all_logs();
		add_settings_error( 'sec_fetch_csrf', 'deleted_all', 'All logs deleted.', 'success' );
	}
}

/**
 * Render the admin page.
 *
 * @return void
 */
function render_admin_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Tab switching only, no action performed.
	$tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'logs';

	?>
	<div class="wrap">
		<h1>CSRF Protection</h1>

		<nav class="nav-tab-wrapper">
			<a href="?page=sec-fetch-csrf&tab=logs"
			class="nav-tab <?php echo 'logs' === $tab ? 'nav-tab-active' : ''; ?>">
				Request Log
			</a>
			<a href="?page=sec-fetch-csrf&tab=settings"
			class="nav-tab <?php echo 'settings' === $tab ? 'nav-tab-active' : ''; ?>">
				Settings
			</a>
		</nav>

	<?php if ( 'settings' === $tab ) : ?>
		<?php render_settings_tab(); ?>
		<?php else : ?>
			<?php render_logs_tab(); ?>
		<?php endif; ?>
	</div>
	<?php
}

/**
 * Render settings tab
 */
function render_settings_tab(): void {
	$settings = get_plugin_settings();
	?>
	<form method="post" action="options.php">
	<?php settings_fields( 'sec_fetch_csrf_settings' ); ?>

		<table class="form-table">
			<tr>
				<th scope="row">Trust Same-Site Requests</th>
				<td>
					<label>
						<input type="checkbox" name="sec_fetch_csrf_settings[trust_same_site]"
							value="1" <?php checked( $settings['trust_same_site'] ); ?>>
						Allow requests with <code>Sec-Fetch-Site: same-site</code>
					</label>
						<p class="description">
						Enable only if you trust all subdomains. Disabled by default for security.
						<br>Consequence: off breaks cross-subdomain writes (multisite, SSO flows across subdomains);
						on trusts every subdomain, which is unsafe on shared-domain hosting where attackers can mint their own.
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row">Sensitive Endpoints</th>
				<td>
					<textarea name="sec_fetch_csrf_settings[sensitive_endpoints]"
							rows="5" cols="50" class="large-text code"
					><?php echo esc_textarea( implode( "\n", $settings['sensitive_endpoints'] ) ); ?></textarea>
					<p class="description">
						<strong>Block cross-site read requests (GET/HEAD/OPTIONS)</strong> to these URI patterns
						for logged-in users (one per line). Cross-site writes are always blocked regardless of this setting.
						<br>Default: <code>/wp-admin/</code>, <code>/wp-json/</code>, <code>action=logout</code>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row">Bypass Patterns</th>
				<td>
					<textarea name="sec_fetch_csrf_settings[bypass_patterns]"
							rows="5" cols="50" class="large-text code"
					><?php echo esc_textarea( implode( "\n", $settings['bypass_patterns'] ) ); ?></textarea>
					<p class="description">
						<strong>Allow cross-site requests</strong> to these URI patterns (one per line).
						Bypasses blocking for both writes (POST/PUT/DELETE) and reads to sensitive endpoints.
						Use for webhooks, payment callbacks, etc. Supports wildcards: <code>/wp-json/webhook/*</code>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row">Trusted Origins</th>
				<td>
					<textarea name="sec_fetch_csrf_settings[trusted_origins]"
							rows="5" cols="50" class="large-text code"
					><?php echo esc_textarea( implode( "\n", $settings['trusted_origins'] ) ); ?></textarea>
					<p class="description">
						<strong>Allow all requests from these external origins</strong> (one per line).
						Use for trusted third-party integrations: <code>https://trusted-site.com</code>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row">Log Allowed Cross-Site Reads</th>
				<td>
					<label>
						<input type="checkbox" name="sec_fetch_csrf_settings[log_all_gets]"
							value="1" <?php checked( $settings['log_all_gets'] ); ?>>
						Log cross-site GET/HEAD/OPTIONS requests that are allowed through
					</label>
					<p class="description">
						Useful during development to identify endpoints that may need protection.
						Blocked requests are always logged regardless of this setting.
					</p>
				</td>
			</tr>
		</table>

	<?php submit_button(); ?>
	</form>
	<?php
}

/**
 * Render logs tab.
 *
 * @return void
 */
function render_logs_tab(): void {
	// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only pagination/filtering.
	$page     = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
	$per_page = isset( $_GET['per_page'] ) ? max( 10, min( 200, intval( $_GET['per_page'] ) ) ) : 50;
	$search   = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : null;
	// phpcs:enable

	// Always show all requests (blocked and logged).
	$logs        = get_logs( $page, $per_page, false, $search );
	$total_pages = (int) ceil( $logs['total'] / $per_page );

	?>
	<form method="post" action="">
	<?php wp_nonce_field( 'sec_fetch_csrf_bulk', 'sec_fetch_csrf_nonce' ); ?>

		<div class="tablenav top">
			<div class="alignleft actions bulkactions">
				<select name="sec_fetch_csrf_action">
					<option value="">Bulk Actions</option>
					<option value="delete_selected">Delete Selected</option>
					<option value="delete_all">Delete All Logs</option>
				</select>
				<input type="submit" class="button action" value="Apply">
			</div>

			<div class="alignright">
				<label>
					Per page:
					<select onchange="window.location.href='?page=sec-fetch-csrf&per_page=' + this.value">
						<?php foreach ( array( 25, 50, 100, 200 ) as $opt ) : ?>
							<option value="<?php echo esc_attr( $opt ); ?>" <?php selected( $per_page, $opt ); ?>>
							<?php echo esc_html( $opt ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</label>
			</div>
		</div>

		<p class="search-box">
			<label class="screen-reader-text" for="log-search">Search:</label>
			<input type="search" id="log-search" name="s" value="<?php echo esc_attr( null !== $search ? $search : '' ); ?>">
			<input type="submit" class="button" value="Search">
			<input type="hidden" name="page" value="sec-fetch-csrf">
		</p>

		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<td class="manage-column column-cb check-column">
						<input type="checkbox" id="cb-select-all">
					</td>
					<th style="width:140px">Time</th>
					<th style="width:60px">Method</th>
					<th>URI</th>
					<th style="width:80px">Type</th>
					<th style="width:90px">Sec-Fetch</th>
					<th style="width:150px">Origin</th>
					<th>Reason</th>
					<th style="width:60px">Status</th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $logs['items'] ) ) : ?>
					<tr>
						<td colspan="9">No requests logged.</td>
					</tr>
				<?php else : ?>
					<?php foreach ( $logs['items'] as $log ) : ?>
						<tr class="<?php echo esc_attr( $log['was_blocked'] ? '' : 'logged-only' ); ?>">
							<th class="check-column">
								<input type="checkbox" name="log_ids[]"
									value="<?php echo esc_attr( $log['id'] ); ?>">
							</th>
							<td><?php echo esc_html( $log['blocked_at'] ); ?></td>
							<td><code><?php echo esc_html( $log['request_method'] ); ?></code></td>
							<td>
								<code style="font-size:11px;word-break:break-all;">
						<?php echo esc_html( $log['request_uri'] ); ?>
								</code>
							</td>
							<td><?php echo esc_html( $log['request_type'] ); ?></td>
							<?php // phpcs:ignore Universal.Operators.DisallowShortTernary.Found -- This is a standard ternary, not short ternary. ?>
							<td><code><?php echo esc_html( ( ! empty( $log['sec_fetch_site'] ) ? $log['sec_fetch_site'] : '-' ) ); ?></code></td>
							<td>
								<code style="font-size:10px;">
						<?php // phpcs:ignore Universal.Operators.DisallowShortTernary.Found -- This is a standard ternary, not short ternary. ?>
						<?php echo esc_html( ( ! empty( $log['origin_header'] ) ? $log['origin_header'] : '-' ) ); ?>
								</code>
							</td>
							<td style="font-size:11px;">
						<?php echo esc_html( $log['block_reason'] ); ?>
							</td>
							<td>
						<?php if ( $log['was_blocked'] ) : ?>
									<span style="color:#d63638">Blocked</span>
								<?php else : ?>
									<span style="color:#72aee6">Logged</span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>

		<div class="tablenav bottom">
			<div class="tablenav-pages">
				<span class="displaying-num"><?php echo esc_html( $logs['total'] ); ?> items</span>
				<?php if ( $total_pages > 1 ) : ?>
					<?php
					// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- paginate_links returns safe HTML.
					echo paginate_links(
						array(
							'base'    => add_query_arg( 'paged', '%#%' ),
							'format'  => '',
							'current' => $page,
							'total'   => $total_pages,
						)
					);
					?>
				<?php endif; ?>
			</div>
		</div>
	</form>

	<style>
		.logged-only { background-color: #f0f6fc !important; }
		.logged-only:hover { background-color: #e5f0fa !important; }
	</style>
	<?php
}