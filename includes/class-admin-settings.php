<?php
/**
 * Admin Settings Class
 *
 * Handles the admin settings page for the plugin.
 *
 * @package JPKCom_Hide_Login
 * @since 1.0.0
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class JPKCom_Hide_Login_Admin_Settings
 *
 * Manages the admin settings interface.
 */
class JPKCom_Hide_Login_Admin_Settings {

	/**
	 * IP Manager instance.
	 *
	 * @var JPKCom_Hide_Login_IP_Manager
	 */
	private JPKCom_Hide_Login_IP_Manager $ip_manager;

	/**
	 * Mask Login instance.
	 *
	 * @var JPKCom_Hide_Login_Mask_Login
	 */
	private JPKCom_Hide_Login_Mask_Login $mask_login;

	/**
	 * Login Protection instance.
	 *
	 * @var JPKCom_Hide_Login_Login_Protection
	 */
	private JPKCom_Hide_Login_Login_Protection $login_protection;

	/**
	 * Option key for login slug.
	 *
	 * @var string
	 */
	private const OPTION_SLUG = 'jpkcom_hide_login_slug';

	/**
	 * Option key for maximum login attempts.
	 *
	 * @var string
	 */
	private const OPTION_MAX_ATTEMPTS = 'jpkcom_hide_login_max_attempts';

	/**
	 * Option key for attempt window duration.
	 *
	 * @var string
	 */
	private const OPTION_ATTEMPT_WINDOW = 'jpkcom_hide_login_attempt_window';

	/**
	 * Option key for block duration.
	 *
	 * @var string
	 */
	private const OPTION_BLOCK_DURATION = 'jpkcom_hide_login_block_duration';

	/**
	 * Constructor.
	 *
	 * @param JPKCom_Hide_Login_IP_Manager         $ip_manager       IP Manager instance.
	 * @param JPKCom_Hide_Login_Mask_Login         $mask_login       Mask Login instance.
	 * @param JPKCom_Hide_Login_Login_Protection   $login_protection Login Protection instance.
	 */
	public function __construct(
		JPKCom_Hide_Login_IP_Manager $ip_manager,
		JPKCom_Hide_Login_Mask_Login $mask_login,
		JPKCom_Hide_Login_Login_Protection $login_protection
	) {
		$this->ip_manager       = $ip_manager;
		$this->mask_login       = $mask_login;
		$this->login_protection = $login_protection;
	}

	/**
	 * Initialize hooks for admin settings.
	 *
	 * @return void
	 */
	public function init_hooks(): void {
		add_action( 'admin_menu', [ $this, 'add_settings_page' ] );
		add_action( 'admin_init', [ $this, 'register_settings' ] );
		add_action( 'admin_notices', [ $this, 'show_notices' ] );
		add_action( 'admin_post_jpkcom_hide_login_clear_blocks', [ $this, 'handle_clear_blocks' ] );
		add_action( 'admin_post_jpkcom_hide_login_add_whitelist', [ $this, 'handle_add_whitelist' ] );
		add_action( 'admin_post_jpkcom_hide_login_remove_whitelist', [ $this, 'handle_remove_whitelist' ] );
	}

	/**
	 * Add settings page to WordPress admin.
	 *
	 * @return void
	 */
	public function add_settings_page(): void {
		add_options_page(
			__( 'JPKCom Hide Login Settings', 'jpkcom-hide-login' ),
			__( 'Hide Login', 'jpkcom-hide-login' ),
			'manage_options',
			'jpkcom-hide-login',
			[ $this, 'render_settings_page' ]
		);
	}

	/**
	 * Register plugin settings.
	 *
	 * @return void
	 */
	public function register_settings(): void {
		// Login slug settings group.
		register_setting(
			'jpkcom_hide_login_settings',
			self::OPTION_SLUG,
			[
				'type'              => 'string',
				'sanitize_callback' => [ $this, 'sanitize_slug' ],
				'default'           => JPKCOM_HIDE_LOGIN_DEFAULT_SLUG,
			]
		);

		// Brute force protection settings group.
		register_setting(
			'jpkcom_hide_login_protection_settings',
			self::OPTION_MAX_ATTEMPTS,
			[
				'type'              => 'integer',
				'sanitize_callback' => [ $this, 'sanitize_max_attempts' ],
				'default'           => 5,
			]
		);

		register_setting(
			'jpkcom_hide_login_protection_settings',
			self::OPTION_ATTEMPT_WINDOW,
			[
				'type'              => 'integer',
				'sanitize_callback' => [ $this, 'sanitize_attempt_window' ],
				'default'           => 60,
			]
		);

		register_setting(
			'jpkcom_hide_login_protection_settings',
			self::OPTION_BLOCK_DURATION,
			[
				'type'              => 'integer',
				'sanitize_callback' => [ $this, 'sanitize_block_duration' ],
				'default'           => 600,
			]
		);
	}

	/**
	 * Sanitize the login slug.
	 *
	 * @param mixed $value Input value.
	 *
	 * @return string Sanitized slug.
	 */
	public function sanitize_slug( mixed $value ): string {
		// Handle null or empty values.
		if ( null === $value || '' === $value ) {
			return get_option( self::OPTION_SLUG, JPKCOM_HIDE_LOGIN_DEFAULT_SLUG );
		}

		$slug = sanitize_title_with_dashes( (string) $value );

		// Check for forbidden slugs.
		$forbidden = [
			'login',
			'wp-admin',
			'admin',
			'dashboard',
			'wp-login',
			'wp-login.php',
			'wp-login-php',
			'wp-signup',
			'wp-signup.php',
		];

		if ( in_array( $slug, $forbidden, true ) ) {
			add_settings_error(
				'jpkcom_hide_login_slug',
				'invalid_slug',
				__( 'The slug you have provided cannot be used. Please try a different one.', 'jpkcom-hide-login' ),
				'error'
			);

			return get_option( self::OPTION_SLUG, JPKCOM_HIDE_LOGIN_DEFAULT_SLUG );
		}

		// Check if slug exists as page/post.
		if ( $this->slug_exists_in_posts( $slug ) ) {
			add_settings_error(
				'jpkcom_hide_login_slug',
				'slug_exists',
				__( 'A page or post already exists with this URL. Please choose a different slug.', 'jpkcom-hide-login' ),
				'error'
			);

			return get_option( self::OPTION_SLUG, JPKCOM_HIDE_LOGIN_DEFAULT_SLUG );
		}

		// Update the mask login instance.
		$this->mask_login->set_custom_slug( $slug );

		// Note: WordPress automatically shows "Settings saved" message,
		// so we don't need to add our own success message here.
		return $slug;
	}

	/**
	 * Sanitize maximum login attempts.
	 *
	 * @param mixed $value Input value.
	 *
	 * @return int Sanitized value.
	 */
	public function sanitize_max_attempts( $value ): int {
		$attempts = (int) $value;

		if ( $attempts < 1 ) {
			add_settings_error(
				'jpkcom_hide_login_max_attempts',
				'invalid_attempts',
				__( 'Maximum login attempts must be at least 1.', 'jpkcom-hide-login' ),
				'error'
			);
			return (int) get_option( self::OPTION_MAX_ATTEMPTS, 5 );
		}

		if ( $attempts > 100 ) {
			add_settings_error(
				'jpkcom_hide_login_max_attempts',
				'invalid_attempts',
				__( 'Maximum login attempts cannot exceed 100.', 'jpkcom-hide-login' ),
				'error'
			);
			return (int) get_option( self::OPTION_MAX_ATTEMPTS, 5 );
		}

		// Update the login protection instance.
		$this->login_protection->set_max_attempts( $attempts );

		return $attempts;
	}

	/**
	 * Sanitize attempt window duration.
	 *
	 * @param mixed $value Input value.
	 *
	 * @return int Sanitized value.
	 */
	public function sanitize_attempt_window( $value ): int {
		$window = (int) $value;

		if ( $window < 1 ) {
			add_settings_error(
				'jpkcom_hide_login_attempt_window',
				'invalid_window',
				__( 'Attempt window must be at least 1 second.', 'jpkcom-hide-login' ),
				'error'
			);
			return (int) get_option( self::OPTION_ATTEMPT_WINDOW, 60 );
		}

		if ( $window > 3600 ) {
			add_settings_error(
				'jpkcom_hide_login_attempt_window',
				'invalid_window',
				__( 'Attempt window cannot exceed 3600 seconds (1 hour).', 'jpkcom-hide-login' ),
				'error'
			);
			return (int) get_option( self::OPTION_ATTEMPT_WINDOW, 60 );
		}

		// Update the login protection instance.
		$this->login_protection->set_attempt_window( $window );

		return $window;
	}

	/**
	 * Sanitize block duration.
	 *
	 * @param mixed $value Input value.
	 *
	 * @return int Sanitized value.
	 */
	public function sanitize_block_duration( $value ): int {
		$duration = (int) $value;

		if ( $duration < 1 ) {
			add_settings_error(
				'jpkcom_hide_login_block_duration',
				'invalid_duration',
				__( 'Block duration must be at least 1 second.', 'jpkcom-hide-login' ),
				'error'
			);
			return (int) get_option( self::OPTION_BLOCK_DURATION, 600 );
		}

		if ( $duration > 86400 ) {
			add_settings_error(
				'jpkcom_hide_login_block_duration',
				'invalid_duration',
				__( 'Block duration cannot exceed 86400 seconds (24 hours).', 'jpkcom-hide-login' ),
				'error'
			);
			return (int) get_option( self::OPTION_BLOCK_DURATION, 600 );
		}

		// Update the login protection instance.
		$this->login_protection->set_block_duration( $duration );

		return $duration;
	}

	/**
	 * Check if slug exists as a post or page.
	 *
	 * @param string $slug Slug to check.
	 *
	 * @return bool True if exists, false otherwise.
	 */
	private function slug_exists_in_posts( string $slug ): bool {
		global $wpdb;

		$query = $wpdb->prepare(
			"SELECT ID FROM $wpdb->posts WHERE post_name = %s AND post_status = 'publish' AND post_type IN ('post', 'page') LIMIT 1",
			$slug
		);

		return (bool) $wpdb->get_var( $query );
	}

	/**
	 * Render the settings page.
	 *
	 * @return void
	 */
	public function render_settings_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$current_slug     = get_option( self::OPTION_SLUG, JPKCOM_HIDE_LOGIN_DEFAULT_SLUG );
		$current_url      = home_url( '/' . $current_slug . '/' );
		$whitelist        = $this->ip_manager->get_whitelist();
		$blocked_ips      = $this->ip_manager->get_blocked_ips();
		$current_ip       = $this->ip_manager->get_current_ip();
		$max_attempts     = (int) get_option( self::OPTION_MAX_ATTEMPTS, 5 );
		$attempt_window   = (int) get_option( self::OPTION_ATTEMPT_WINDOW, 60 );
		$block_duration   = (int) get_option( self::OPTION_BLOCK_DURATION, 600 );
		$block_minutes    = (int) ceil( $block_duration / 60 );

		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

			<!-- Login Slug Settings -->
			<form method="post" action="options.php">
				<?php
				settings_fields( 'jpkcom_hide_login_settings' );
				do_settings_sections( 'jpkcom_hide_login_settings' );
				?>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">
							<label for="<?php echo esc_attr( self::OPTION_SLUG ); ?>">
								<?php esc_html_e( 'Custom Login URL Slug', 'jpkcom-hide-login' ); ?>
							</label>
						</th>
						<td>
							<input
								name="<?php echo esc_attr( self::OPTION_SLUG ); ?>"
								type="text"
								id="<?php echo esc_attr( self::OPTION_SLUG ); ?>"
								value="<?php echo esc_attr( $current_slug ); ?>"
								class="regular-text"
								placeholder="<?php echo esc_attr( JPKCOM_HIDE_LOGIN_DEFAULT_SLUG ); ?>"
								required
							/>
							<p class="description">
								<?php
								printf(
									/* translators: %s: Full custom login URL */
									esc_html__( 'Your current login URL: %s', 'jpkcom-hide-login' ),
									'<code>' . esc_html( $current_url ) . '</code>'
								);
								?>
							</p>
						</td>
					</tr>
				</table>

				<?php submit_button( __( 'Save Changes', 'jpkcom-hide-login' ) ); ?>
			</form>

			<hr>

			<!-- Brute Force Protection Settings -->
			<h2><?php esc_html_e( 'Brute Force Protection Settings', 'jpkcom-hide-login' ); ?></h2>
			<form method="post" action="options.php">
				<?php
				settings_fields( 'jpkcom_hide_login_protection_settings' );
				do_settings_sections( 'jpkcom_hide_login_protection_settings' );
				?>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">
							<label for="<?php echo esc_attr( self::OPTION_MAX_ATTEMPTS ); ?>">
								<?php esc_html_e( 'Maximum Login Attempts', 'jpkcom-hide-login' ); ?>
							</label>
						</th>
						<td>
							<input
								name="<?php echo esc_attr( self::OPTION_MAX_ATTEMPTS ); ?>"
								type="number"
								id="<?php echo esc_attr( self::OPTION_MAX_ATTEMPTS ); ?>"
								value="<?php echo esc_attr( (string) $max_attempts ); ?>"
								class="small-text"
								min="1"
								max="100"
								required
							/>
							<p class="description">
								<?php esc_html_e( 'Number of failed login attempts before an IP is blocked (1-100). Default: 5', 'jpkcom-hide-login' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="<?php echo esc_attr( self::OPTION_ATTEMPT_WINDOW ); ?>">
								<?php esc_html_e( 'Attempt Window (seconds)', 'jpkcom-hide-login' ); ?>
							</label>
						</th>
						<td>
							<input
								name="<?php echo esc_attr( self::OPTION_ATTEMPT_WINDOW ); ?>"
								type="number"
								id="<?php echo esc_attr( self::OPTION_ATTEMPT_WINDOW ); ?>"
								value="<?php echo esc_attr( (string) $attempt_window ); ?>"
								class="small-text"
								min="1"
								max="3600"
								required
							/>
							<p class="description">
								<?php esc_html_e( 'Time window for counting failed attempts in seconds (1-3600). Default: 60', 'jpkcom-hide-login' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="<?php echo esc_attr( self::OPTION_BLOCK_DURATION ); ?>">
								<?php esc_html_e( 'Block Duration (seconds)', 'jpkcom-hide-login' ); ?>
							</label>
						</th>
						<td>
							<input
								name="<?php echo esc_attr( self::OPTION_BLOCK_DURATION ); ?>"
								type="number"
								id="<?php echo esc_attr( self::OPTION_BLOCK_DURATION ); ?>"
								value="<?php echo esc_attr( (string) $block_duration ); ?>"
								class="small-text"
								min="1"
								max="86400"
								required
							/>
							<p class="description">
								<?php
								printf(
									/* translators: %d: Block duration in minutes */
									esc_html__( 'How long to block an IP after max attempts in seconds (1-86400). Default: 600 (%d minutes)', 'jpkcom-hide-login' ),
									10
								);
								?>
							</p>
						</td>
					</tr>
				</table>

				<?php submit_button( __( 'Save Brute Force Settings', 'jpkcom-hide-login' ) ); ?>
			</form>

			<hr>

			<!-- Brute Force Protection Info -->
			<h2><?php esc_html_e( 'Brute Force Protection Status', 'jpkcom-hide-login' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Current Status', 'jpkcom-hide-login' ); ?></th>
					<td>
						<span class="dashicons dashicons-yes-alt" style="color: #46b450;"></span>
						<?php
						printf(
							/* translators: 1: Maximum login attempts, 2: Block duration in minutes */
							esc_html__( 'Active - IPs are blocked for %2$d minutes after %1$d failed login attempts', 'jpkcom-hide-login' ),
							$max_attempts,
							$block_minutes
						);
						?>
					</td>
				</tr>
			</table>

			<!-- Blocked IPs -->
			<h3><?php esc_html_e( 'Currently Blocked IPs', 'jpkcom-hide-login' ); ?></h3>
			<?php if ( ! empty( $blocked_ips ) ) : ?>
				<table class="wp-list-table widefat fixed striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'IP Address', 'jpkcom-hide-login' ); ?></th>
							<th><?php esc_html_e( 'Blocked At', 'jpkcom-hide-login' ); ?></th>
							<th><?php esc_html_e( 'Expires At', 'jpkcom-hide-login' ); ?></th>
							<th><?php esc_html_e( 'Time Remaining', 'jpkcom-hide-login' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $blocked_ips as $data ) : ?>
							<?php
							$blocked_at = isset( $data['blocked_at'] ) ? (int) $data['blocked_at'] : 0;
							$expiry     = isset( $data['expiry'] ) ? (int) $data['expiry'] : 0;
							$remaining  = max( 0, $expiry - time() );
							$ip_display = isset( $data['ip'] ) ? esc_html( $data['ip'] ) : esc_html__( 'Hidden', 'jpkcom-hide-login' );
							?>
							<tr>
								<td><code><?php echo $ip_display; ?></code></td>
								<td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $blocked_at ) ); ?></td>
								<td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $expiry ) ); ?></td>
								<td><?php echo esc_html( human_time_diff( time(), $expiry ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<p>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
						<?php wp_nonce_field( 'jpkcom_hide_login_clear_blocks', 'jpkcom_hide_login_nonce' ); ?>
						<input type="hidden" name="action" value="jpkcom_hide_login_clear_blocks">
						<button type="submit" class="button button-secondary">
							<?php esc_html_e( 'Clear All Blocked IPs', 'jpkcom-hide-login' ); ?>
						</button>
					</form>
				</p>
			<?php else : ?>
				<p><?php esc_html_e( 'No IPs are currently blocked.', 'jpkcom-hide-login' ); ?></p>
			<?php endif; ?>

			<hr>

			<!-- IP Whitelist -->
			<h2><?php esc_html_e( 'IP Whitelist', 'jpkcom-hide-login' ); ?></h2>
			<p><?php esc_html_e( 'Whitelisted IP addresses will never be blocked by brute force protection. Supports CIDR notation (e.g., 192.168.1.0/24).', 'jpkcom-hide-login' ); ?></p>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Your Current IP', 'jpkcom-hide-login' ); ?></th>
					<td>
						<code><?php echo esc_html( $current_ip ); ?></code>
						<?php if ( $this->ip_manager->is_ip_whitelisted( $current_ip ) ) : ?>
							<span class="dashicons dashicons-yes-alt" style="color: #46b450;" title="<?php esc_attr_e( 'Whitelisted', 'jpkcom-hide-login' ); ?>"></span>
						<?php endif; ?>
					</td>
				</tr>
			</table>

			<!-- Add to Whitelist -->
			<h3><?php esc_html_e( 'Add IP to Whitelist', 'jpkcom-hide-login' ); ?></h3>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'jpkcom_hide_login_add_whitelist', 'jpkcom_hide_login_nonce' ); ?>
				<input type="hidden" name="action" value="jpkcom_hide_login_add_whitelist">
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">
							<label for="whitelist_ip">
								<?php esc_html_e( 'IP Address or CIDR Range', 'jpkcom-hide-login' ); ?>
							</label>
						</th>
						<td>
							<input
								name="whitelist_ip"
								type="text"
								id="whitelist_ip"
								class="regular-text"
								placeholder="192.168.1.1 or 192.168.1.0/24"
								required
							/>
							<p class="description">
								<?php esc_html_e( 'Enter a single IP address or a CIDR range.', 'jpkcom-hide-login' ); ?>
							</p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Add to Whitelist', 'jpkcom-hide-login' ), 'secondary' ); ?>
			</form>

			<!-- Current Whitelist -->
			<?php if ( ! empty( $whitelist ) ) : ?>
				<h3><?php esc_html_e( 'Current Whitelist', 'jpkcom-hide-login' ); ?></h3>
				<table class="wp-list-table widefat fixed striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'IP Address / Range', 'jpkcom-hide-login' ); ?></th>
							<th><?php esc_html_e( 'Actions', 'jpkcom-hide-login' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $whitelist as $ip ) : ?>
							<tr>
								<td><code><?php echo esc_html( $ip ); ?></code></td>
								<td>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
										<?php wp_nonce_field( 'jpkcom_hide_login_remove_whitelist', 'jpkcom_hide_login_nonce' ); ?>
										<input type="hidden" name="action" value="jpkcom_hide_login_remove_whitelist">
										<input type="hidden" name="whitelist_ip" value="<?php echo esc_attr( $ip ); ?>">
										<button type="submit" class="button button-small button-link-delete">
											<?php esc_html_e( 'Remove', 'jpkcom-hide-login' ); ?>
										</button>
									</form>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php else : ?>
				<p><?php esc_html_e( 'No IPs are currently whitelisted.', 'jpkcom-hide-login' ); ?></p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Handle clear all blocks request.
	 *
	 * @return void
	 */
	public function handle_clear_blocks(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'jpkcom-hide-login' ) );
		}

		check_admin_referer( 'jpkcom_hide_login_clear_blocks', 'jpkcom_hide_login_nonce' );

		$this->ip_manager->clear_all_blocks();

		wp_safe_redirect(
			add_query_arg(
				[ 'page' => 'jpkcom-hide-login', 'message' => 'blocks_cleared' ],
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	/**
	 * Handle add to whitelist request.
	 *
	 * @return void
	 */
	public function handle_add_whitelist(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'jpkcom-hide-login' ) );
		}

		check_admin_referer( 'jpkcom_hide_login_add_whitelist', 'jpkcom_hide_login_nonce' );

		$ip = isset( $_POST['whitelist_ip'] ) ? sanitize_text_field( wp_unslash( $_POST['whitelist_ip'] ) ) : '';

		if ( empty( $ip ) ) {
			wp_safe_redirect(
				add_query_arg(
					[ 'page' => 'jpkcom-hide-login', 'message' => 'whitelist_empty' ],
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$success = $this->ip_manager->add_to_whitelist( $ip );

		wp_safe_redirect(
			add_query_arg(
				[
					'page'    => 'jpkcom-hide-login',
					'message' => $success ? 'whitelist_added' : 'whitelist_invalid',
				],
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	/**
	 * Handle remove from whitelist request.
	 *
	 * @return void
	 */
	public function handle_remove_whitelist(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'jpkcom-hide-login' ) );
		}

		check_admin_referer( 'jpkcom_hide_login_remove_whitelist', 'jpkcom_hide_login_nonce' );

		$ip = isset( $_POST['whitelist_ip'] ) ? sanitize_text_field( wp_unslash( $_POST['whitelist_ip'] ) ) : '';

		if ( ! empty( $ip ) ) {
			$this->ip_manager->remove_from_whitelist( $ip );
		}

		wp_safe_redirect(
			add_query_arg(
				[ 'page' => 'jpkcom-hide-login', 'message' => 'whitelist_removed' ],
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	/**
	 * Show admin notices based on URL parameters.
	 *
	 * @return void
	 */
	public function show_notices(): void {
		if ( ! isset( $_GET['page'] ) || 'jpkcom-hide-login' !== $_GET['page'] ) {
			return;
		}

		if ( ! isset( $_GET['message'] ) ) {
			return;
		}

		$message = sanitize_key( $_GET['message'] );
		$messages = [
			'blocks_cleared'    => [
				'type' => 'success',
				'text' => __( 'All blocked IPs have been cleared successfully.', 'jpkcom-hide-login' ),
			],
			'whitelist_added'   => [
				'type' => 'success',
				'text' => __( 'IP address added to whitelist successfully.', 'jpkcom-hide-login' ),
			],
			'whitelist_removed' => [
				'type' => 'success',
				'text' => __( 'IP address removed from whitelist successfully.', 'jpkcom-hide-login' ),
			],
			'whitelist_invalid' => [
				'type' => 'error',
				'text' => __( 'Invalid IP address or CIDR range.', 'jpkcom-hide-login' ),
			],
			'whitelist_empty'   => [
				'type' => 'error',
				'text' => __( 'Please enter an IP address.', 'jpkcom-hide-login' ),
			],
		];

		if ( isset( $messages[ $message ] ) ) {
			printf(
				'<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
				esc_attr( $messages[ $message ]['type'] ),
				esc_html( $messages[ $message ]['text'] )
			);
		}
	}
}
