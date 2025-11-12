<?php
/**
 * WP-CLI Commands for JPKCom Hide Login
 *
 * Provides command-line management for the plugin.
 *
 * @package JPKCom_Hide_Login
 * @since 1.2.0
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage JPKCom Hide Login plugin settings and security features.
 *
 * ## OVERVIEW
 *
 * Provides command-line management for custom login URLs, IP whitelist,
 * blocked IPs, and brute force protection settings.
 *
 * ## AVAILABLE COMMANDS
 *
 * * status       - Display plugin status and configuration
 * * get-slug     - Get current login slug
 * * set-slug     - Set login slug
 * * whitelist    - Manage IP whitelist (list, add, remove)
 * * blocked      - Manage blocked IPs (list, clear)
 * * protection   - Configure brute force protection settings
 * * cleanup      - Clean up expired login attempt data
 *
 * ## EXAMPLES
 *
 *     # Display plugin status
 *     wp jpkcom-hide-login status
 *
 *     # Change login URL
 *     wp jpkcom-hide-login set-slug my-secure-login
 *
 *     # Add IP to whitelist
 *     wp jpkcom-hide-login whitelist add 192.168.1.100
 *
 *     # Configure brute force protection
 *     wp jpkcom-hide-login protection max-attempts 10
 *
 * @package JPKCom_Hide_Login
 */
class JPKCom_Hide_Login_WP_CLI {

	/**
	 * IP Manager instance.
	 *
	 * @var JPKCom_Hide_Login_IP_Manager
	 */
	private JPKCom_Hide_Login_IP_Manager $ip_manager;

	/**
	 * Login Protection instance.
	 *
	 * @var JPKCom_Hide_Login_Login_Protection
	 */
	private JPKCom_Hide_Login_Login_Protection $login_protection;

	/**
	 * Constructor.
	 *
	 * @param JPKCom_Hide_Login_IP_Manager       $ip_manager       IP Manager instance.
	 * @param JPKCom_Hide_Login_Login_Protection $login_protection Login Protection instance.
	 */
	public function __construct(
		JPKCom_Hide_Login_IP_Manager $ip_manager,
		JPKCom_Hide_Login_Login_Protection $login_protection
	) {
		$this->ip_manager       = $ip_manager;
		$this->login_protection = $login_protection;
	}

	/**
	 * Display plugin status and configuration.
	 *
	 * ## EXAMPLES
	 *
	 *     wp jpkcom-hide-login status
	 *
	 * @when after_wp_load
	 */
	public function status(): void {
		$slug           = get_option( 'jpkcom_hide_login_slug', JPKCOM_HIDE_LOGIN_DEFAULT_SLUG );
		$login_url      = home_url( '/' . $slug . '/' );
		$max_attempts   = (int) get_option( 'jpkcom_hide_login_max_attempts', 5 );
		$attempt_window = (int) get_option( 'jpkcom_hide_login_attempt_window', 60 );
		$block_duration = (int) get_option( 'jpkcom_hide_login_block_duration', 600 );
		$whitelist      = $this->ip_manager->get_whitelist();
		$blocked_ips    = $this->ip_manager->get_blocked_ips();

		\WP_CLI::line( '' );
		\WP_CLI::line( \WP_CLI::colorize( '%G=== JPKCom Hide Login Status ===%n' ) );
		\WP_CLI::line( '' );
		\WP_CLI::line( \WP_CLI::colorize( '%YLogin Configuration:%n' ) );
		\WP_CLI::line( '  Current Slug: ' . $slug );
		\WP_CLI::line( '  Login URL: ' . $login_url );
		\WP_CLI::line( '' );
		\WP_CLI::line( \WP_CLI::colorize( '%YBrute Force Protection:%n' ) );
		\WP_CLI::line( '  Max Attempts: ' . $max_attempts );
		\WP_CLI::line( '  Attempt Window: ' . $attempt_window . ' seconds' );
		\WP_CLI::line( '  Block Duration: ' . $block_duration . ' seconds (' . (int) ceil( $block_duration / 60 ) . ' minutes)' );
		\WP_CLI::line( '' );
		\WP_CLI::line( \WP_CLI::colorize( '%YIP Management:%n' ) );
		\WP_CLI::line( '  Whitelisted IPs: ' . count( $whitelist ) );
		\WP_CLI::line( '  Blocked IPs: ' . count( $blocked_ips ) );
		\WP_CLI::line( '' );
	}

	/**
	 * Get the current login slug.
	 *
	 * ## EXAMPLES
	 *
	 *     wp jpkcom-hide-login get-slug
	 *
	 * @when after_wp_load
	 */
	public function get_slug(): void {
		$slug = get_option( 'jpkcom_hide_login_slug', JPKCOM_HIDE_LOGIN_DEFAULT_SLUG );
		\WP_CLI::success( 'Current login slug: ' . $slug );
	}

	/**
	 * Set the login slug.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : The new login slug.
	 *
	 * ## EXAMPLES
	 *
	 *     wp jpkcom-hide-login set-slug my-secure-login
	 *
	 * @when after_wp_load
	 *
	 * @param array<int, string> $args Command arguments.
	 */
	public function set_slug( array $args ): void {
		if ( ! isset( $args[0] ) || empty( $args[0] ) ) {
			\WP_CLI::error( 'Please provide a slug.' );
			return;
		}

		$slug = sanitize_title_with_dashes( $args[0] );

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
			\WP_CLI::error( 'The slug you have provided cannot be used. Please try a different one.' );
			return;
		}

		update_option( 'jpkcom_hide_login_slug', $slug );
		$login_url = home_url( '/' . $slug . '/' );
		\WP_CLI::success( 'Login slug updated to: ' . $slug );
		\WP_CLI::line( 'New login URL: ' . $login_url );
	}

	/**
	 * Manage IP whitelist.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : Action to perform: list, add, remove
	 *
	 * [<ip>]
	 * : IP address or CIDR range (required for add/remove)
	 *
	 * ## EXAMPLES
	 *
	 *     wp jpkcom-hide-login whitelist list
	 *     wp jpkcom-hide-login whitelist add 192.168.1.100
	 *     wp jpkcom-hide-login whitelist add 192.168.1.0/24
	 *     wp jpkcom-hide-login whitelist remove 192.168.1.100
	 *
	 * @when after_wp_load
	 *
	 * @param array<int, string> $args Command arguments.
	 */
	public function whitelist( array $args ): void {
		if ( ! isset( $args[0] ) ) {
			\WP_CLI::error( 'Please specify an action: list, add, remove' );
			return;
		}

		$action = $args[0];

		switch ( $action ) {
			case 'list':
				$this->whitelist_list();
				break;

			case 'add':
				if ( ! isset( $args[1] ) || empty( $args[1] ) ) {
					\WP_CLI::error( 'Please provide an IP address or CIDR range.' );
					return;
				}
				$this->whitelist_add( $args[1] );
				break;

			case 'remove':
				if ( ! isset( $args[1] ) || empty( $args[1] ) ) {
					\WP_CLI::error( 'Please provide an IP address.' );
					return;
				}
				$this->whitelist_remove( $args[1] );
				break;

			default:
				\WP_CLI::error( 'Invalid action. Use: list, add, remove' );
		}
	}

	/**
	 * List whitelisted IPs.
	 *
	 * @return void
	 */
	private function whitelist_list(): void {
		$whitelist = $this->ip_manager->get_whitelist();

		if ( empty( $whitelist ) ) {
			\WP_CLI::warning( 'No IPs are currently whitelisted.' );
			return;
		}

		\WP_CLI::line( '' );
		\WP_CLI::line( \WP_CLI::colorize( '%G=== Whitelisted IPs ===%n' ) );
		\WP_CLI::line( '' );

		foreach ( $whitelist as $ip ) {
			\WP_CLI::line( '  • ' . $ip );
		}

		\WP_CLI::line( '' );
		\WP_CLI::success( 'Total: ' . count( $whitelist ) . ' IP(s)' );
	}

	/**
	 * Add IP to whitelist.
	 *
	 * @param string $ip IP address or CIDR range.
	 *
	 * @return void
	 */
	private function whitelist_add( string $ip ): void {
		$success = $this->ip_manager->add_to_whitelist( $ip );

		if ( $success ) {
			\WP_CLI::success( 'IP address added to whitelist: ' . $ip );
		} else {
			\WP_CLI::error( 'Failed to add IP address. Please check the format.' );
		}
	}

	/**
	 * Remove IP from whitelist.
	 *
	 * @param string $ip IP address.
	 *
	 * @return void
	 */
	private function whitelist_remove( string $ip ): void {
		$success = $this->ip_manager->remove_from_whitelist( $ip );

		if ( $success ) {
			\WP_CLI::success( 'IP address removed from whitelist: ' . $ip );
		} else {
			\WP_CLI::error( 'Failed to remove IP address.' );
		}
	}

	/**
	 * Manage blocked IPs.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : Action to perform: list, clear
	 *
	 * ## EXAMPLES
	 *
	 *     wp jpkcom-hide-login blocked list
	 *     wp jpkcom-hide-login blocked clear
	 *
	 * @when after_wp_load
	 *
	 * @param array<int, string> $args Command arguments.
	 */
	public function blocked( array $args ): void {
		if ( ! isset( $args[0] ) ) {
			\WP_CLI::error( 'Please specify an action: list, clear' );
			return;
		}

		$action = $args[0];

		switch ( $action ) {
			case 'list':
				$this->blocked_list();
				break;

			case 'clear':
				$this->blocked_clear();
				break;

			default:
				\WP_CLI::error( 'Invalid action. Use: list, clear' );
		}
	}

	/**
	 * List blocked IPs.
	 *
	 * @return void
	 */
	private function blocked_list(): void {
		$blocked_ips = $this->ip_manager->get_blocked_ips();

		if ( empty( $blocked_ips ) ) {
			\WP_CLI::warning( 'No IPs are currently blocked.' );
			return;
		}

		\WP_CLI::line( '' );
		\WP_CLI::line( \WP_CLI::colorize( '%G=== Blocked IPs ===%n' ) );
		\WP_CLI::line( '' );

		$items = [];
		foreach ( $blocked_ips as $data ) {
			$ip         = $data['ip'] ?? 'Hidden';
			$blocked_at = isset( $data['blocked_at'] ) ? (int) $data['blocked_at'] : 0;
			$expiry     = isset( $data['expiry'] ) ? (int) $data['expiry'] : 0;
			$remaining  = max( 0, $expiry - time() );

			$items[] = [
				'IP'         => $ip,
				'Blocked At' => gmdate( 'Y-m-d H:i:s', $blocked_at ),
				'Expires At' => gmdate( 'Y-m-d H:i:s', $expiry ),
				'Remaining'  => human_time_diff( time(), $expiry ),
			];
		}

		\WP_CLI\Utils\format_items( 'table', $items, [ 'IP', 'Blocked At', 'Expires At', 'Remaining' ] );
		\WP_CLI::line( '' );
		\WP_CLI::success( 'Total: ' . count( $blocked_ips ) . ' IP(s)' );
	}

	/**
	 * Clear all blocked IPs.
	 *
	 * @return void
	 */
	private function blocked_clear(): void {
		$success = $this->ip_manager->clear_all_blocks();

		if ( $success ) {
			\WP_CLI::success( 'All blocked IPs have been cleared.' );
		} else {
			\WP_CLI::error( 'Failed to clear blocked IPs.' );
		}
	}

	/**
	 * Manage brute force protection settings.
	 *
	 * ## OPTIONS
	 *
	 * <setting>
	 * : Setting to manage: max-attempts, attempt-window, block-duration
	 *
	 * [<value>]
	 * : New value for the setting (required for set operations)
	 *
	 * ## EXAMPLES
	 *
	 *     wp jpkcom-hide-login protection max-attempts 10
	 *     wp jpkcom-hide-login protection attempt-window 120
	 *     wp jpkcom-hide-login protection block-duration 1800
	 *
	 * @when after_wp_load
	 *
	 * @param array<int, string> $args Command arguments.
	 */
	public function protection( array $args ): void {
		if ( ! isset( $args[0] ) ) {
			\WP_CLI::error( 'Please specify a setting: max-attempts, attempt-window, block-duration' );
			return;
		}

		$setting = $args[0];
		$value   = isset( $args[1] ) ? (int) $args[1] : null;

		switch ( $setting ) {
			case 'max-attempts':
				$this->protection_max_attempts( $value );
				break;

			case 'attempt-window':
				$this->protection_attempt_window( $value );
				break;

			case 'block-duration':
				$this->protection_block_duration( $value );
				break;

			default:
				\WP_CLI::error( 'Invalid setting. Use: max-attempts, attempt-window, block-duration' );
		}
	}

	/**
	 * Set maximum login attempts.
	 *
	 * @param int|null $value New value.
	 *
	 * @return void
	 */
	private function protection_max_attempts( ?int $value ): void {
		if ( null === $value ) {
			$current = (int) get_option( 'jpkcom_hide_login_max_attempts', 5 );
			\WP_CLI::line( 'Current max attempts: ' . $current );
			return;
		}

		if ( $value < 1 || $value > 100 ) {
			\WP_CLI::error( 'Value must be between 1 and 100.' );
			return;
		}

		update_option( 'jpkcom_hide_login_max_attempts', $value );
		$this->login_protection->set_max_attempts( $value );
		\WP_CLI::success( 'Max attempts updated to: ' . $value );
	}

	/**
	 * Set attempt window duration.
	 *
	 * @param int|null $value New value.
	 *
	 * @return void
	 */
	private function protection_attempt_window( ?int $value ): void {
		if ( null === $value ) {
			$current = (int) get_option( 'jpkcom_hide_login_attempt_window', 60 );
			\WP_CLI::line( 'Current attempt window: ' . $current . ' seconds' );
			return;
		}

		if ( $value < 1 || $value > 3600 ) {
			\WP_CLI::error( 'Value must be between 1 and 3600 seconds.' );
			return;
		}

		update_option( 'jpkcom_hide_login_attempt_window', $value );
		$this->login_protection->set_attempt_window( $value );
		\WP_CLI::success( 'Attempt window updated to: ' . $value . ' seconds' );
	}

	/**
	 * Set block duration.
	 *
	 * @param int|null $value New value.
	 *
	 * @return void
	 */
	private function protection_block_duration( ?int $value ): void {
		if ( null === $value ) {
			$current = (int) get_option( 'jpkcom_hide_login_block_duration', 600 );
			\WP_CLI::line( 'Current block duration: ' . $current . ' seconds (' . (int) ceil( $current / 60 ) . ' minutes)' );
			return;
		}

		if ( $value < 1 || $value > 86400 ) {
			\WP_CLI::error( 'Value must be between 1 and 86400 seconds (24 hours).' );
			return;
		}

		update_option( 'jpkcom_hide_login_block_duration', $value );
		$this->login_protection->set_block_duration( $value );
		\WP_CLI::success( 'Block duration updated to: ' . $value . ' seconds (' . (int) ceil( $value / 60 ) . ' minutes)' );
	}

	/**
	 * Cleanup expired login attempt transients.
	 *
	 * Manually trigger the cleanup of expired login attempt data from the database.
	 *
	 * ## EXAMPLES
	 *
	 *     wp jpkcom-hide-login cleanup
	 *
	 * @when after_wp_load
	 */
	public function cleanup(): void {
		\WP_CLI::line( 'Cleaning up expired login attempt transients...' );

		$count = $this->login_protection->cleanup_expired_attempts();

		if ( $count > 0 ) {
			\WP_CLI::success( sprintf( 'Cleaned up %d expired login attempt transient(s).', $count ) );
		} else {
			\WP_CLI::success( 'No expired login attempt transients found.' );
		}
	}
}
