<?php
/**
 * Login Protection Class
 *
 * Handles brute force protection by tracking failed login attempts
 * and temporarily blocking IPs after threshold is reached.
 *
 * @package JPKCom_Hide_Login
 * @since 1.0.0
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class JPKCom_Hide_Login_Login_Protection
 *
 * Provides brute force protection for login attempts.
 */
class JPKCom_Hide_Login_Login_Protection {

	/**
	 * IP Manager instance.
	 *
	 * @var JPKCom_Hide_Login_IP_Manager
	 */
	private JPKCom_Hide_Login_IP_Manager $ip_manager;

	/**
	 * Maximum login attempts before blocking.
	 *
	 * @var int
	 */
	private int $max_attempts = 5;

	/**
	 * Time window for counting attempts (in seconds).
	 *
	 * @var int
	 */
	private int $attempt_window = 60;

	/**
	 * Block duration after max attempts (in seconds).
	 *
	 * @var int
	 */
	private int $block_duration = 600;

	/**
	 * Constructor.
	 *
	 * @param JPKCom_Hide_Login_IP_Manager $ip_manager IP Manager instance.
	 */
	public function __construct( JPKCom_Hide_Login_IP_Manager $ip_manager ) {
		$this->ip_manager = $ip_manager;
	}

	/**
	 * Initialize hooks for login protection.
	 *
	 * @return void
	 */
	public function init_hooks(): void {
		add_action( 'wp_login_failed', [ $this, 'handle_failed_login' ], 10, 2 );
		add_filter( 'authenticate', [ $this, 'check_login_attempts' ], 30, 2 );
		add_action( 'wp_login', [ $this, 'clear_login_attempts' ], 10, 2 );
		add_action( 'jpkcom_hide_login_cleanup_attempts', [ $this, 'cleanup_expired_attempts' ] );
	}

	/**
	 * Handle failed login attempt.
	 *
	 * @param string   $username Username used in login attempt.
	 * @param \WP_Error $error    WP_Error object with error details.
	 *
	 * @return void
	 */
	public function handle_failed_login( string $username, \WP_Error $error ): void {
		$ip = $this->ip_manager->get_current_ip();

		// Skip if IP is whitelisted.
		if ( $this->ip_manager->is_ip_whitelisted( $ip ) ) {
			return;
		}

		// Increment attempt counter.
		$attempts = $this->get_login_attempts( $ip );
		$attempts++;

		$this->set_login_attempts( $ip, $attempts );

		// Block IP if threshold reached.
		if ( $attempts >= $this->max_attempts ) {
			$this->ip_manager->block_ip( $ip, $this->block_duration );

			$this->log_event(
				sprintf(
					'IP %s blocked after %d failed login attempts',
					$ip,
					$attempts
				)
			);
		} else {
			$this->log_event(
				sprintf(
					'Failed login attempt %d/%d from IP %s (username: %s)',
					$attempts,
					$this->max_attempts,
					$ip,
					$username
				)
			);
		}
	}

	/**
	 * Check login attempts before authentication.
	 *
	 * @param \WP_User|\WP_Error|null $user     User object or WP_Error.
	 * @param string                  $username Username used in login attempt.
	 *
	 * @return \WP_User|\WP_Error|null Modified user object or error.
	 */
	public function check_login_attempts( $user, string $username ) {
		$ip = $this->ip_manager->get_current_ip();

		// Skip if IP is whitelisted.
		if ( $this->ip_manager->is_ip_whitelisted( $ip ) ) {
			return $user;
		}

		// Check if IP is blocked.
		if ( $this->ip_manager->is_ip_blocked( $ip ) ) {
			$error = new \WP_Error(
				'jpkcom_hide_login_blocked',
				sprintf(
					/* translators: %d: Number of minutes until unblock */
					__( 'Too many failed login attempts. Please try again in %d minutes.', 'jpkcom-hide-login' ),
					(int) ceil( $this->block_duration / 60 )
				)
			);

			$this->log_event(
				sprintf(
					'Blocked login attempt from IP %s (username: %s)',
					$ip,
					$username
				)
			);

			return $error;
		}

		// Show remaining attempts if there were previous failures.
		$attempts = $this->get_login_attempts( $ip );

		if ( $attempts > 0 && is_wp_error( $user ) ) {
			$remaining = $this->max_attempts - $attempts;

			if ( $remaining > 0 ) {
				$user->add(
					'jpkcom_hide_login_attempts',
					sprintf(
						/* translators: %d: Number of login attempts remaining */
						_n(
							'%d login attempt remaining.',
							'%d login attempts remaining.',
							$remaining,
							'jpkcom-hide-login'
						),
						$remaining
					)
				);
			}
		}

		return $user;
	}

	/**
	 * Clear login attempts after successful login.
	 *
	 * @param string   $username Username used in login.
	 * @param \WP_User $user     User object.
	 *
	 * @return void
	 */
	public function clear_login_attempts( string $username, \WP_User $user ): void {
		$ip = $this->ip_manager->get_current_ip();

		$this->delete_login_attempts( $ip );

		$this->log_event(
			sprintf(
				'Successful login from IP %s (username: %s)',
				$ip,
				$username
			)
		);
	}

	/**
	 * Get number of login attempts for an IP.
	 *
	 * @param string $ip IP address.
	 *
	 * @return int Number of attempts.
	 */
	private function get_login_attempts( string $ip ): int {
		$key      = $this->get_attempt_key( $ip );
		$attempts = get_transient( $key );

		return is_numeric( $attempts ) ? (int) $attempts : 0;
	}

	/**
	 * Set number of login attempts for an IP.
	 *
	 * @param string $ip       IP address.
	 * @param int    $attempts Number of attempts.
	 *
	 * @return bool True on success, false on failure.
	 */
	private function set_login_attempts( string $ip, int $attempts ): bool {
		$key = $this->get_attempt_key( $ip );

		return set_transient( $key, $attempts, $this->attempt_window );
	}

	/**
	 * Delete login attempt counter for an IP.
	 *
	 * @param string $ip IP address.
	 *
	 * @return bool True on success, false on failure.
	 */
	private function delete_login_attempts( string $ip ): bool {
		$key = $this->get_attempt_key( $ip );

		return delete_transient( $key );
	}

	/**
	 * Get transient key for login attempts.
	 *
	 * @param string $ip IP address.
	 *
	 * @return string Transient key.
	 */
	private function get_attempt_key( string $ip ): string {
		return 'jpkcom_hide_login_attempts_' . md5( $ip );
	}

	/**
	 * Log an event to debug log if WP_DEBUG is enabled.
	 *
	 * @param string $message Log message.
	 *
	 * @return void
	 */
	private function log_event( string $message ): void {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[JPKCom Hide Login] ' . $message );
		}
	}

	/**
	 * Set maximum login attempts.
	 *
	 * @param int $attempts Number of attempts.
	 *
	 * @return void
	 */
	public function set_max_attempts( int $attempts ): void {
		$this->max_attempts = max( 1, $attempts );
	}

	/**
	 * Set attempt window duration.
	 *
	 * @param int $seconds Duration in seconds.
	 *
	 * @return void
	 */
	public function set_attempt_window( int $seconds ): void {
		$this->attempt_window = max( 1, $seconds );
	}

	/**
	 * Set block duration.
	 *
	 * @param int $seconds Duration in seconds.
	 *
	 * @return void
	 */
	public function set_block_duration( int $seconds ): void {
		$this->block_duration = max( 1, $seconds );
	}

	/**
	 * Get maximum login attempts.
	 *
	 * @return int Number of attempts.
	 */
	public function get_max_attempts(): int {
		return $this->max_attempts;
	}

	/**
	 * Get block duration.
	 *
	 * @return int Duration in seconds.
	 */
	public function get_block_duration(): int {
		return $this->block_duration;
	}

	/**
	 * Cleanup expired login attempt transients.
	 *
	 * This method searches for and removes all expired login attempt
	 * transients from the database to prevent buildup of old data.
	 *
	 * @return int Number of expired transients cleaned up.
	 */
	public function cleanup_expired_attempts(): int {
		global $wpdb;

		$count = 0;

		// Find all login attempt transients.
		$transient_prefix = '_transient_jpkcom_hide_login_attempts_';
		$timeout_prefix   = '_transient_timeout_jpkcom_hide_login_attempts_';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$expired_transients = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT option_name FROM {$wpdb->options}
				WHERE option_name LIKE %s
				AND option_value < %d",
				$wpdb->esc_like( $timeout_prefix ) . '%',
				time()
			)
		);

		if ( ! empty( $expired_transients ) ) {
			foreach ( $expired_transients as $timeout_option ) {
				// Extract the transient key.
				$transient_key = str_replace( $timeout_prefix, '', $timeout_option );

				// Delete both the timeout and the transient value.
				delete_transient( 'jpkcom_hide_login_attempts_' . $transient_key );
				$count++;
			}

			$this->log_event(
				sprintf(
					'Cleaned up %d expired login attempt transient(s)',
					$count
				)
			);
		}

		return $count;
	}
}
