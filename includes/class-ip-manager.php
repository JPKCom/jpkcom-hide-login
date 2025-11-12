<?php
/**
 * IP Manager Class
 *
 * Handles IP whitelist, blocklist, and IP-based access control.
 *
 * @package JPKCom_Hide_Login
 * @since 1.0.0
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class JPKCom_Hide_Login_IP_Manager
 *
 * Manages IP addresses for whitelist and temporary blocklist.
 */
class JPKCom_Hide_Login_IP_Manager {

	/**
	 * Transient key for blocked IPs list.
	 *
	 * @var string
	 */
	private const BLOCKED_IPS_KEY = 'jpkcom_hide_login_blocked_ips';

	/**
	 * Option key for whitelisted IPs.
	 *
	 * @var string
	 */
	private const WHITELIST_OPTION = 'jpkcom_hide_login_ip_whitelist';

	/**
	 * Get the current user's IP address.
	 *
	 * @return string IP address or 'unknown' if not available.
	 */
	public function get_current_ip(): string {
		$ip = '';

		// Check for proxied IP addresses.
		$headers = [
			'HTTP_CF_CONNECTING_IP', // Cloudflare
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		];

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				// For X-Forwarded-For, take the first IP.
				if ( str_contains( $ip, ',' ) ) {
					$ips = explode( ',', $ip );
					$ip  = trim( $ips[0] );
				}
				break;
			}
		}

		// Validate IP address.
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $ip;
		}

		return 'unknown';
	}

	/**
	 * Check if an IP address is whitelisted.
	 *
	 * @param string $ip IP address to check.
	 *
	 * @return bool True if whitelisted, false otherwise.
	 */
	public function is_ip_whitelisted( string $ip ): bool {
		// Always whitelist localhost and server IP.
		$default_whitelist = [
			'127.0.0.1',
			'::1',
		];

		if ( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
			$default_whitelist[] = sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) );
		}

		if ( in_array( $ip, $default_whitelist, true ) ) {
			return true;
		}

		// Check user-defined whitelist.
		$whitelist = $this->get_whitelist();

		return $this->is_ip_in_list( $ip, $whitelist );
	}

	/**
	 * Check if an IP address is blocked.
	 *
	 * @param string $ip IP address to check.
	 *
	 * @return bool True if blocked, false otherwise.
	 */
	public function is_ip_blocked( string $ip ): bool {
		$blocked_list = $this->get_blocked_ips();
		$ip_hash      = $this->hash_ip( $ip );

		if ( ! isset( $blocked_list[ $ip_hash ] ) ) {
			return false;
		}

		// Check if block has expired.
		$expiry = $blocked_list[ $ip_hash ]['expiry'] ?? 0;

		if ( $expiry < time() ) {
			// Block expired, clean it up.
			$this->unblock_ip( $ip );

			return false;
		}

		return true;
	}

	/**
	 * Block an IP address temporarily.
	 *
	 * @param string $ip       IP address to block.
	 * @param int    $duration Duration in seconds (default 600 = 10 minutes).
	 *
	 * @return bool True on success, false on failure.
	 */
	public function block_ip( string $ip, int $duration = 600 ): bool {
		$blocked_list = $this->get_blocked_ips();
		$ip_hash      = $this->hash_ip( $ip );
		$expiry       = time() + $duration;

		$blocked_list[ $ip_hash ] = [
			'ip'         => $ip, // Store for display purposes only.
			'blocked_at' => time(),
			'expiry'     => $expiry,
		];

		return $this->save_blocked_ips( $blocked_list, $duration );
	}

	/**
	 * Unblock an IP address.
	 *
	 * @param string $ip IP address to unblock.
	 *
	 * @return bool True on success, false on failure.
	 */
	public function unblock_ip( string $ip ): bool {
		$blocked_list = $this->get_blocked_ips();
		$ip_hash      = $this->hash_ip( $ip );

		if ( ! isset( $blocked_list[ $ip_hash ] ) ) {
			return false;
		}

		unset( $blocked_list[ $ip_hash ] );

		// Calculate remaining TTL for transient.
		$max_expiry = 0;
		foreach ( $blocked_list as $data ) {
			if ( isset( $data['expiry'] ) && $data['expiry'] > $max_expiry ) {
				$max_expiry = $data['expiry'];
			}
		}

		$ttl = max( 1, $max_expiry - time() );

		return $this->save_blocked_ips( $blocked_list, $ttl );
	}

	/**
	 * Clear all blocked IPs.
	 *
	 * @return bool True on success, false on failure.
	 */
	public function clear_all_blocks(): bool {
		return delete_transient( self::BLOCKED_IPS_KEY );
	}

	/**
	 * Get all blocked IPs.
	 *
	 * @return array Array of blocked IPs with metadata.
	 */
	public function get_blocked_ips(): array {
		$blocked = get_transient( self::BLOCKED_IPS_KEY );

		if ( ! is_array( $blocked ) ) {
			return [];
		}

		// Clean expired entries.
		$now     = time();
		$changed = false;

		foreach ( $blocked as $hash => $data ) {
			if ( ! isset( $data['expiry'] ) || $data['expiry'] <= $now ) {
				unset( $blocked[ $hash ] );
				$changed = true;
			}
		}

		if ( $changed ) {
			if ( empty( $blocked ) ) {
				$this->clear_all_blocks();
			} else {
				// Calculate remaining TTL.
				$max_expiry = 0;
				foreach ( $blocked as $data ) {
					if ( isset( $data['expiry'] ) && $data['expiry'] > $max_expiry ) {
						$max_expiry = $data['expiry'];
					}
				}
				$ttl = max( 1, $max_expiry - $now );
				$this->save_blocked_ips( $blocked, $ttl );
			}
		}

		return $blocked;
	}

	/**
	 * Get the whitelist of IP addresses.
	 *
	 * @return array Array of whitelisted IP addresses and ranges.
	 */
	public function get_whitelist(): array {
		$whitelist = get_option( self::WHITELIST_OPTION, [] );

		if ( ! is_array( $whitelist ) ) {
			return [];
		}

		return $whitelist;
	}

	/**
	 * Add an IP address or range to the whitelist.
	 *
	 * @param string $ip IP address or CIDR range to whitelist.
	 *
	 * @return bool True on success, false on failure.
	 */
	public function add_to_whitelist( string $ip ): bool {
		$ip = trim( $ip );

		if ( empty( $ip ) ) {
			return false;
		}

		// Validate IP or CIDR.
		if ( ! $this->validate_ip_or_range( $ip ) ) {
			return false;
		}

		$whitelist = $this->get_whitelist();

		if ( in_array( $ip, $whitelist, true ) ) {
			return true; // Already whitelisted.
		}

		$whitelist[] = $ip;

		return update_option( self::WHITELIST_OPTION, $whitelist );
	}

	/**
	 * Remove an IP address or range from the whitelist.
	 *
	 * @param string $ip IP address or CIDR range to remove.
	 *
	 * @return bool True on success, false on failure.
	 */
	public function remove_from_whitelist( string $ip ): bool {
		$whitelist = $this->get_whitelist();
		$key       = array_search( $ip, $whitelist, true );

		if ( false === $key ) {
			return false;
		}

		unset( $whitelist[ $key ] );
		$whitelist = array_values( $whitelist ); // Re-index array.

		return update_option( self::WHITELIST_OPTION, $whitelist );
	}

	/**
	 * Clear the entire whitelist.
	 *
	 * @return bool True on success, false on failure.
	 */
	public function clear_whitelist(): bool {
		return delete_option( self::WHITELIST_OPTION );
	}

	/**
	 * Check if an IP is in a list (supports CIDR ranges).
	 *
	 * @param string $ip   IP address to check.
	 * @param array  $list List of IPs and CIDR ranges.
	 *
	 * @return bool True if IP is in list, false otherwise.
	 */
	private function is_ip_in_list( string $ip, array $list ): bool {
		foreach ( $list as $entry ) {
			$entry = trim( $entry );

			// Check for CIDR range.
			if ( str_contains( $entry, '/' ) ) {
				if ( $this->ip_in_range( $ip, $entry ) ) {
					return true;
				}
			} elseif ( $ip === $entry ) {
				// Exact match.
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if an IP is within a CIDR range.
	 *
	 * @param string $ip    IP address to check.
	 * @param string $range CIDR range (e.g., "192.168.1.0/24").
	 *
	 * @return bool True if IP is in range, false otherwise.
	 */
	private function ip_in_range( string $ip, string $range ): bool {
		if ( ! str_contains( $range, '/' ) ) {
			return false;
		}

		list( $subnet, $mask ) = explode( '/', $range, 2 );

		$ip_long     = ip2long( $ip );
		$subnet_long = ip2long( $subnet );
		$mask_long   = -1 << ( 32 - (int) $mask );

		if ( false === $ip_long || false === $subnet_long ) {
			return false;
		}

		return ( $ip_long & $mask_long ) === ( $subnet_long & $mask_long );
	}

	/**
	 * Validate IP address or CIDR range.
	 *
	 * @param string $ip IP address or CIDR range.
	 *
	 * @return bool True if valid, false otherwise.
	 */
	private function validate_ip_or_range( string $ip ): bool {
		// Check for CIDR range.
		if ( str_contains( $ip, '/' ) ) {
			list( $subnet, $mask ) = explode( '/', $ip, 2 );

			if ( ! filter_var( $subnet, FILTER_VALIDATE_IP ) ) {
				return false;
			}

			$mask_int = (int) $mask;

			return $mask_int >= 0 && $mask_int <= 32;
		}

		// Validate single IP.
		return false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Hash an IP address for privacy.
	 *
	 * @param string $ip IP address to hash.
	 *
	 * @return string MD5 hash of IP address.
	 */
	private function hash_ip( string $ip ): string {
		return md5( $ip );
	}

	/**
	 * Save blocked IPs list to transient.
	 *
	 * @param array $blocked_list Array of blocked IPs.
	 * @param int   $ttl          Time to live in seconds.
	 *
	 * @return bool True on success, false on failure.
	 */
	private function save_blocked_ips( array $blocked_list, int $ttl ): bool {
		if ( empty( $blocked_list ) ) {
			return delete_transient( self::BLOCKED_IPS_KEY );
		}

		return set_transient( self::BLOCKED_IPS_KEY, $blocked_list, $ttl );
	}
}
