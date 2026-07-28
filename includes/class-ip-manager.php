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
	 * Only `REMOTE_ADDR` is authoritative. Proxy headers such as
	 * `X-Forwarded-For` or `CF-Connecting-IP` are plain request headers that any
	 * client can set, so they are consulted *only* when the request actually
	 * reaches us from a proxy that has been declared trustworthy.
	 *
	 * Earlier versions read those headers unconditionally and preferred them
	 * over `REMOTE_ADDR`. A single `X-Forwarded-For: 127.0.0.1` therefore made
	 * this method report a whitelisted address, which disabled both the
	 * wp-login.php block and the brute-force protection, and allowed an attacker
	 * to get somebody else's address blocked.
	 *
	 * Trusted proxies are opt-in via the `JPKCOM_HIDE_LOGIN_TRUSTED_PROXIES`
	 * constant or the `jpkcom_hide_login_trusted_proxies` filter; with no
	 * configuration nothing but `REMOTE_ADDR` is believed.
	 *
	 * @since 1.2.5 Proxy headers require a trusted proxy.
	 *
	 * @return string IP address or 'unknown' if not available.
	 */
	public function get_current_ip(): string {
		$remote = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';

		if ( false === filter_var( $remote, FILTER_VALIDATE_IP ) ) {
			return 'unknown';
		}

		$trusted = $this->get_trusted_proxies();

		if ( empty( $trusted ) || ! $this->is_ip_in_list( $remote, $trusted ) ) {
			return $remote;
		}

		// Cloudflare sets this to the originating client and overwrites anything
		// the client sent, so it is a single trustworthy value behind CF.
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$candidate = trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) );

			if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				return $candidate;
			}
		}

		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$forwarded = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );

			// The chain is client, proxy1, proxy2 ... - only the entries appended
			// by our own trusted proxies can be believed. Walk from the right and
			// stop at the first address that is not itself a trusted proxy; the
			// left-hand entries are attacker-supplied.
			$chain = array_reverse( array_map( 'trim', explode( ',', $forwarded ) ) );

			foreach ( $chain as $candidate ) {
				if ( false === filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
					break;
				}

				if ( ! $this->is_ip_in_list( $candidate, $trusted ) ) {
					return $candidate;
				}
			}
		}

		if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
			$candidate = trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ) );

			if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				return $candidate;
			}
		}

		return $remote;
	}

	/**
	 * Get the list of proxies whose forwarding headers may be believed.
	 *
	 * Empty by default: without an explicit declaration no proxy header is
	 * trusted, which is the safe behaviour for a site that is reached directly.
	 *
	 * Configure via `define( 'JPKCOM_HIDE_LOGIN_TRUSTED_PROXIES', '173.245.48.0/20, 2400:cb00::/32' );`
	 * or the `jpkcom_hide_login_trusted_proxies` filter. Entries may be single
	 * addresses or CIDR ranges, IPv4 or IPv6.
	 *
	 * @since 1.2.5
	 *
	 * @return array List of IP addresses / CIDR ranges.
	 */
	public function get_trusted_proxies(): array {
		$proxies = [];

		if ( defined( 'JPKCOM_HIDE_LOGIN_TRUSTED_PROXIES' ) ) {
			$configured = constant( 'JPKCOM_HIDE_LOGIN_TRUSTED_PROXIES' );

			if ( is_string( $configured ) ) {
				$configured = explode( ',', $configured );
			}

			if ( is_array( $configured ) ) {
				$proxies = $configured;
			}
		}

		/**
		 * Filters the proxies whose forwarding headers are trusted.
		 *
		 * @since 1.2.5
		 *
		 * @param array $proxies List of IP addresses / CIDR ranges.
		 */
		$proxies = apply_filters( 'jpkcom_hide_login_trusted_proxies', $proxies );

		if ( ! is_array( $proxies ) ) {
			return [];
		}

		$clean = [];

		foreach ( $proxies as $entry ) {
			$entry = trim( (string) $entry );

			if ( '' !== $entry && $this->validate_ip_or_range( $entry ) ) {
				$clean[] = $entry;
			}
		}

		return $clean;
	}

	/**
	 * Whether an address looks like a proxy or gateway rather than a visitor.
	 *
	 * If every request appears to come from a loopback, private, link-local or
	 * CGNAT address, the site is sitting behind something - a reverse proxy, a
	 * CDN, a container router, a load balancer - and `REMOTE_ADDR` is that hop,
	 * not the visitor. Two things follow, both bad and both silent:
	 *
	 * - All visitors share one address, so five failed logins from anywhere lock
	 *   out everybody.
	 * - If that address happens to be 127.0.0.1, ::1 or SERVER_ADDR, it is on the
	 *   built-in whitelist, and both the wp-login.php block and the brute-force
	 *   protection are effectively switched off for the entire internet.
	 *
	 * The cure is to declare the proxy via `JPKCOM_HIDE_LOGIN_TRUSTED_PROXIES`
	 * so the forwarded headers may be believed. This method exists so the admin
	 * screen can point that out instead of leaving it to be discovered.
	 *
	 * @since 1.2.7
	 *
	 * @param string $ip IP address to classify.
	 *
	 * @return bool True if the address cannot be a public visitor address.
	 */
	public function looks_like_proxy_address( string $ip ): bool {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		// Public addresses are what a directly reached site sees.
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return false;
		}

		return true;
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

		$mask = trim( $mask );

		if ( '' === $mask || ! ctype_digit( $mask ) ) {
			return false;
		}

		// inet_pton handles both families and yields a fixed-width binary string:
		// 4 bytes for IPv4, 16 for IPv6. The previous ip2long() implementation
		// returned false for every IPv6 address, so IPv6 CIDR entries silently
		// never matched even though the admin UI accepted them.
		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( trim( $subnet ) );

		if ( false === $ip_bin || false === $subnet_bin ) {
			return false;
		}

		// Never compare an IPv4 address against an IPv6 range or vice versa.
		if ( strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$bits = (int) $mask;
		$max  = strlen( $ip_bin ) * 8;

		if ( $bits > $max ) {
			return false;
		}

		if ( 0 === $bits ) {
			return true; // ::/0 and 0.0.0.0/0 match everything.
		}

		$full_bytes = intdiv( $bits, 8 );
		$rest_bits  = $bits % 8;

		if ( $full_bytes > 0 && substr( $ip_bin, 0, $full_bytes ) !== substr( $subnet_bin, 0, $full_bytes ) ) {
			return false;
		}

		if ( 0 === $rest_bits ) {
			return true;
		}

		$byte_mask = chr( ( 0xFF << ( 8 - $rest_bits ) ) & 0xFF );

		return ( $ip_bin[ $full_bytes ] & $byte_mask ) === ( $subnet_bin[ $full_bytes ] & $byte_mask );
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

			$subnet = trim( $subnet );
			$mask   = trim( $mask );

			if ( ! filter_var( $subnet, FILTER_VALIDATE_IP ) ) {
				return false;
			}

			if ( '' === $mask || ! ctype_digit( $mask ) ) {
				return false;
			}

			// The prefix ceiling depends on the family: /32 is a single host in
			// IPv4 but a very large block in IPv6. Accepting up to /32 for both,
			// as before, let the UI store IPv6 ranges that could never match.
			$is_v6    = false !== filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
			$max_bits = $is_v6 ? 128 : 32;
			$mask_int = (int) $mask;

			return $mask_int >= 0 && $mask_int <= $max_bits;
		}

		// Validate single IP.
		return false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Derive a stable, non-guessable key for an IP address.
	 *
	 * Note what this does and does not achieve: the block list stores the plain
	 * address alongside the key so the admin screen can display it, so this is
	 * not anonymisation. What the site salt does buy is that the key cannot be
	 * recomputed without it - a plain `md5( $ip )` is reversible for IPv4 by
	 * walking all 2^32 addresses in seconds, which makes it useless as a
	 * privacy measure and as an unguessable identifier alike.
	 *
	 * @since 1.2.5 Salted HMAC instead of a bare MD5.
	 *
	 * @param string $ip IP address to hash.
	 *
	 * @return string Keyed hash of the IP address.
	 */
	private function hash_ip( string $ip ): string {
		return hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) );
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
