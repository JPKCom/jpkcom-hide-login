<?php
/**
 * Mask Login Class
 *
 * Handles the masking of the WordPress login URL by replacing
 * wp-login.php with a custom slug.
 *
 * @package JPKCom_Hide_Login
 * @since 1.0.0
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class JPKCom_Hide_Login_Mask_Login
 *
 * Manages the login URL masking functionality.
 */
class JPKCom_Hide_Login_Mask_Login {

	/**
	 * IP Manager instance.
	 *
	 * @var JPKCom_Hide_Login_IP_Manager
	 */
	private JPKCom_Hide_Login_IP_Manager $ip_manager;

	/**
	 * Custom login slug.
	 *
	 * @var string
	 */
	private string $custom_slug;

	/**
	 * Constructor.
	 *
	 * @param JPKCom_Hide_Login_IP_Manager $ip_manager   IP Manager instance.
	 * @param string                       $custom_slug  Custom login slug.
	 */
	public function __construct( JPKCom_Hide_Login_IP_Manager $ip_manager, string $custom_slug ) {
		$this->ip_manager  = $ip_manager;
		$this->custom_slug = $custom_slug;
	}

	/**
	 * Initialize hooks for mask login functionality.
	 *
	 * @return void
	 */
	public function init_hooks(): void {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[JPKCom Hide Login] Mask_Login init_hooks called. Custom slug: ' . $this->custom_slug );
		}

		// Handle login requests early.
		add_action( 'init', [ $this, 'handle_login_request' ], 1 );

		// Filter redirects to replace wp-login.php URLs.
		add_filter( 'wp_redirect', [ $this, 'filter_wp_redirect' ], 10, 2 );

		// Filter URLs to use custom slug.
		add_filter( 'login_url', [ $this, 'filter_login_url' ], 10, 3 );
		add_filter( 'logout_url', [ $this, 'filter_logout_url' ], 10, 2 );
		add_filter( 'lostpassword_url', [ $this, 'filter_lostpassword_url' ], 10, 2 );
		add_filter( 'register_url', [ $this, 'filter_register_url' ], 10 );
		add_filter( 'logout_redirect', [ $this, 'filter_logout_redirect' ], 10, 3 );

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[JPKCom Hide Login] All filters registered' );
		}

		// Filter site_url and network_site_url for wp-login.php references.
		add_filter( 'site_url', [ $this, 'filter_site_url' ], 100, 3 );
		add_filter( 'network_site_url', [ $this, 'filter_network_site_url' ], 100, 3 );

		// Handle password reset links.
		add_action( 'login_form_rp', [ $this, 'handle_password_reset' ], 1 );
		add_action( 'login_form_resetpass', [ $this, 'handle_password_reset' ], 1 );

		// Multisite signup support.
		if ( is_multisite() ) {
			add_filter( 'wp_signup_location', [ $this, 'filter_signup_url' ], 10 );
		}

		// WooCommerce compatibility.
		if ( class_exists( 'WooCommerce' ) ) {
			add_filter( 'woocommerce_logout_default_redirect_url', [ $this, 'filter_woocommerce_logout' ], 10 );
		}

		// Prevent admin redirect for non-logged-in users.
		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
	}

	/**
	 * Handle login requests and block unauthorized access.
	 *
	 * @return void
	 */
	public function handle_login_request(): void {
		// Skip for AJAX and REST API requests.
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return;
		}

		// Skip for WooCommerce AJAX.
		if ( ! empty( $_GET['wc-ajax'] ) ) {
			return;
		}

		$request_uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$request_path = trim( (string) wp_parse_url( $request_uri, PHP_URL_PATH ), '/' );
		$ip           = $this->ip_manager->get_current_ip();

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[JPKCom Hide Login] handle_login_request - Request path: ' . $request_path . ' | Custom slug: ' . $this->custom_slug );
		}

		// Serve login page if custom slug is accessed.
		if ( $request_path === $this->custom_slug ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[JPKCom Hide Login] Serving login page for: ' . $request_path );
			}
			$this->serve_login_page();
		}

		// Block access to wp-admin for non-logged-in users (except admin-ajax.php).
		if ( ! is_user_logged_in() && str_contains( $request_path, 'wp-admin' ) ) {
			if ( str_contains( $request_uri, 'admin-ajax.php' ) ) {
				return;
			}

			$this->show_404();
		}

		// Block direct access to wp-login.php.
		if ( str_contains( $request_path, 'wp-login.php' ) ) {
			// Check if IP is whitelisted.
			if ( $this->ip_manager->is_ip_whitelisted( $ip ) ) {
				return;
			}

			$this->show_404();
		}

		// Block access to wp-signup.php for Multisite.
		if ( is_multisite() && str_contains( $request_path, 'wp-signup.php' ) ) {
			if ( $this->ip_manager->is_ip_whitelisted( $ip ) ) {
				return;
			}

			$this->show_404();
		}
	}

	/**
	 * Serve the WordPress login page via custom slug.
	 *
	 * @return void
	 */
	private function serve_login_page(): void {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[JPKCom Hide Login] serve_login_page called' );
		}

		// Handle Multisite signup requests.
		if ( is_multisite() && isset( $_GET['action'] ) && 'signup' === $_GET['action'] ) {
			$GLOBALS['pagenow'] = 'wp-signup.php';
			require_once ABSPATH . 'wp-signup.php';
			exit;
		}

		// Declare globals that wp-login.php expects.
		global $error, $interim_login, $action, $user_login, $user, $redirect_to;

		// Tell WordPress we're on the login page.
		$GLOBALS['pagenow'] = 'wp-login.php';

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[JPKCom Hide Login] Set $GLOBALS[pagenow] = wp-login.php' );
			error_log( '[JPKCom Hide Login] Current REQUEST_URI: ' . ( $_SERVER['REQUEST_URI'] ?? 'none' ) );
			error_log( '[JPKCom Hide Login] GET params: ' . print_r( $_GET, true ) );
		}

		// CRITICAL: Do NOT modify $_SERVER variables!
		// The form needs to POST to the current REQUEST_URI (our custom slug),
		// not to wp-login.php. Only $GLOBALS['pagenow'] is needed.

		// Include wp-login.php.
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Show 404 error page.
	 *
	 * @return void
	 */
	private function show_404(): void {
		status_header( 404 );
		nocache_headers();

		wp_die(
			esc_html__( 'Page not found.', 'jpkcom-hide-login' ),
			esc_html__( '404 Not Found', 'jpkcom-hide-login' ),
			[ 'response' => 404 ]
		);
	}

	/**
	 * Filter login_url to use custom slug.
	 *
	 * @param string $login_url    Original login URL.
	 * @param string $redirect     Redirect URL after login.
	 * @param bool   $force_reauth Whether to force re-authentication.
	 *
	 * @return string Modified login URL.
	 */
	public function filter_login_url( string $login_url, string $redirect = '', bool $force_reauth = false ): string {
		// Check if URL already contains our custom slug - if so, don't modify.
		if ( str_contains( $login_url, $this->custom_slug ) ) {
			return $login_url;
		}

		// Only filter if URL contains wp-login.php.
		if ( ! str_contains( $login_url, 'wp-login.php' ) ) {
			return $login_url;
		}

		$custom_url = home_url( '/' . $this->custom_slug . '/' );

		// Preserve query parameters.
		$parsed_url = wp_parse_url( $login_url );

		if ( ! empty( $parsed_url['query'] ) ) {
			parse_str( $parsed_url['query'], $query_args );
			$custom_url = add_query_arg( $query_args, $custom_url );
		}

		// Add redirect parameter.
		if ( ! empty( $redirect ) ) {
			$custom_url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $custom_url );
		}

		// Add reauth parameter.
		if ( $force_reauth ) {
			$custom_url = add_query_arg( 'reauth', '1', $custom_url );
		}

		return $custom_url;
	}

	/**
	 * Filter logout_url to use custom slug.
	 *
	 * @param string $logout_url Original logout URL.
	 * @param string $redirect   Redirect URL after logout.
	 *
	 * @return string Modified logout URL.
	 */
	public function filter_logout_url( string $logout_url, string $redirect = '' ): string {
		// Check if URL already contains our custom slug - if so, don't modify.
		if ( str_contains( $logout_url, $this->custom_slug ) ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[JPKCom Hide Login] logout_url already contains custom slug: ' . $logout_url );
			}
			return $logout_url;
		}

		// Only filter if URL contains wp-login.php.
		if ( ! str_contains( $logout_url, 'wp-login.php' ) ) {
			return $logout_url;
		}

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[JPKCom Hide Login] Filtering logout_url: ' . $logout_url );
		}

		$custom_url = home_url( '/' . $this->custom_slug . '/' );

		// Preserve query parameters (action=logout, _wpnonce, etc.).
		$parsed_url = wp_parse_url( $logout_url );

		if ( ! empty( $parsed_url['query'] ) ) {
			parse_str( $parsed_url['query'], $query_args );
			$custom_url = add_query_arg( $query_args, $custom_url );
		}

		// Add redirect parameter.
		if ( ! empty( $redirect ) ) {
			$custom_url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $custom_url );
		}

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[JPKCom Hide Login] New logout_url: ' . $custom_url );
		}

		return $custom_url;
	}

	/**
	 * Filter lostpassword_url to use custom slug.
	 *
	 * @param string $lostpassword_url Original lost password URL.
	 * @param string $redirect         Redirect URL after password reset.
	 *
	 * @return string Modified lost password URL.
	 */
	public function filter_lostpassword_url( string $lostpassword_url, string $redirect = '' ): string {
		$custom_url = home_url( '/' . $this->custom_slug . '/?action=lostpassword' );

		if ( ! empty( $redirect ) ) {
			$custom_url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $custom_url );
		}

		return $custom_url;
	}

	/**
	 * Filter register_url to use custom slug.
	 *
	 * @param string $register_url Original registration URL.
	 *
	 * @return string Modified registration URL.
	 */
	public function filter_register_url( string $register_url ): string {
		return home_url( '/' . $this->custom_slug . '/?action=register' );
	}

	/**
	 * Filter logout redirect to use custom login page.
	 *
	 * @param string         $redirect_to           Redirect URL.
	 * @param string         $requested_redirect_to Requested redirect URL.
	 * @param \WP_User|mixed $user                  User object.
	 *
	 * @return string Modified redirect URL.
	 */
	public function filter_logout_redirect( string $redirect_to, string $requested_redirect_to, $user ): string {
		if ( empty( $requested_redirect_to ) || str_contains( $redirect_to, 'wp-login.php' ) ) {
			return home_url( '/' . $this->custom_slug . '/?loggedout=true' );
		}

		return $redirect_to;
	}

	/**
	 * Filter wp_redirect to replace wp-login.php URLs.
	 *
	 * This is critical for making login work correctly. When WordPress
	 * processes a login and wants to redirect, it may try to redirect
	 * to wp-login.php with various parameters. We need to intercept
	 * these redirects and replace wp-login.php with our custom slug.
	 *
	 * @param string $location Redirect location URL.
	 * @param int    $status   HTTP status code.
	 *
	 * @return string Modified redirect URL.
	 */
	public function filter_wp_redirect( string $location, int $status ): string {
		// Log for debugging.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[JPKCom Hide Login] wp_redirect called with location: ' . $location );
			error_log( '[JPKCom Hide Login] is_serving_login_page: ' . ( $this->is_serving_login_page() ? 'yes' : 'no' ) );
		}

		// IMPORTANT: We must filter redirects even when serving login page.
		// After login processing, WordPress may redirect to wp-login.php with error messages.
		// We need to replace those URLs with our custom slug.

		// If URL contains wp-login.php, replace it with custom slug.
		if ( str_contains( $location, 'wp-login.php' ) ) {
			// Parse the URL to extract query parameters.
			$parsed_url = wp_parse_url( $location );
			$query_params = [];

			if ( ! empty( $parsed_url['query'] ) ) {
				parse_str( $parsed_url['query'], $query_params );
			}

			// Build new URL with custom slug.
			$new_location = home_url( '/' . $this->custom_slug . '/' );

			// Add query parameters if any exist.
			if ( ! empty( $query_params ) ) {
				$new_location = add_query_arg( $query_params, $new_location );
			}

			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[JPKCom Hide Login] Replacing with: ' . $new_location );
			}

			return $new_location;
		}

		return $location;
	}

	/**
	 * Filter site_url for wp-login.php references.
	 *
	 * @param string      $url    Complete site URL.
	 * @param string      $path   Path relative to site URL.
	 * @param string|null $scheme URL scheme.
	 *
	 * @return string Modified URL.
	 */
	public function filter_site_url( string $url, string $path, ?string $scheme ): string {
		// IMPORTANT: We MUST filter site_url even when serving login page!
		// wp-login.php uses site_url() to build the form action attribute,
		// so we need to replace wp-login.php with our custom slug.

		if ( str_contains( $path, 'wp-login.php' ) ) {
			// Split path and query if path contains query string.
			$path_parts = explode( '?', $path, 2 );
			$clean_path = $path_parts[0];
			$path_query = isset( $path_parts[1] ) ? $path_parts[1] : '';

			// Replace wp-login.php in path only.
			$new_path = str_replace( 'wp-login.php', $this->custom_slug . '/', $clean_path );
			$url      = home_url( $new_path, $scheme );

			// Add query parameters (prefer path query over parsed URL query to avoid duplicates).
			if ( ! empty( $path_query ) ) {
				$url = add_query_arg( wp_parse_args( $path_query ), $url );
			} elseif ( ! empty( wp_parse_url( $url, PHP_URL_QUERY ) ) ) {
				// Only add parsed query if path didn't have one.
				$parsed_query = wp_parse_url( $url, PHP_URL_QUERY );
				parse_str( $parsed_query, $query_args );
				$url = add_query_arg( $query_args, home_url( $new_path, $scheme ) );
			}
		}

		// Handle wp-signup.php for Multisite.
		if ( is_multisite() && str_contains( $path, 'wp-signup.php' ) ) {
			$parsed_url = wp_parse_url( $url );
			$new_path   = str_replace( 'wp-signup.php', $this->custom_slug . '/', $path );
			$url        = home_url( $new_path, $scheme );

			$query_args = [ 'action' => 'signup' ];

			if ( ! empty( $parsed_url['query'] ) ) {
				parse_str( $parsed_url['query'], $existing_args );
				$query_args = array_merge( $query_args, $existing_args );
			}

			$url = add_query_arg( $query_args, $url );
		}

		return $url;
	}

	/**
	 * Filter network_site_url for Multisite.
	 *
	 * @param string      $url    Complete network site URL.
	 * @param string      $path   Path relative to network site URL.
	 * @param string|null $scheme URL scheme.
	 *
	 * @return string Modified URL.
	 */
	public function filter_network_site_url( string $url, string $path, ?string $scheme ): string {
		if ( ! is_multisite() ) {
			return $url;
		}

		// IMPORTANT: Filter even when serving login page (same reason as filter_site_url)

		if ( str_contains( $path, 'wp-login.php' ) ) {
			// Split path and query if path contains query string (same fix as filter_site_url).
			$path_parts = explode( '?', $path, 2 );
			$clean_path = $path_parts[0];
			$path_query = isset( $path_parts[1] ) ? $path_parts[1] : '';

			// Replace wp-login.php in path only.
			$new_path = str_replace( 'wp-login.php', $this->custom_slug . '/', $clean_path );
			$url      = network_home_url( $new_path, $scheme );

			// Add query parameters (prefer path query to avoid duplicates).
			if ( ! empty( $path_query ) ) {
				$url = add_query_arg( wp_parse_args( $path_query ), $url );
			} elseif ( ! empty( wp_parse_url( $url, PHP_URL_QUERY ) ) ) {
				$parsed_query = wp_parse_url( $url, PHP_URL_QUERY );
				parse_str( $parsed_query, $query_args );
				$url = add_query_arg( $query_args, network_home_url( $new_path, $scheme ) );
			}
		}

		if ( str_contains( $path, 'wp-signup.php' ) ) {
			$parsed_url = wp_parse_url( $url );
			$new_path   = str_replace( 'wp-signup.php', $this->custom_slug . '/', $path );
			$url        = network_home_url( $new_path, $scheme );

			$query_args = [ 'action' => 'signup' ];

			if ( ! empty( $parsed_url['query'] ) ) {
				parse_str( $parsed_url['query'], $existing_args );
				$query_args = array_merge( $query_args, $existing_args );
			}

			$url = add_query_arg( $query_args, $url );
		}

		return $url;
	}

	/**
	 * Handle password reset links from emails.
	 *
	 * @return void
	 */
	public function handle_password_reset(): void {
		$request_uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$request_path = trim( (string) wp_parse_url( $request_uri, PHP_URL_PATH ), '/' );

		if ( str_contains( $request_path, 'wp-login.php' ) ) {
			$redirect_url = home_url( '/' . $this->custom_slug . '/' );

			if ( ! empty( $_GET ) ) {
				$redirect_url = add_query_arg( $_GET, $redirect_url );
			}

			wp_safe_redirect( $redirect_url );
			exit;
		}
	}

	/**
	 * Filter signup URL for Multisite.
	 *
	 * @param string $url Signup URL.
	 *
	 * @return string Modified signup URL.
	 */
	public function filter_signup_url( string $url ): string {
		if ( str_contains( $url, 'wp-signup.php' ) ) {
			$parsed_url = wp_parse_url( $url );
			$new_url    = home_url( '/' . $this->custom_slug . '/?action=signup' );

			if ( ! empty( $parsed_url['query'] ) ) {
				parse_str( $parsed_url['query'], $query_args );
				$new_url = add_query_arg( $query_args, $new_url );
			}

			return $new_url;
		}

		return $url;
	}

	/**
	 * Filter WooCommerce logout redirect.
	 *
	 * @param string $redirect_url Original redirect URL.
	 *
	 * @return string Modified redirect URL.
	 */
	public function filter_woocommerce_logout( string $redirect_url ): string {
		if ( str_contains( $redirect_url, 'wp-login.php' ) ) {
			return home_url( '/' . $this->custom_slug . '/' );
		}

		return $redirect_url;
	}

	/**
	 * Check if we're currently serving the login page.
	 *
	 * @return bool True if serving login page, false otherwise.
	 */
	private function is_serving_login_page(): bool {
		return isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'];
	}

	/**
	 * Get the custom login URL.
	 *
	 * @return string Custom login URL.
	 */
	public function get_login_url(): string {
		return home_url( '/' . $this->custom_slug . '/' );
	}

	/**
	 * Get the custom login slug.
	 *
	 * @return string Custom login slug.
	 */
	public function get_custom_slug(): string {
		return $this->custom_slug;
	}

	/**
	 * Set a new custom slug.
	 *
	 * @param string $slug New custom slug.
	 *
	 * @return void
	 */
	public function set_custom_slug( string $slug ): void {
		$this->custom_slug = sanitize_title_with_dashes( $slug );
	}
}
