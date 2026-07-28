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
	 * Whether the current request is the masked login page itself.
	 *
	 * Gates whether redirects may reveal the custom slug.
	 *
	 * @since 1.2.5
	 *
	 * @var bool
	 */
	private bool $is_custom_login_request = false;

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
		jpkcom_hide_login_log( 'Mask_Login init_hooks called. Custom slug: ' . $this->custom_slug );

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

		jpkcom_hide_login_log( 'All filters registered' );

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
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Routing decision on a public request; nothing is read or written.
		if ( ! empty( $_GET['wc-ajax'] ) ) {
			return;
		}

		$request_path = $this->get_request_path();
		$segments     = '' === $request_path ? [] : explode( '/', $request_path );
		$script_path  = $this->get_script_path();
		$script       = basename( $script_path );
		$ip           = $this->ip_manager->get_current_ip();

		jpkcom_hide_login_log( 'handle_login_request - Request path: ' . $request_path . ' | Script: ' . $script_path . ' | Custom slug: ' . $this->custom_slug );

		// Serve login page if custom slug is accessed.
		if ( $request_path === $this->custom_slug ) {
			jpkcom_hide_login_log( 'Serving login page for: ' . $request_path );
			$this->is_custom_login_request = true;
			$this->serve_login_page();
		}

		// admin-ajax.php must stay reachable for logged-out users.
		if ( 'admin-ajax.php' === $script ) {
			return;
		}

		// Block access to wp-admin for non-logged-in users.
		// Matching the first path segment rather than searching the whole path:
		// a substring test also caught legitimate content such as
		// /my-wp-admin-guide/ and 404'd it for every visitor.
		$in_wp_admin = ( ( $segments[0] ?? '' ) === 'wp-admin' ) || str_starts_with( $script_path, 'wp-admin/' );

		if ( ! is_user_logged_in() && $in_wp_admin ) {
			$this->show_404();
		}

		// Block direct access to wp-login.php.
		if ( $this->targets_script( 'wp-login.php', $script, $segments ) ) {
			// Check if IP is whitelisted.
			if ( $this->ip_manager->is_ip_whitelisted( $ip ) ) {
				return;
			}

			$this->show_404();
		}

		// Block direct access to wp-signup.php.
		//
		// Deliberately not limited to Multisite. On a single site wp-signup.php
		// answers with `wp_redirect( wp_registration_url() )`, and because
		// filter_register_url() rewrites that to the custom slug, one anonymous
		// request to /wp-signup.php handed the secret slug straight back in the
		// Location header - the very disclosure filter_wp_redirect() guards
		// against. The page has no purpose outside Multisite anyway, and on
		// Multisite signup is reached through the masked slug with
		// ?action=signup.
		if ( $this->targets_script( 'wp-signup.php', $script, $segments ) ) {
			if ( $this->ip_manager->is_ip_whitelisted( $ip ) ) {
				return;
			}

			$this->show_404();
		}
	}

	/**
	 * Normalised path of the current request, without query string.
	 *
	 * Deliberately avoids `wp_parse_url()`: for an input like `//wp-login.php`
	 * that function reads `wp-login.php` as the *host* and returns an empty
	 * path, which is precisely how the previous block was bypassed. The path is
	 * also percent-decoded and collapsed, so `/wp-%6cogin.php` and
	 * `//wp-login.php` resolve to the same string the web server resolved.
	 *
	 * @since 1.2.5
	 *
	 * @return string Normalised path without leading/trailing slashes.
	 */
	private function get_request_path(): string {
		// Deliberately not sanitize_text_field(): this value is compared against
		// core script names, and stripping characters before that comparison is
		// exactly how the `//wp-login.php` and `/wp-%6cogin.php` bypasses worked.
		// It is normalised below and never echoed.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

		foreach ( [ '?', '#' ] as $cut ) {
			$pos = strpos( $uri, $cut );

			if ( false !== $pos ) {
				$uri = substr( $uri, 0, $pos );
			}
		}

		$uri = rawurldecode( $uri );
		$uri = (string) preg_replace( '#/+#', '/', $uri );

		return trim( $uri, '/' );
	}

	/**
	 * Path of the script the web server actually resolved and is executing.
	 *
	 * This is the authoritative signal: whatever encoding or slash trickery the
	 * request URI contains, `SCRIPT_NAME` reflects the file PHP is running. For
	 * a pretty permalink it is `index.php`, so ordinary pages never match.
	 *
	 * @since 1.2.5
	 *
	 * @return string Script path without a leading slash.
	 */
	private function get_script_path(): string {
		// See get_request_path(): compared, normalised, never output.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ) : '';
		$script = (string) preg_replace( '#/+#', '/', $script );

		return ltrim( $script, '/' );
	}

	/**
	 * Whether the request targets a given core script.
	 *
	 * Checks the executing script first, then falls back to an exact path
	 * segment match so setups that route the file through a rewrite are still
	 * caught. A segment comparison avoids matching a page whose slug merely
	 * contains the file name.
	 *
	 * @since 1.2.5
	 *
	 * @param string $file     Script file name, e.g. 'wp-login.php'.
	 * @param string $script   Base name of the executing script.
	 * @param array  $segments Segments of the normalised request path.
	 *
	 * @return bool True if the request targets the script.
	 */
	private function targets_script( string $file, string $script, array $segments ): bool {
		return $file === $script || in_array( $file, $segments, true );
	}

	/**
	 * Serve the WordPress login page via custom slug.
	 *
	 * @return void
	 */
	private function serve_login_page(): void {
		jpkcom_hide_login_log( 'serve_login_page called' );

		// Handle Multisite signup requests.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public login page routing; wp-signup.php does its own nonce handling.
		if ( is_multisite() && isset( $_GET['action'] ) && 'signup' === sanitize_key( wp_unslash( $_GET['action'] ) ) ) {
			$GLOBALS['pagenow'] = 'wp-signup.php';
			require_once ABSPATH . 'wp-signup.php';
			exit;
		}

		// Declare globals that wp-login.php expects.
		global $error, $interim_login, $action, $user_login, $user, $redirect_to;

		// Tell WordPress we're on the login page.
		$GLOBALS['pagenow'] = 'wp-login.php';

		// The former dump of REQUEST_URI and the whole $_GET array is gone on
		// purpose: it wrote every login attempt's query string - including
		// password-reset keys - into the error log.
		jpkcom_hide_login_log( 'Set $GLOBALS[pagenow] = wp-login.php' );

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
	 * The arguments are untyped on purpose: `login_url` is a public filter and
	 * callers pass null for "no redirect" often enough that a `string $redirect`
	 * signature is a fatal waiting to happen. Same reasoning as
	 * JPKCom_Hide_Login_Login_Protection::handle_failed_login().
	 *
	 * @since 1.2.7 Tolerates null arguments from third-party callers.
	 *
	 * @param string $login_url    Original login URL.
	 * @param mixed  $redirect     Redirect URL after login.
	 * @param mixed  $force_reauth Whether to force re-authentication.
	 *
	 * @return string Modified login URL.
	 */
	public function filter_login_url( string $login_url, mixed $redirect = '', mixed $force_reauth = false ): string {
		$redirect     = is_string( $redirect ) ? $redirect : '';
		$force_reauth = (bool) $force_reauth;

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
	 * @since 1.2.7 Tolerates a null redirect.
	 *
	 * @param string $logout_url Original logout URL.
	 * @param mixed  $redirect   Redirect URL after logout.
	 *
	 * @return string Modified logout URL.
	 */
	public function filter_logout_url( string $logout_url, mixed $redirect = '' ): string {
		$redirect = is_string( $redirect ) ? $redirect : '';

		// Check if URL already contains our custom slug - if so, don't modify.
		if ( str_contains( $logout_url, $this->custom_slug ) ) {
			jpkcom_hide_login_log( 'logout_url already contains custom slug: ' . $logout_url );
			return $logout_url;
		}

		// Only filter if URL contains wp-login.php.
		if ( ! str_contains( $logout_url, 'wp-login.php' ) ) {
			return $logout_url;
		}

		jpkcom_hide_login_log( 'Filtering logout_url: ' . $logout_url );

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

		jpkcom_hide_login_log( 'New logout_url: ' . $custom_url );

		return $custom_url;
	}

	/**
	 * Filter lostpassword_url to use custom slug.
	 *
	 * @since 1.2.7 Tolerates a null redirect.
	 *
	 * @param string $lostpassword_url Original lost password URL.
	 * @param mixed  $redirect         Redirect URL after password reset.
	 *
	 * @return string Modified lost password URL.
	 */
	public function filter_lostpassword_url( string $lostpassword_url, mixed $redirect = '' ): string {
		$redirect   = is_string( $redirect ) ? $redirect : '';
		$custom_url = home_url( '/' . $this->custom_slug . '/?action=lostpassword' );

		if ( ! empty( $redirect ) ) {
			$custom_url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $custom_url );
		}

		return $custom_url;
	}

	/**
	 * Filter register_url to use custom slug.
	 *
	 * @param mixed $register_url Original registration URL.
	 *
	 * @return string Modified registration URL.
	 */
	public function filter_register_url( mixed $register_url = '' ): string {
		return home_url( '/' . $this->custom_slug . '/?action=register' );
	}

	/**
	 * Filter logout redirect to use custom login page.
	 *
	 * @param mixed $redirect_to           Redirect URL.
	 * @param mixed $requested_redirect_to Requested redirect URL.
	 * @param mixed $user                  User object.
	 *
	 * @return string Modified redirect URL.
	 */
	public function filter_logout_redirect( mixed $redirect_to = '', mixed $requested_redirect_to = '', mixed $user = null ): string {
		$redirect_to           = is_string( $redirect_to ) ? $redirect_to : '';
		$requested_redirect_to = is_string( $requested_redirect_to ) ? $requested_redirect_to : '';

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
		jpkcom_hide_login_log( 'wp_redirect called with location: ' . $location );
		jpkcom_hide_login_log( 'is_serving_login_page: ' . ( $this->is_serving_login_page() ? 'yes' : 'no' ) );

		// IMPORTANT: We must filter redirects even when serving login page.
		// After login processing, WordPress may redirect to wp-login.php with error messages.
		// We need to replace those URLs with our custom slug.

		// If URL contains wp-login.php, replace it with custom slug.
		if ( str_contains( $location, 'wp-login.php' ) ) {
			// Only reveal the slug where it is actually needed: while we are
			// serving the masked login page, or to an already authenticated
			// request. Otherwise an unauthenticated probe that provokes a
			// redirect to wp-login.php would get the secret slug handed to it in
			// the Location header, which defeats the masking entirely.
			if ( ! $this->is_custom_login_request && ! is_user_logged_in() ) {
				jpkcom_hide_login_log( 'Not rewriting redirect for anonymous request - would disclose the slug' );

				return $location;
			}

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

			jpkcom_hide_login_log( 'Replacing with: ' . $new_location );

			return $new_location;
		}

		return $location;
	}

	/**
	 * Filter site_url for wp-login.php references.
	 *
	 * @param string $url    Complete site URL.
	 * @param mixed  $path   Path relative to site URL.
	 * @param mixed  $scheme URL scheme.
	 *
	 * @return string Modified URL.
	 */
	public function filter_site_url( string $url, mixed $path = '', mixed $scheme = null ): string {
		$path   = is_string( $path ) ? $path : '';
		$scheme = is_string( $scheme ) ? $scheme : null;

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
	 * @param string $url    Complete network site URL.
	 * @param mixed  $path   Path relative to network site URL.
	 * @param mixed  $scheme URL scheme.
	 *
	 * @return string Modified URL.
	 */
	public function filter_network_site_url( string $url, mixed $path = '', mixed $scheme = null ): string {
		$path   = is_string( $path ) ? $path : '';
		$scheme = is_string( $scheme ) ? $scheme : null;

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
		$request_path = $this->get_request_path();

		if ( ! in_array( 'wp-login.php', explode( '/', $request_path ), true ) ) {
			return;
		}

		$redirect_url = home_url( '/' . $this->custom_slug . '/' );

		// The reset link carries `login`, `key` and `action`; they are handed
		// straight back to the masked login page, so sanitise rather than trust.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- A password reset link is its own credential; wp-login.php validates the key.
		$args = array_map( 'sanitize_text_field', wp_unslash( $_GET ) );

		if ( ! empty( $args ) ) {
			$redirect_url = add_query_arg( $args, $redirect_url );
		}

		wp_safe_redirect( $redirect_url );
		exit;
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
