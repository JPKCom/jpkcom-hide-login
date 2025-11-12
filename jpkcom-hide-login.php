<?php
/*
Plugin Name: JPKCom Hide Login
Plugin URI: https://github.com/JPKCom/jpkcom-hide-login
Description: Rename the default WordPress login URL (wp-login.php) to a custom slug for enhanced security. Includes brute force protection and IP whitelist management.
Version: 1.2.0
Author: Jean Pierre Kolb <jpk@jpkc.com>
Author URI: https://www.jpkc.com/
Contributors: JPKCom
Tags: Login, Security, Brute Force Protection
Requires at least: 6.8
Tested up to: 6.9
Requires PHP: 8.3
Network: true
Stable tag: 1.2.0
License: GPL-2.0+
License URI: http://www.gnu.org/licenses/gpl-2.0.txt
Text Domain: jpkcom-hide-login
Domain Path: /languages
*/

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Prevent direct access.
}

/**
 * Plugin Constants
 */
if ( ! defined( 'JPKCOM_HIDE_LOGIN_VERSION' ) ) {
	define( 'JPKCOM_HIDE_LOGIN_VERSION', '1.2.0' );
}

if ( ! defined( 'JPKCOM_HIDE_LOGIN_OPTION' ) ) {
	define( 'JPKCOM_HIDE_LOGIN_OPTION', 'jpkcom_hide_login_slug' );
}

if ( ! defined( 'JPKCOM_HIDE_LOGIN_DEFAULT_SLUG' ) ) {
	define( 'JPKCOM_HIDE_LOGIN_DEFAULT_SLUG', 'jpkcom-login' );
}

if ( ! defined( 'JPKCOM_HIDE_LOGIN_NETWORK_OPTION' ) ) {
	define( 'JPKCOM_HIDE_LOGIN_NETWORK_OPTION', 'jpkcom_hide_login_network_slug' );
}

if ( ! defined( 'JPKCOM_HIDE_LOGIN_BASENAME' ) ) {
	define( 'JPKCOM_HIDE_LOGIN_BASENAME', plugin_basename( __FILE__ ) );
}

if ( ! defined( 'JPKCOM_HIDE_LOGIN_PLUGIN_PATH' ) ) {
	define( 'JPKCOM_HIDE_LOGIN_PLUGIN_PATH', plugin_dir_path( __FILE__ ) );
}

if ( ! defined( 'JPKCOM_HIDE_LOGIN_PLUGIN_URL' ) ) {
	define( 'JPKCOM_HIDE_LOGIN_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
}

/**
 * Requirements Check
 *
 * Deactivate plugin if requirements are not met.
 */
add_action( 'admin_init', static function (): void {
	global $wp_version;

	if ( version_compare( PHP_VERSION, '8.3', '<' ) ) {
		deactivate_plugins( JPKCOM_HIDE_LOGIN_BASENAME );
		wp_die(
			esc_html__( 'JPKCom Hide Login requires PHP 8.3 or higher.', 'jpkcom-hide-login' ),
			esc_html__( 'Plugin Deactivated', 'jpkcom-hide-login' ),
			[ 'back_link' => true ]
		);
	}

	if ( version_compare( $wp_version, '6.8', '<' ) ) {
		deactivate_plugins( JPKCOM_HIDE_LOGIN_BASENAME );
		wp_die(
			esc_html__( 'JPKCom Hide Login requires WordPress 6.8 or higher.', 'jpkcom-hide-login' ),
			esc_html__( 'Plugin Deactivated', 'jpkcom-hide-login' ),
			[ 'back_link' => true ]
		);
	}
} );

/**
 * Load Text Domain
 */
add_action( 'plugins_loaded', static function (): void {
	load_plugin_textdomain(
		'jpkcom-hide-login',
		false,
		dirname( JPKCOM_HIDE_LOGIN_BASENAME ) . '/languages'
	);
} );

/**
 * Plugin Activation Hook
 *
 * Schedule the daily cleanup cron event.
 */
register_activation_hook( __FILE__, static function (): void {
	if ( ! wp_next_scheduled( 'jpkcom_hide_login_cleanup_attempts' ) ) {
		wp_schedule_event( time(), 'daily', 'jpkcom_hide_login_cleanup_attempts' );
	}
} );

/**
 * Plugin Deactivation Hook
 *
 * Clear the scheduled cleanup cron event.
 */
register_deactivation_hook( __FILE__, static function (): void {
	$timestamp = wp_next_scheduled( 'jpkcom_hide_login_cleanup_attempts' );
	if ( $timestamp ) {
		wp_unschedule_event( $timestamp, 'jpkcom_hide_login_cleanup_attempts' );
	}
	wp_clear_scheduled_hook( 'jpkcom_hide_login_cleanup_attempts' );
} );

/**
 * Ensure cleanup cron is scheduled (in case it was cleared).
 *
 * This runs on every admin page load to ensure the cron event exists.
 */
add_action( 'admin_init', static function (): void {
	if ( ! wp_next_scheduled( 'jpkcom_hide_login_cleanup_attempts' ) ) {
		wp_schedule_event( time(), 'daily', 'jpkcom_hide_login_cleanup_attempts' );
	}
} );

/**
 * Initialize Plugin Updater
 */
add_action( 'init', static function (): void {
	$updater_file = JPKCOM_HIDE_LOGIN_PLUGIN_PATH . 'includes/class-plugin-updater.php';

	if ( file_exists( $updater_file ) ) {
		require_once $updater_file;

		if ( class_exists( 'JPKComHideLoginGitUpdate\\JPKComGitPluginUpdater' ) ) {
			new \JPKComHideLoginGitUpdate\JPKComGitPluginUpdater(
				plugin_file: __FILE__,
				current_version: JPKCOM_HIDE_LOGIN_VERSION,
				manifest_url: 'https://jpkcom.github.io/jpkcom-hide-login/plugin_jpkcom-hide-login.json'
			);
		}
	}
}, 5 );

/**
 * Load Plugin Classes
 */
require_once JPKCOM_HIDE_LOGIN_PLUGIN_PATH . 'includes/class-ip-manager.php';
require_once JPKCOM_HIDE_LOGIN_PLUGIN_PATH . 'includes/class-login-protection.php';
require_once JPKCOM_HIDE_LOGIN_PLUGIN_PATH . 'includes/class-mask-login.php';
require_once JPKCOM_HIDE_LOGIN_PLUGIN_PATH . 'includes/class-admin-settings.php';

/**
 * Bootstrap Plugin
 */
add_action( 'plugins_loaded', static function (): void {
	if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
		error_log( '[JPKCom Hide Login] Plugin bootstrap starting...' );
	}

	// Initialize components.
	$ip_manager       = new JPKCom_Hide_Login_IP_Manager();
	$login_protection = new JPKCom_Hide_Login_Login_Protection( $ip_manager );

	// Load brute force settings from options.
	$max_attempts   = (int) get_option( 'jpkcom_hide_login_max_attempts', 5 );
	$attempt_window = (int) get_option( 'jpkcom_hide_login_attempt_window', 60 );
	$block_duration = (int) get_option( 'jpkcom_hide_login_block_duration', 600 );

	$login_protection->set_max_attempts( $max_attempts );
	$login_protection->set_attempt_window( $attempt_window );
	$login_protection->set_block_duration( $block_duration );

	$mask_login       = new JPKCom_Hide_Login_Mask_Login( $ip_manager, jpkcom_hide_login_get_slug() );
	$admin_settings   = new JPKCom_Hide_Login_Admin_Settings( $ip_manager, $mask_login, $login_protection );

	if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
		error_log( '[JPKCom Hide Login] Components initialized. Slug: ' . jpkcom_hide_login_get_slug() );
	}

	// Initialize hooks.
	$login_protection->init_hooks();
	$mask_login->init_hooks();

	if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
		error_log( '[JPKCom Hide Login] Hooks initialized. is_admin: ' . ( is_admin() ? 'yes' : 'no' ) );
	}

	if ( is_admin() ) {
		$admin_settings->init_hooks();
	}

	// Register WP-CLI commands if available.
	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		require_once JPKCOM_HIDE_LOGIN_PLUGIN_PATH . 'includes/class-wp-cli.php';
		$wp_cli_commands = new JPKCom_Hide_Login_WP_CLI( $ip_manager, $login_protection );
		\WP_CLI::add_command( 'jpkcom-hide-login', $wp_cli_commands );
	}
}, 10 );

/**
 * Get the configured login slug.
 *
 * Priority:
 * 1. Network-wide slug (if multisite and set)
 * 2. Per-site option
 * 3. Default constant
 *
 * @return string Sanitized slug (no leading/trailing slashes).
 */
function jpkcom_hide_login_get_slug(): string {
	// Check for network-wide setting in Multisite.
	if ( is_multisite() ) {
		$network_slug = get_site_option( JPKCOM_HIDE_LOGIN_NETWORK_OPTION, null );

		if ( null !== $network_slug && false !== $network_slug && '' !== (string) $network_slug ) {
			$slug = sanitize_title_with_dashes( (string) $network_slug );

			if ( '' !== $slug ) {
				return $slug;
			}
		}
	}

	// Per-site option.
	$option = get_option( JPKCOM_HIDE_LOGIN_OPTION, JPKCOM_HIDE_LOGIN_DEFAULT_SLUG );
	$slug   = sanitize_title_with_dashes( (string) $option );

	return '' !== $slug ? $slug : JPKCOM_HIDE_LOGIN_DEFAULT_SLUG;
}

/**
 * Show one-time activation notice with new login URL.
 */
add_action( 'admin_notices', static function (): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	$notice_shown = get_option( 'jpkcom_hide_login_notice_shown', false );

	if ( $notice_shown ) {
		return;
	}

	$slug        = jpkcom_hide_login_get_slug();
	$url         = esc_url( home_url( '/' . $slug . '/' ) );
	$network_hint = '';

	if ( is_multisite() ) {
		$network_slug = get_site_option( JPKCOM_HIDE_LOGIN_NETWORK_OPTION, null );

		if ( null !== $network_slug && false !== $network_slug && '' !== (string) $network_slug ) {
			$network_hint = ' ' . esc_html__( '(network-wide setting active)', 'jpkcom-hide-login' );
		}
	}

	printf(
		'<div class="notice notice-success is-dismissible"><p><strong>%s</strong> %s%s</p></div>',
		esc_html__( 'JPKCom Hide Login activated! Your new login URL:', 'jpkcom-hide-login' ),
		'<a href="' . $url . '" target="_blank">' . esc_html( $url ) . '</a>',
		$network_hint
	);

	update_option( 'jpkcom_hide_login_notice_shown', true );
}, 20 );

/**
 * Show blocked IPs notice on Dashboard and Settings page.
 */
add_action( 'admin_notices', static function (): void {
	global $pagenow;

	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	$allowed_pages = [ 'index.php', 'options-general.php' ];

	if ( 'options-general.php' === $pagenow && ( $_GET['page'] ?? '' ) !== 'jpkcom-hide-login' ) {
		return;
	}

	if ( ! in_array( $pagenow, $allowed_pages, true ) ) {
		return;
	}

	$ip_manager  = new JPKCom_Hide_Login_IP_Manager();
	$blocked_ips = $ip_manager->get_blocked_ips();

	if ( empty( $blocked_ips ) ) {
		return;
	}

	$count = count( $blocked_ips );

	printf(
		'<div class="notice notice-warning"><p><strong>%s</strong> %s</p></div>',
		esc_html__( 'JPKCom Hide Login', 'jpkcom-hide-login' ),
		esc_html(
			sprintf(
				/* translators: %d: Number of blocked IPs */
				_n(
					'%d IP is currently blocked due to multiple failed login attempts.',
					'%d IPs are currently blocked due to multiple failed login attempts.',
					$count,
					'jpkcom-hide-login'
				),
				$count
			)
		)
	);
}, 21 );

/**
 * Network Admin Menu (Multisite)
 */
add_action( 'network_admin_menu', static function (): void {
	if ( ! is_multisite() ) {
		return;
	}

	add_submenu_page(
		'settings.php',
		__( 'JPKCom Hide Login (Network)', 'jpkcom-hide-login' ),
		__( 'Hide Login (Network)', 'jpkcom-hide-login' ),
		'manage_network_options',
		'jpkcom-hide-login-network',
		'jpkcom_hide_login_network_settings_page'
	);
} );

/**
 * Network Settings Page Callback (Multisite)
 */
function jpkcom_hide_login_network_settings_page(): void {
	if ( ! is_multisite() || ! current_user_can( 'manage_network_options' ) ) {
		return;
	}

	// Handle form submission.
	if ( 'POST' === $_SERVER['REQUEST_METHOD'] && check_admin_referer( 'jpkcom_hide_login_network_save', 'jpkcom_hide_login_network_nonce' ) ) {
		$posted    = $_POST['jpkcom_hide_login_network_slug'] ?? '';
		$sanitized = sanitize_title_with_dashes( (string) $posted );

		if ( '' === $sanitized ) {
			delete_site_option( JPKCOM_HIDE_LOGIN_NETWORK_OPTION );
			add_settings_error(
				'jpkcom-hide-login-network',
				'updated',
				esc_html__( 'Network slug removed. Sites will use their own settings.', 'jpkcom-hide-login' ),
				'updated'
			);
		} else {
			update_site_option( JPKCOM_HIDE_LOGIN_NETWORK_OPTION, $sanitized );
			add_settings_error(
				'jpkcom-hide-login-network',
				'updated',
				esc_html__( 'Network slug updated.', 'jpkcom-hide-login' ),
				'updated'
			);
		}
	}

	$network_slug = get_site_option( JPKCOM_HIDE_LOGIN_NETWORK_OPTION, '' );

	settings_errors( 'jpkcom-hide-login-network' );
	?>
	<div class="wrap">
		<h1><?php echo esc_html__( 'JPKCom Hide Login — Network Settings', 'jpkcom-hide-login' ); ?></h1>

		<form method="post" action="">
			<?php wp_nonce_field( 'jpkcom_hide_login_network_save', 'jpkcom_hide_login_network_nonce' ); ?>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row">
						<label for="jpkcom_hide_login_network_slug">
							<?php echo esc_html__( 'Network-wide login slug', 'jpkcom-hide-login' ); ?>
						</label>
					</th>
					<td>
						<input
							name="jpkcom_hide_login_network_slug"
							type="text"
							id="jpkcom_hide_login_network_slug"
							value="<?php echo esc_attr( (string) $network_slug ); ?>"
							class="regular-text"
							placeholder="<?php echo esc_attr( JPKCOM_HIDE_LOGIN_DEFAULT_SLUG ); ?>"
						/>
						<p class="description">
							<?php echo esc_html__( 'Set a network-wide login slug. Leave empty to let each site use its own slug.', 'jpkcom-hide-login' ); ?>
						</p>
					</td>
				</tr>
			</table>

			<?php submit_button( __( 'Save Network Settings', 'jpkcom-hide-login' ) ); ?>
		</form>
	</div>
	<?php
}
