<?php
/**
 * Security regression tests.
 *
 * Every case here corresponds to a defect that was actually present and is
 * written so that it fails against the pre-fix implementation. Run with:
 *
 *     php tests/test-security.php
 *
 * @package JPKCom_Hide_Login
 * @since 1.2.5
 */

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../includes/class-ip-manager.php';
require_once __DIR__ . '/../includes/class-mask-login.php';

/**
 * Resolve the client IP for a given $_SERVER shape.
 */
function ip_for( JPKCom_Hide_Login_IP_Manager $m, array $server ): string {
	$_SERVER = $server;
	return $m->get_current_ip();
}

/**
 * Run handle_login_request() and report whether the request was blocked.
 */
function request_outcome( string $uri, string $script, bool $logged_in = false, string $slug = 'geheim-login' ): string {
	$GLOBALS['__logged_in'] = $logged_in;
	$_SERVER                = [
		'REQUEST_URI' => $uri,
		'SCRIPT_NAME' => $script,
		'REMOTE_ADDR' => '203.0.113.9',
	];

	$mask = new JPKCom_Hide_Login_Mask_Login( new JPKCom_Hide_Login_IP_Manager(), $slug );

	try {
		$mask->handle_login_request();
		return 'allowed';
	} catch ( RuntimeException $e ) {
		return '404';
	}
}

$ipm = new JPKCom_Hide_Login_IP_Manager();

// ---------------------------------------------------------------------------
section( 'Client IP: proxy headers are not believed without a trusted proxy' );

chk( 'plain visitor', '203.0.113.9' === ip_for( $ipm, [ 'REMOTE_ADDR' => '203.0.113.9' ] ) );
chk( 'X-Forwarded-For ignored', '203.0.113.9' === ip_for( $ipm, [ 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '127.0.0.1' ] ) );
chk( 'CF-Connecting-IP ignored', '203.0.113.9' === ip_for( $ipm, [ 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_CF_CONNECTING_IP' => '127.0.0.1' ] ) );
chk( 'X-Real-IP ignored', '203.0.113.9' === ip_for( $ipm, [ 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_REAL_IP' => '::1' ] ) );
chk(
	'spoofed header no longer yields a whitelisted IP',
	! $ipm->is_ip_whitelisted( ip_for( $ipm, [ 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '127.0.0.1' ] ) )
);

// ---------------------------------------------------------------------------
section( 'Client IP: behind a declared trusted proxy' );

add_filter( 'jpkcom_hide_login_trusted_proxies', fn( $p ) => [ '10.0.0.0/8', '2400:cb00::/32' ] );

chk( 'CF header honoured behind the proxy', '198.51.100.5' === ip_for( $ipm, [ 'REMOTE_ADDR' => '10.1.2.3', 'HTTP_CF_CONNECTING_IP' => '198.51.100.5' ] ) );
chk( 'XFF: client left, proxy right', '198.51.100.5' === ip_for( $ipm, [ 'REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '198.51.100.5, 10.9.9.9' ] ) );
chk(
	'XFF: attacker-prepended entry is discarded',
	'198.51.100.5' === ip_for( $ipm, [ 'REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '127.0.0.1, 198.51.100.5, 10.9.9.9' ] )
);
chk( 'IPv6 proxy recognised', '198.51.100.7' === ip_for( $ipm, [ 'REMOTE_ADDR' => '2400:cb00::1', 'HTTP_CF_CONNECTING_IP' => '198.51.100.7' ] ) );
chk( 'non-proxy still cannot forge', '203.0.113.9' === ip_for( $ipm, [ 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '127.0.0.1' ] ) );

$GLOBALS['__filters'] = [];

// ---------------------------------------------------------------------------
section( 'Whitelist: CIDR matching for both address families' );

$GLOBALS['__options']['jpkcom_hide_login_ip_whitelist'] = [ '2001:db8::/32', '192.0.2.0/24' ];

chk( 'IPv6 inside range', $ipm->is_ip_whitelisted( '2001:db8:1234::9' ) );
chk( 'IPv6 outside range', ! $ipm->is_ip_whitelisted( '2001:dead::1' ) );
chk( 'IPv4 inside range', $ipm->is_ip_whitelisted( '192.0.2.77' ) );
chk( 'IPv4 outside range', ! $ipm->is_ip_whitelisted( '198.51.100.1' ) );
chk( 'IPv4 not matched against an IPv6 range', ! $ipm->is_ip_whitelisted( '203.0.113.1' ) );

$GLOBALS['__options']['jpkcom_hide_login_ip_whitelist'] = [ '0.0.0.0/0' ];
chk( '/0 matches everything', $ipm->is_ip_whitelisted( '8.8.8.8' ) );
$GLOBALS['__options']['jpkcom_hide_login_ip_whitelist'] = [];

// ---------------------------------------------------------------------------
section( 'wp-login.php block, including the encoding and slash bypasses' );

chk( '/wp-login.php', '404' === request_outcome( '/wp-login.php', '/wp-login.php' ) );
chk( '/wp-login.php/ trailing slash', '404' === request_outcome( '/wp-login.php/', '/wp-login.php' ) );
chk( '//wp-login.php (parse_url read it as a host)', '404' === request_outcome( '//wp-login.php', '/wp-login.php' ) );
chk( '/wp-%6cogin.php (percent-encoded)', '404' === request_outcome( '/wp-%6cogin.php', '/wp-login.php' ) );
chk( '/wp-%6Cogin.php (uppercase hex)', '404' === request_outcome( '/wp-%6Cogin.php', '/wp-login.php' ) );
chk( '/wp-login.php?a=1', '404' === request_outcome( '/wp-login.php?a=1', '/wp-login.php' ) );

// ---------------------------------------------------------------------------
section( 'wp-admin block matches the path segment, not any substring' );

chk( '/wp-admin/ while logged out', '404' === request_outcome( '/wp-admin/', '/wp-admin/index.php' ) );
chk( '/wp-admin/options.php', '404' === request_outcome( '/wp-admin/options.php', '/wp-admin/options.php' ) );
chk( '//wp-admin/ (slash bypass)', '404' === request_outcome( '//wp-admin/', '/wp-admin/index.php' ) );
chk( 'logged-in users pass', 'allowed' === request_outcome( '/wp-admin/', '/wp-admin/index.php', true ) );
chk( 'admin-ajax.php stays reachable', 'allowed' === request_outcome( '/wp-admin/admin-ajax.php', '/wp-admin/admin-ajax.php' ) );
chk( 'a post slug containing "wp-admin" is not blocked', 'allowed' === request_outcome( '/my-wp-admin-guide/', '/index.php' ) );
chk( 'ordinary page', 'allowed' === request_outcome( '/about-us/', '/index.php' ) );

// ---------------------------------------------------------------------------
section( 'Redirects must not disclose the secret slug' );

$slug     = 'geheim-login';
$location = 'https://example.test/wp-login.php?redirect_to=%2Fwp-admin%2F';

$GLOBALS['__logged_in'] = false;
$_SERVER                = [ 'REQUEST_URI' => '/wp-admin/', 'SCRIPT_NAME' => '/wp-admin/index.php', 'REMOTE_ADDR' => '203.0.113.9' ];
$anon                   = ( new JPKCom_Hide_Login_Mask_Login( new JPKCom_Hide_Login_IP_Manager(), $slug ) )->filter_wp_redirect( $location, 302 );
chk( 'anonymous request: slug absent from Location', ! str_contains( $anon, $slug ), $anon );

$GLOBALS['__logged_in'] = true;
$auth                   = ( new JPKCom_Hide_Login_Mask_Login( new JPKCom_Hide_Login_IP_Manager(), $slug ) )->filter_wp_redirect( $location, 302 );
chk( 'authenticated request: slug applied', str_contains( $auth, $slug ), $auth );

$GLOBALS['__logged_in'] = false;
$_SERVER                = [ 'REQUEST_URI' => '/' . $slug, 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => '203.0.113.9' ];
$mask                   = new JPKCom_Hide_Login_Mask_Login( new JPKCom_Hide_Login_IP_Manager(), $slug );
$prop                   = new ReflectionProperty( $mask, 'is_custom_login_request' );
$prop->setAccessible( true );
$prop->setValue( $mask, true );
chk( 'while serving the masked login page: slug applied', str_contains( $mask->filter_wp_redirect( $location, 302 ), $slug ) );

$untouched = ( new JPKCom_Hide_Login_Mask_Login( new JPKCom_Hide_Login_IP_Manager(), $slug ) )->filter_wp_redirect( 'https://example.test/thanks/', 302 );
chk( 'unrelated redirect left alone', 'https://example.test/thanks/' === $untouched );

exit( summary() );
