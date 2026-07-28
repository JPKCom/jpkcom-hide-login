<?php
/**
 * Minimal WordPress stubs for the security regression tests.
 *
 * These tests deliberately avoid a full WordPress install: the logic under test
 * is pure request handling, and a dependency-free runner means the checks also
 * run in CI on every pull request.
 *
 * @package JPKCom_Hide_Login
 * @since 1.2.5
 */

declare(strict_types=1);

define( 'ABSPATH', '/tmp/jpkcom-hide-login-tests/' );
define( 'JPKCOM_HIDE_LOGIN_DEBUG', false );

$GLOBALS['__options']    = [];
$GLOBALS['__transients'] = [];
$GLOBALS['__filters']    = [];
$GLOBALS['__logged_in']  = false;

function sanitize_text_field( $s ) { return is_string( $s ) ? trim( strip_tags( $s ) ) : ''; }
function wp_unslash( $s ) { return is_string( $s ) ? stripslashes( $s ) : $s; }
function wp_salt( $scheme = 'auth' ) { return 'test-salt-for-regression-tests'; }
function get_option( $k, $d = false ) { return $GLOBALS['__options'][ $k ] ?? $d; }
function update_option( $k, $v ) { $GLOBALS['__options'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['__options'][ $k ] ); return true; }
function get_transient( $k ) { return $GLOBALS['__transients'][ $k ] ?? false; }
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['__transients'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['__transients'][ $k ] ); return true; }
function apply_filters( $tag, $val ) { $cb = $GLOBALS['__filters'][ $tag ] ?? null; return $cb ? $cb( $val ) : $val; }
function add_filter( $tag, $cb, $prio = 10, $args = 1 ) { $GLOBALS['__filters'][ $tag ] = $cb; }
function add_action( $tag, $cb, $prio = 10, $args = 1 ) {}
function remove_action( $tag, $cb, $prio = 10 ) {}
function is_multisite() { return false; }
function is_user_logged_in() { return (bool) ( $GLOBALS['__logged_in'] ?? false ); }
function home_url( $p = '', $s = null ) { return 'https://example.test/' . ltrim( (string) $p, '/' ); }
function network_home_url( $p = '', $s = null ) { return home_url( $p, $s ); }
function add_query_arg( $args, $url = null ) {
	if ( is_array( $args ) && null !== $url ) {
		return $url . ( str_contains( (string) $url, '?' ) ? '&' : '?' ) . http_build_query( $args );
	}
	return $url ?? $args;
}
function wp_parse_url( $u, $c = -1 ) { return parse_url( $u, $c ); }
function wp_parse_args( $a ) { parse_str( (string) $a, $o ); return $o; }
function status_header( $c ) {}
function nocache_headers() {}
function esc_html__( $s, $d = null ) { return $s; }
function __( $s, $d = null ) { return $s; }
function sanitize_title_with_dashes( $s ) { return strtolower( (string) $s ); }
function class_exists_wc() { return false; }
function jpkcom_hide_login_log( $message, $level = 'trace' ) {}
function sanitize_key( $k ) { return strtolower( preg_replace( '/[^a-zA-Z0-9_\-]/', '', (string) $k ) ); }
function _n( $s, $p, $n, $d = null ) { return 1 === $n ? $s : $p; }
function is_wp_error( $t ) { return $t instanceof WP_Error; }

/**
 * Just enough of WP_Error for the login-protection callbacks.
 */
class WP_Error {
	public array $errors = [];
	public function __construct( $code = '', $message = '' ) {
		if ( '' !== $code ) { $this->errors[ $code ][] = $message; }
	}
	public function add( $code, $message = '' ) { $this->errors[ $code ][] = $message; }
	public function get_error_message() { return reset( $this->errors )[0] ?? ''; }
}

/**
 * Stands in for wp_die(); the tests treat the exception as "blocked with 404".
 */
function wp_die( $message, $title = '', $args = [] ) {
	throw new RuntimeException( 'wp_die:404' );
}

// --- tiny assertion harness -------------------------------------------------

$GLOBALS['__pass'] = 0;
$GLOBALS['__fail'] = 0;

function section( string $title ): void {
	echo "\n" . $title . "\n";
}

function chk( string $name, bool $cond, string $detail = '' ): void {
	if ( $cond ) {
		$GLOBALS['__pass']++;
		echo "  PASS  {$name}\n";
	} else {
		$GLOBALS['__fail']++;
		echo "  FAIL  {$name}" . ( '' !== $detail ? "  ({$detail})" : '' ) . "\n";
	}
}

function summary(): int {
	printf( "\n  %d passed, %d failed\n", $GLOBALS['__pass'], $GLOBALS['__fail'] );
	return $GLOBALS['__fail'] > 0 ? 1 : 0;
}
