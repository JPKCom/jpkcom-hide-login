<?php
/**
 * Guard: the bundled updater is the unmodified family copy.
 *
 * includes/class-plugin-updater.php is shared by every JPKCom plugin and must
 * stay identical to the family copy modulo namespace and slug; it is never
 * patched per plugin. From 1.2.7 to 1.2.12 this copy did differ: its log()
 * went through jpkcom_hide_login_log() instead of error_log(), presumably to
 * quiet a Plugin Check finding. Nothing caught it, so the deviation was
 * carried into the 1.5.0 updater by hand and every family release had to be
 * redone for this plugin alone. The Plugin Check finding for error_log() in
 * the updater is accepted instead, as in the other family plugins.
 *
 * The family reference is jpkcom-allow-blocks. Its normalised SHA256 is pinned
 * below so the check also runs in CI, where the sibling repository is absent;
 * when the sibling is checked out next to this one, it is compared directly.
 *
 * Unlike jpkcom-harden-trim's guard this does NOT forbid error_log() in the
 * plugin's own code: jpkcom_hide_login_log() writes there on purpose, gated by
 * WP_DEBUG / JPKCOM_HIDE_LOGIN_DEBUG.
 *
 * @package JPKCom_Hide_Login
 */
declare(strict_types=1);

$root = dirname( __DIR__ );
$fail = 0;

/**
 * Report one check.
 *
 * @param string $label Check name.
 * @param bool   $ok    Result.
 */
function pin_chk( string $label, bool $ok ): void {
	global $fail;
	echo ( $ok ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	if ( ! $ok ) {
		$fail++;
	}
}

/**
 * Replace a copy's namespace and slug by neutral placeholders.
 *
 * @param string $source    Updater source.
 * @param string $namespace Namespace of that copy.
 * @param string $slug      Plugin slug of that copy.
 * @return string Normalised source.
 */
function pin_normalise_updater( string $source, string $namespace, string $slug ): string {
	return str_replace( array( $namespace, $slug ), array( 'FAMILYNS', 'FAMILYSLUG' ), $source );
}

// Normalised SHA256 of jpkcom-allow-blocks/includes/class-plugin-updater.php
// (updater 1.5.0), the same value jpkcom-harden-trim pins. Bump it only
// together with a family-wide updater release.
const PIN_FAMILY_UPDATER_SHA256 = 'b9f592fb774b7e07c0500ccc438f8dfea12297960d389065f41e20fd7de43190';

$updater    = (string) file_get_contents( $root . '/includes/class-plugin-updater.php' );
$normalised = pin_normalise_updater( $updater, 'JPKComHideLoginGitUpdate', 'jpkcom-hide-login' );
$actual     = hash( 'sha256', $normalised );

echo "\nThe updater is the family copy\n";

pin_chk( 'updater uses this plugin\'s namespace', str_contains( $updater, 'namespace JPKComHideLoginGitUpdate;' ) );
pin_chk( 'updater equals the pinned family copy (normalised SHA256 ' . $actual . ')', PIN_FAMILY_UPDATER_SHA256 === $actual );
pin_chk( 'updater does not call this plugin\'s own log helper', ! str_contains( $updater, 'jpkcom_hide_login_log' ) );

$sibling = dirname( $root ) . '/jpkcom-allow-blocks/includes/class-plugin-updater.php';
if ( is_readable( $sibling ) ) {
	$family = pin_normalise_updater( (string) file_get_contents( $sibling ), 'JPKComAllowBlocksGitUpdate', 'jpkcom-allow-blocks' );
	pin_chk( 'updater equals the jpkcom-allow-blocks checkout (normalised)', $family === $normalised );
} else {
	echo "  SKIP  comparison with the jpkcom-allow-blocks checkout (not present)\n";
}

printf( "\n  %d failed\n", $fail );
exit( $fail > 0 ? 1 : 0 );
