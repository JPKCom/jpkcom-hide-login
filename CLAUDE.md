# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JPKCom Hide Login is a professional WordPress security plugin that renames the default WordPress login URL (`wp-login.php`) to a custom slug for protection against automated attacks. The plugin includes comprehensive brute force protection with IP-based rate limiting and IP whitelist management.

## Requirements

- **PHP:** 8.3+ (enforced via runtime check in jpkcom-hide-login.php:67-73)
- **WordPress:** 6.9+ — header and runtime check both driven by `JPKCOM_HIDE_LOGIN_MIN_WP`; `JPKCOM_HIDE_LOGIN_MIN_PHP` does the same for PHP. Change the constant *and* the plugin header together.
- **Multisite:** Fully supported with network-wide configuration options

## Architecture

### Modular Design

The plugin uses a **modular, object-oriented architecture** with separation of concerns:

```
jpkcom-hide-login/
├── jpkcom-hide-login.php              # Bootstrap & initialization
└── includes/
    ├── class-ip-manager.php           # IP whitelist/blocklist management
    ├── class-login-protection.php     # Brute force protection
    ├── class-mask-login.php           # Login URL masking
    ├── class-admin-settings.php       # Admin interface
    ├── class-wp-cli.php               # WP-CLI commands
    └── class-plugin-updater.php       # GitHub-based updates
```

### Key Components

#### 1. Bootstrap (jpkcom-hide-login.php)

**Responsibilities:**
- Define plugin constants (lines 31-57)
- Check PHP and WordPress version requirements (lines 64-83)
- Load plugin classes from `includes/` directory (lines 119-122)
- Register plugin activation/deactivation hooks for cleanup cron (lines 97-119)
- Schedule daily WordPress Cron event for cleanup (line 126-129)
- Bootstrap plugin components (lines 127-141)
- Helper function `jpkcom_hide_login_get_slug()` for slug resolution (lines 153-172)
- Admin notices for activation and blocked IPs (lines 177-255)
- Multisite network admin menu and settings page (lines 260-344)

**Constants:**
- `JPKCOM_HIDE_LOGIN_VERSION` - Plugin version (1.2.7)
- `JPKCOM_HIDE_LOGIN_DEBUG` - Verbose request tracing, default `false`. Deliberately *not* `WP_DEBUG`: the mask runs on `init` for every request, so tying tracing to `WP_DEBUG` wrote ~10 lines per request into every dev/staging log.
- `JPKCOM_HIDE_LOGIN_OPTION` - Per-site option name
- `JPKCOM_HIDE_LOGIN_DEFAULT_SLUG` - Default slug ('jpkcom-login')
- `JPKCOM_HIDE_LOGIN_NETWORK_OPTION` - Network option name (Multisite)
- `JPKCOM_HIDE_LOGIN_BASENAME` - Plugin basename
- `JPKCOM_HIDE_LOGIN_PLUGIN_PATH` - Plugin directory path
- `JPKCOM_HIDE_LOGIN_PLUGIN_URL` - Plugin URL

#### 2. IP Manager (includes/class-ip-manager.php)

**Class:** `JPKCom_Hide_Login_IP_Manager`

**Responsibilities:**
- Get current user IP address (supports proxies and Cloudflare)
- Manage IP whitelist with CIDR range support
- Manage temporary IP blocklist
- Validate IP addresses and CIDR ranges

**Key Methods:**
- `get_current_ip(): string` - Get visitor's IP address
- `is_ip_whitelisted(string $ip): bool` - Check if IP is whitelisted
- `is_ip_blocked(string $ip): bool` - Check if IP is blocked
- `block_ip(string $ip, int $duration = 600): bool` - Block an IP
- `unblock_ip(string $ip): bool` - Unblock an IP
- `clear_all_blocks(): bool` - Clear all blocked IPs
- `get_whitelist(): array` - Get whitelisted IPs
- `add_to_whitelist(string $ip): bool` - Add IP to whitelist
- `remove_from_whitelist(string $ip): bool` - Remove IP from whitelist

**Storage:**
- Whitelist: WordPress option `jpkcom_hide_login_ip_whitelist` (persistent)
- Blocklist: WordPress transient `jpkcom_hide_login_blocked_ips` (TTL-based)

**Client IP determination — read this before touching `get_current_ip()`:**

Only `REMOTE_ADDR` is authoritative. `X-Forwarded-For`, `CF-Connecting-IP` and `X-Real-IP` are ordinary request headers that **any client can set**, so they are consulted *only* when `REMOTE_ADDR` itself matches a declared trusted proxy.

Until 1.2.4 those headers were read unconditionally and preferred over `REMOTE_ADDR`. A single `X-Forwarded-For: 127.0.0.1` therefore made the plugin see a whitelisted address, which disabled the wp-login.php block **and** the brute-force protection, and let an attacker get someone else's address blocked. Do not reintroduce a header-first lookup.

Trusted proxies are opt-in and empty by default:

```php
// wp-config.php — e.g. Cloudflare ranges
define( 'JPKCOM_HIDE_LOGIN_TRUSTED_PROXIES', '173.245.48.0/20, 2400:cb00::/32' );
```

```php
add_filter( 'jpkcom_hide_login_trusted_proxies', fn() => [ '10.0.0.0/8' ] );
```

For `X-Forwarded-For` the chain is walked **right to left**, stopping at the first entry that is not itself a trusted proxy — the left-hand entries are attacker-supplied and must never win.

**Privacy — what the hashing does and does not do:**
- Keys are derived with `hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) )`, not `md5( $ip )`. A bare MD5 of an IPv4 address is reversible by walking all 2^32 candidates in seconds, so it was neither private nor unguessable.
- The **block list deliberately stores the plain address** alongside the key so the admin screen can show it. That record is therefore *not* anonymised — do not describe it as such.
- The **attempt counter** stores no address at all; there the salted key is the only trace, which is where the salt genuinely buys something.

#### 3. Login Protection (includes/class-login-protection.php)

**Class:** `JPKCom_Hide_Login_Login_Protection`

**Responsibilities:**
- Track failed login attempts per IP
- Automatically block IPs after threshold
- Show remaining attempts on login form
- Clear attempts on successful login

**Configuration:**
- Max attempts: 5 (configurable via setter)
- Attempt window: 60 seconds (configurable)
- Block duration: 600 seconds / 10 minutes (configurable)

**Key Methods:**
- `init_hooks(): void` - Register WordPress hooks
- `handle_failed_login(string $username, WP_Error $error): void` - Process failed login
- `check_login_attempts($user, string $username)` - Pre-authentication check
- `clear_login_attempts(string $username, WP_User $user): void` - Clear on success
- `cleanup_expired_attempts(): int` - Cleanup expired transients from database

**Hooks Used:**
- `wp_login_failed` - Track failed attempts
- `authenticate` (priority 30) - Check attempts before login
- `wp_login` - Clear attempts on success
- `jpkcom_hide_login_cleanup_attempts` - Daily cron cleanup

**Storage:**
- Transient: `jpkcom_hide_login_attempts_{hash}` (60 second TTL)

#### 4. Mask Login (includes/class-mask-login.php)

**Class:** `JPKCom_Hide_Login_Mask_Login`

**Responsibilities:**
- Handle custom login URL routing
- Block unauthorized access to wp-login.php and wp-admin
- Filter all WordPress URLs to use custom slug
- Handle password reset links
- WooCommerce compatibility
- Multisite wp-signup.php support

**Critical Implementation:**
Uses the **Defender Security approach** for serving login page:
```php
// Set global flag - NO $_SERVER manipulation!
global $error, $interim_login, $action, $user_login, $user, $redirect_to;
$GLOBALS['pagenow'] = 'wp-login.php';
require_once ABSPATH . 'wp-login.php';
exit;
```

**Key Methods:**
- `init_hooks(): void` - Register all WordPress hooks
- `handle_login_request(): void` - Main request router
- `serve_login_page(): void` - Serve wp-login.php via custom slug
- `show_404(): void` - Display 404 error for blocked access
- `filter_login_url()` - Replace wp-login.php in login URLs
- `filter_logout_url()` - Replace wp-login.php in logout URLs
- `filter_site_url()` - Replace wp-login.php in site URLs
- `filter_network_site_url()` - Replace wp-login.php in network URLs

**Hooks Used:**
- `init` (priority 1) - Handle login requests early
- `login_url`, `logout_url`, `lostpassword_url`, `register_url`
- `logout_redirect` - Redirect after logout
- `site_url`, `network_site_url` (priority 100)
- `login_form_rp`, `login_form_resetpass` - Password reset
- `wp_signup_location` - Multisite signup URL
- `woocommerce_logout_default_redirect_url` - WooCommerce compatibility

**Security:**
- Returns 404 (not 403) to avoid information disclosure
- Skips AJAX, REST API, and WooCommerce AJAX requests
- Allows admin-ajax.php for logged-out users
- Respects IP whitelist for emergency access

#### 5. Admin Settings (includes/class-admin-settings.php)

**Class:** `JPKCom_Hide_Login_Admin_Settings`

**Responsibilities:**
- Render admin settings page
- Handle slug validation and saving
- Manage IP whitelist via admin interface
- Clear blocked IPs
- Display blocked IPs with expiration
- Show protection status and current IP

**Key Methods:**
- `init_hooks(): void` - Register admin hooks
- `add_settings_page(): void` - Add to Settings menu
- `register_settings(): void` - Register WordPress settings
- `sanitize_slug(mixed $value): string` - Validate and sanitize slug
- `sanitize_max_attempts(mixed $value): int` - Validate max attempts
- `sanitize_attempt_window(mixed $value): int` - Validate attempt window
- `sanitize_block_duration(mixed $value): int` - Validate block duration
- `render_settings_page(): void` - Render admin interface
- `handle_clear_blocks(): void` - Clear all blocked IPs
- `handle_add_whitelist(): void` - Add IP to whitelist
- `handle_remove_whitelist(): void` - Remove IP from whitelist

**Admin Page Location:**
- **Settings → Hide Login** (per-site)
- **Network Admin → Settings → Hide Login (Network)** (Multisite)

**Features:**
- Custom slug configuration with validation
- Brute force protection status display
- Brute force threshold customization (max attempts, attempt window, block duration)
- Currently blocked IPs table with expiration times
- One-click "Clear All Blocked IPs" button
- IP whitelist management (add/remove)
- Current IP display with whitelist indicator
- WordPress Core UI (no custom elements)

#### 6. WP-CLI Commands (includes/class-wp-cli.php)

**Class:** `JPKCom_Hide_Login_WP_CLI`

**Responsibilities:**
- Provide command-line interface for plugin management
- Display plugin status and configuration
- Manage login slug via CLI
- Manage IP whitelist via CLI
- View and clear blocked IPs
- Configure brute force protection settings
- Manually trigger database cleanup for expired transients

**Available Commands:**
- `wp jpkcom-hide-login status` - Display plugin status and configuration
- `wp jpkcom-hide-login get-slug` - Get current login slug
- `wp jpkcom-hide-login set-slug <slug>` - Set login slug
- `wp jpkcom-hide-login whitelist list` - List whitelisted IPs
- `wp jpkcom-hide-login whitelist add <ip>` - Add IP to whitelist
- `wp jpkcom-hide-login whitelist remove <ip>` - Remove IP from whitelist
- `wp jpkcom-hide-login blocked list` - List blocked IPs with details
- `wp jpkcom-hide-login blocked clear` - Clear all blocked IPs
- `wp jpkcom-hide-login protection max-attempts <value>` - Set max login attempts
- `wp jpkcom-hide-login protection attempt-window <value>` - Set attempt window
- `wp jpkcom-hide-login protection block-duration <value>` - Set block duration
- `wp jpkcom-hide-login cleanup` - Manually cleanup expired login attempt transients

**Registration:**
Commands are registered in jpkcom-hide-login.php during `plugins_loaded` hook if WP-CLI is available.

WP-CLI derives subcommand names from **method names**, so `get_slug()` registered as `get_slug`, not the documented `get-slug`. Both slug commands therefore carry an explicit `@subcommand get-slug` / `@subcommand set-slug` annotation. Add one to any future method whose name contains an underscore, otherwise the documented command simply does not exist.

### Slug Resolution Priority

The function `jpkcom_hide_login_get_slug()` resolves slugs with this priority:
1. Network-wide slug (if multisite and set)
2. Per-site option
3. Default constant `JPKCOM_HIDE_LOGIN_DEFAULT_SLUG`

### Security Considerations

**IP Privacy:**
- Attempt-counter keys are derived with `hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) )`; that transient stores no address, so the key is the only trace
- The block list stores the plain address on purpose so the admin screen can display it — that record is not anonymised
- No plain IP addresses in persistent (autoloaded option) storage; both stores are expiring transients

**Request-path matching:**
- Never match core scripts with `str_contains()` against `REQUEST_URI` or `wp_parse_url()`'s path. `//wp-login.php` makes `parse_url()` read `wp-login.php` as the *host* and return an empty path, and `/wp-%6cogin.php` never matches an undecoded comparison — both bypassed the block until 1.2.4.
- `get_request_path()` strips the query manually, `rawurldecode()`s and collapses repeated slashes; `get_script_path()` reports what the server actually resolved (`SCRIPT_NAME`), which is the authoritative signal.
- wp-admin is matched on the **first path segment**, not as a substring: `/my-wp-admin-guide/` used to 404 for every visitor.

**Slug disclosure:**
- `filter_wp_redirect()` rewrites `wp-login.php` to the custom slug only while serving the masked login page or for an authenticated request. An anonymous probe that provokes such a redirect must not receive the secret slug in the `Location` header.

**Regression tests:**
- `tests/test-security.php` covers all of the above and is written so each case fails against the pre-1.2.5 implementation. Run with `php tests/test-security.php`; CI runs it on every pull request. `tests/` is excluded from the release ZIP.

**Transient Expiration & Cleanup:**
- Blocked IPs automatically expire via WordPress transients
- Attempt counters expire based on configured attempt window (default: 60 seconds)
- **Automatic Cleanup:** Daily WordPress Cron job (`jpkcom_hide_login_cleanup_attempts`) removes expired transients
- **Manual Cleanup:** Via WP-CLI command `wp jpkcom-hide-login cleanup`
- **Deactivation:** All scheduled cron events are cleared on plugin deactivation

**A block must never renew itself:**
`check_login_attempts()` returns a `WP_Error` for a blocked IP, and WordPress fires `wp_login_failed` for that rejection like any other. `handle_failed_login()` therefore returns early when the IP is already blocked — otherwise every retry increments the counter and calls `block_ip()` again with a fresh full duration, so the block lasts as long as someone keeps trying and the "try again in N minutes" message is a lie.

**Client IP that is not public means the setup is broken, not the visitor:**
`JPKCom_Hide_Login_IP_Manager::looks_like_proxy_address()` flags loopback/private/link-local addresses. With no trusted proxy declared, that means all visitors share one address (collective lockout) or — if the address is whitelisted — the protection is off entirely. The settings screen says so rather than leaving it to be discovered.

**Hook callbacks must tolerate foreign argument shapes:**
`wp_login`, `wp_login_failed` and `authenticate` are public and third-party code fires them with whatever it has — MainWP Child calls `do_action( 'wp_login', $user_login )` with a *single* argument. Under `declare(strict_types=1)` a `string $username, \WP_User $user` signature turns that into a fatal `ArgumentCountError` in the middle of someone else's login. Every hook callback in `class-login-protection.php` and the URL filters in `class-mask-login.php` therefore take `mixed`/optional parameters and normalise inside. Do not "tighten" these signatures back up.

**Direct File Access Prevention:**
All PHP files include the check:
```php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
```

**Type Safety:**
All files use `declare(strict_types=1);` and type hints on all methods.

### Text Domain & Translations

- Text domain: `jpkcom-hide-login`
- Domain path: `/languages` — ships `de_DE` and `de_DE_formal` as `.po`, `.mo` **and** `.l10n.php`

**Never hand-write the `.l10n.php` files.** Regenerate them from the `.po` with `wp i18n make-php languages/`. A plural entry in that format is `'<singular>' => "<form0>\0<form1>"` — a *NUL-joined string*. Up to 1.2.6 both files stored plural entries as PHP **arrays**; `WP_Translation_Controller::locate_translation()` passes the value straight to `explode()`, so on a German site the second failed login attempt died with a fatal `TypeError` and the login page returned HTTP 500 — brute-force protection never blocked anything, because the request never got that far.
- Translation loading: jpkcom-hide-login.php:89-95
- All user-facing strings wrapped in `__()`, `_e()`, `_n()`, `esc_html__()`, etc.

### Admin Notices

**One-time activation notice** (jpkcom-hide-login.php:177-208):
- Displays new login URL on first admin page view
- Stored in option `jpkcom_hide_login_notice_shown`
- Shows network hint if network-wide slug is active

**Blocked IP notice** (jpkcom-hide-login.php:213-255):
- Only shown on Dashboard and Settings page
- Auto-cleans expired entries from blocked list
- Displays count of currently blocked IPs

### Database Schema

**WordPress Options:**
- `jpkcom_hide_login_slug` - Per-site custom slug
- `jpkcom_hide_login_network_slug` - Network-wide slug (Multisite)
- `jpkcom_hide_login_ip_whitelist` - Serialized array of whitelisted IPs
- `jpkcom_hide_login_notice_shown` - Boolean, activation notice flag
- `jpkcom_hide_login_max_attempts` - Integer, max login attempts (default: 5)
- `jpkcom_hide_login_attempt_window` - Integer, attempt window in seconds (default: 60)
- `jpkcom_hide_login_block_duration` - Integer, block duration in seconds (default: 600)

**WordPress Transients:**
- `jpkcom_hide_login_blocked_ips` - Array of blocked IPs with metadata
- `jpkcom_hide_login_attempts_{hash}` - Integer, failed attempt counter per IP

### Plugin Updater (includes/class-plugin-updater.php)

Self-hosted GitHub-based update system:
- Fetches JSON manifest from GitHub Pages
- Integrates with WordPress plugin update API
- Provides "View Details" modal with plugin information
- Uses transient caching (24-hour TTL); failed manifest fetches are negatively cached for 1 h
- **SHA256 checksum verification is mandatory (fail closed):** a manifest without `checksum_sha256`, or one that cannot be fetched, aborts the update instead of installing unverified code
- The verified temp file is returned from `upgrader_pre_download`, so WordPress installs exactly the bytes that were hashed (no second download)
- Manifest URL: `https://jpkcom.github.io/jpkcom-hide-login/plugin_jpkcom-hide-login.json`

**Supply-chain: GitHub Actions sind auf Commit-SHAs gepinnt.** Alle `uses:`-Zeilen in `.github/workflows/` referenzieren einen 40-stelligen Commit-SHA statt eines Tags (`@v4`), mit der Version als Kommentar dahinter. Grund: ein Tag ist ein beweglicher Zeiger und lässt sich umhängen, ein SHA nicht. Da dieser Workflow die Plugin-ZIP **und** die SHA256-Summe erzeugt, der der Auto-Updater vertraut, würde eine kompromittierte Action ein manipuliertes ZIP samt passender Prüfsumme ausliefern — die Prüfsumme sichert den Transportweg, das Pinning den Build. `.github/dependabot.yml` hält die Pins wöchentlich aktuell (ein gesammelter PR). Beim Aktualisieren immer SHA *und* Versionskommentar zusammen ändern.

**CI & Dependabot-Auto-Merge.** Zwei zusätzliche Workflows:

- `.github/workflows/ci.yml` — läuft auf jedem `pull_request`. Prüft: `php -l` über alle PHP-Dateien; ungültige benannte Argumente an internen PHP-Funktionen (fängt die Klasse `sprintf(format:, values:)` → `ArgumentCountError`, die `php -l` nicht sieht); YAML-Validität aller `.github`-Dateien; und dass jede Action auf einem 40-stelligen Commit-SHA gepinnt ist (beide YAML-Formen, `uses:` und `- uses:`).
- `.github/workflows/dependabot-auto-merge.yml` — merged Dependabot-PRs automatisch, aber nur `semver-patch` und `semver-minor`. Major-Updates bekommen stattdessen einen Kommentar und bleiben manuell. Greift nur bei PRs von `dependabot[bot]` aus diesem Repo, nie aus Forks.

> **Zwei Repo-Einstellungen sind Voraussetzung, sonst ist der Auto-Merge wirkungslos oder gefährlich:**
> 1. **„Allow auto-merge"** muss in den Repo-Settings aktiv sein.
> 2. Der Branch-Schutz muss den CI-Job als **Required status check** führen (`CI / Lint & Guards`). Fehlt das, merged `gh pr merge --auto` **sofort** — es gibt dann nichts, worauf es warten müsste, und die CI wäre reine Dekoration.

Zusammen mit `cooldown: default-days: 7` in der `dependabot.yml` heißt das: kein Action-Release wird in seiner ersten Woche übernommen, patch/minor laufen danach automatisch durch (sofern CI grün), major bleibt eine bewusste Entscheidung.



## Development Commands

### Testing the Plugin

Since this is a WordPress plugin, testing requires a WordPress installation:

```bash
# Symlink plugin into WordPress installation
ln -s /path/to/jpkcom-hide-login /path/to/wordpress/wp-content/plugins/

# Access WordPress admin to activate plugin
# Default login URL after activation: /jpkcom-login
```

### Build & Release

The plugin uses GitHub Actions for automated releases:

```bash
# Create a new release (triggers .github/workflows/release.yml)
git tag -a v1.1.0 -m "Release version 1.1.0"
git push origin v1.1.0
```

The release workflow automatically:
1. Builds plugin ZIP (excluding .git, .github, .gitignore)
2. Uploads ZIP to GitHub release
3. Generates JSON manifest from README.md metadata
4. Deploys manifest + documentation to GitHub Pages

### WP-CLI Testing (if available)

```bash
# Install plugin via WP-CLI
wp plugin install jpkcom-hide-login.zip --activate

# Check plugin status
wp plugin list

# Update site option (per-site slug)
wp option update jpkcom_hide_login_slug "my-custom-login"

# Update network option (multisite)
wp site option update jpkcom_hide_login_network_slug "network-login"

# Add IP to whitelist
wp option patch insert jpkcom_hide_login_ip_whitelist '["192.168.1.100"]'
```

## Important Implementation Details

### Why No `$_SERVER` Manipulation?

**Previous approach (problematic):**
```php
$_SERVER['SCRIPT_NAME'] = '/wp-login.php';
$_SERVER['PHP_SELF'] = '/wp-login.php';
$_SERVER['REQUEST_URI'] = '/wp-login.php';
```

**Current approach (working):**
```php
global $error, $interim_login, $action, $user_login, $user, $redirect_to;
$GLOBALS['pagenow'] = 'wp-login.php';
require_once ABSPATH . 'wp-login.php';
```

**Why this works:**
- WordPress checks `$GLOBALS['pagenow']` to determine current page
- No need to manipulate `$_SERVER` variables
- Prevents conflicts with WordPress core functionality
- Avoids redirect loops and white screens
- Based on proven pattern from professional security plugins

### URL Filtering Strategy

The plugin filters URLs at multiple points:
1. `login_url`, `logout_url`, `lostpassword_url`, `register_url` filters
2. `site_url` and `network_site_url` filters (priority 100)
3. Password reset action hooks (`login_form_rp`, `login_form_resetpass`)
4. WooCommerce-specific filters

**Critical:** Filters check `$GLOBALS['pagenow']` to avoid filtering when actually serving wp-login.php.

### CIDR Range Support

The IP Manager supports CIDR notation for whitelisting IP ranges:

```php
// Examples:
192.168.1.100      // Single IP
192.168.1.0/24     // 192.168.1.1 - 192.168.1.254
10.0.0.0/8         // 10.0.0.0 - 10.255.255.255
```

Implementation in `ip_in_range()` method uses bitwise operations:
```php
$ip_long = ip2long($ip);
$subnet_long = ip2long($subnet);
$mask_long = -1 << (32 - (int)$mask);
return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
```

### Brute Force Protection Flow

1. User attempts login with wrong credentials
2. `wp_login_failed` hook fires → `handle_failed_login()`
3. Increment attempt counter (transient, configurable TTL)
4. If attempts >= max_attempts (configurable), add IP to blocklist (transient, configurable TTL)
5. Next login attempt: `authenticate` filter checks blocklist first
6. If blocked, return `WP_Error` before authentication
7. On successful login: `wp_login` hook clears attempt counter

**Customizable Settings** (stored in WordPress options):
- `jpkcom_hide_login_max_attempts` - Maximum login attempts (default: 5, range: 1-100)
- `jpkcom_hide_login_attempt_window` - Attempt tracking window in seconds (default: 60, range: 1-3600)
- `jpkcom_hide_login_block_duration` - Block duration in seconds (default: 600, range: 1-86400)

## Coding Standards

- **PHP Version:** Uses PHP 8.3+ features (strict typing, constructor property promotion, named parameters)
- **Strict Types:** `declare(strict_types=1);` enabled in all files
- **WordPress APIs:** Uses WordPress core functions exclusively (minimal direct database queries only for slug existence check and transient cleanup)
- **Escaping:** All output is escaped (`esc_html()`, `esc_attr()`, `esc_url()`)
- **Nonce Verification:** Admin forms use nonce verification (`check_admin_referer()`, `wp_nonce_field()`)
- **Hooks:** All functionality attached via WordPress hooks (no global scope pollution)
- **Type Safety:** All methods have type hints for parameters and return values
- **PHPDoc:** All classes, methods, and properties have comprehensive PHPDoc comments

## Common Modification Points

**Change default slug:**
Modify `JPKCOM_HIDE_LOGIN_DEFAULT_SLUG` constant (jpkcom-hide-login.php:40) or override in `wp-config.php`.

**Adjust brute force thresholds:**
Via Admin UI: Navigate to **Settings → Hide Login → Brute Force Protection Settings**
Via WP-CLI:
```bash
wp jpkcom-hide-login protection max-attempts 10
wp jpkcom-hide-login protection attempt-window 120
wp jpkcom-hide-login protection block-duration 1800
```

Or programmatically using setters:
```php
$login_protection->set_max_attempts(10);
$login_protection->set_attempt_window(120);
$login_protection->set_block_duration(1800); // 30 minutes
```

**Manual database cleanup:**
Cleanup expired login attempt transients manually:
```bash
wp jpkcom-hide-login cleanup
```
Note: This also runs automatically once per day via WordPress Cron.

**Customize admin notices:**
Modify admin_notices hooks in jpkcom-hide-login.php (lines 177-255)

**Update manifest URL:**
Modify updater initialization (jpkcom-hide-login.php:107-113)

**Add custom URL filters:**
Add filters in `JPKCom_Hide_Login_Mask_Login::init_hooks()` method

## Plugin Compatibility

### WooCommerce
- Fully compatible with WooCommerce my-account pages
- WooCommerce login/logout/registration forms work seamlessly
- WooCommerce AJAX requests are not blocked
- Custom logout redirect prevents wp-login.php exposure
- Filter: `woocommerce_logout_default_redirect_url`

### Multisite
- Network-wide slug configuration supported
- wp-signup.php automatically redirected to custom slug with ?action=signup
- Signup URLs filtered via `wp_signup_location` hook
- Per-site configuration available when network setting not active
- Network admin settings page in Network Admin → Settings

### Known Compatible Plugins
- WooCommerce (tested with 8.0+)
- Multisite User Management plugins (via wp_signup_location filter)
- Most caching plugins (plugin uses standard WordPress hooks)
- Most security plugins (except those that also modify login URLs)

### Potential Conflicts
- Plugins that hardcode wp-login.php URLs without using WordPress filters may not work
- Security plugins that also modify login URLs will conflict (disable one or the other)
- Custom authentication plugins that bypass WordPress core may need adjustment
- Plugins that manipulate `$_SERVER` variables may cause issues

## Troubleshooting

### White screen on custom login URL

Check PHP error log for errors. Common causes:
- PHP version < 8.3
- WordPress version < 6.9
- Memory limit too low
- Plugin conflict

### 404 on wp-admin after login

Clear browser cache and cookies. WordPress might be caching redirect URLs.

### Cannot access settings page

Ensure user has `manage_options` capability. Network admins should access network settings page.

### IP blocking not working

- Check if IP detection works: view current IP in admin settings
- Verify attempts are being counted: `define( 'JPKCOM_HIDE_LOGIN_DEBUG', true );` and check the debug log
- Ensure WordPress transients are working (check caching plugins)

### Custom slug not saving

- Check for conflicting page/post slugs
- Verify slug is not in forbidden list
- Check browser console for JavaScript errors
- Temporarily disable other plugins

## Emergency Recovery

If locked out completely:

### Method 1: Database Access
```sql
-- View current slug
SELECT option_value FROM wp_options WHERE option_name = 'jpkcom_hide_login_slug';

-- Reset to default
UPDATE wp_options SET option_value = 'jpkcom-login' WHERE option_name = 'jpkcom_hide_login_slug';

-- Clear all blocks
DELETE FROM wp_options WHERE option_name LIKE 'jpkcom_hide_login_blocked_ips';

-- Add current IP to whitelist
UPDATE wp_options SET option_value = '["YOUR.IP.HERE"]' WHERE option_name = 'jpkcom_hide_login_ip_whitelist';
```

### Method 2: wp-config.php
```php
define('JPKCOM_HIDE_LOGIN_DEFAULT_SLUG', 'emergency-access');
```

### Method 3: Disable Plugin
Rename plugin folder via FTP:
```
/wp-content/plugins/jpkcom-hide-login/
→ /wp-content/plugins/jpkcom-hide-login-disabled/
```

## Testing Checklist

- [ ] Custom slug saves correctly
- [ ] Old URLs (wp-login.php, wp-admin) show 404
- [ ] Custom login URL shows login form
- [ ] Login works with correct credentials
- [ ] Failed login shows remaining attempts
- [ ] Customizable brute force settings save correctly
- [ ] Max attempts threshold works as configured
- [ ] Attempt window works as configured
- [ ] Block duration works as configured
- [ ] Blocked IP shown in admin interface
- [ ] Clear blocked IPs button works
- [ ] Logout redirects to custom URL
- [ ] Password reset emails use custom URL
- [ ] Password reset links work
- [ ] IP whitelist prevents blocking
- [ ] CIDR ranges work in whitelist
- [ ] REST API not blocked
- [ ] AJAX requests not blocked
- [ ] WooCommerce checkout works
- [ ] Multisite network settings work
- [ ] Per-site settings work in multisite
- [ ] WP-CLI commands work correctly
- [ ] WP-CLI status displays correct information
- [ ] WP-CLI slug management works
- [ ] WP-CLI whitelist management works
- [ ] WP-CLI blocked IP management works
- [ ] WP-CLI protection settings work
- [ ] WP-CLI cleanup command works
- [ ] WordPress Cron cleanup event is scheduled on activation
- [ ] WordPress Cron cleanup event is cleared on deactivation

## Version History

- **1.2.7** (2026-07-28) - Fixed the malformed `.l10n.php` plural entries (fatal 500 on the second failed login on German sites), blocked `wp-signup.php` on single sites (it disclosed the secret slug via `wp_registration_url()`), stopped blocks renewing themselves on every retry, made all hook callbacks tolerate foreign argument shapes, added the reverse-proxy warning to the settings screen, aligned the runtime version check with the header, registered the `get-slug` / `set-slug` WP-CLI subcommands, moved request tracing to `JPKCOM_HIDE_LOGIN_DEBUG`, cleared all Plugin Check findings
- **1.2.0** (2025-11-12) - Added customizable brute force thresholds, WP-CLI commands for management, automatic database cleanup via WordPress Cron
- **1.1.0** (2025-11-02) - Complete rewrite with modular architecture, IP whitelist, enhanced brute force protection
- **1.0.0** (2024-10-01) - Initial release
