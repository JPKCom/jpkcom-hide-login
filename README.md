# JPKCom Hide Login

**Plugin Name:** JPKCom Hide Login  
**Plugin URI:** https://github.com/JPKCom/jpkcom-hide-login  
**Description:** Rename the WordPress login URL to a custom slug for enhanced security. Includes brute force protection and IP whitelist management.  
**Version:** 1.2.0  
**Author:** Jean Pierre Kolb <jpk@jpkc.com>  
**Author URI:** https://www.jpkc.com/  
**Contributors:** JPKCom  
**Tags:** Login, Security, Brute Force Protection, Hide Login, Custom Login URL  
**Requires at least:** 6.8  
**Tested up to:** 6.9  
**Requires PHP:** 8.3  
**Network:** true  
**Stable tag:** 1.2.0  
**License:** GPL-2.0+  
**License URI:** http://www.gnu.org/licenses/gpl-2.0.txt  
**Text Domain:** jpkcom-hide-login  
**Domain Path:** /languages

Rename the default WordPress login URL (wp-login.php) to a custom slug for enhanced security with built-in brute force protection and IP management.

---

## Description

**JPKCom Hide Login** is a security plugin that allows you to completely hide your WordPress login page by replacing the default `wp-login.php` URL with a custom slug of your choice. This significantly improves your site's security by preventing automated bot attacks and brute force attempts on the default login URL.

### Key Features

- **Custom Login URL** - Replace `wp-login.php` with any custom slug (e.g., `/secure-login/`)
- **Brute Force Protection** - Automatically block IPs after failed login attempts with customizable thresholds
- **Customizable Security Thresholds** - Configure max attempts, attempt window, and block duration
- **IP Whitelist Management** - Add trusted IPs that will never be blocked (supports CIDR ranges)
- **WP-CLI Support** - Full command-line management via WP-CLI commands
- **WordPress Multisite Support** - Network-wide settings for all sites or per-site configuration
- **WooCommerce Compatible** - Works seamlessly with WooCommerce login/logout
- **REST API Safe** - Does not interfere with REST API or AJAX requests
- **No Core File Modifications** - Uses only WordPress filters and hooks
- **Fully Translatable** - Ready for translation (Text Domain: `jpkcom-hide-login`)
- **Clean Uninstall** - Completely reversible, no database pollution

### How It Works

Once activated, the plugin:

1. **Blocks all direct access** to `wp-login.php` and `wp-admin` for non-logged-in users with a 404 response
2. **Creates a custom login URL** (default: `/jpkcom-login/`) that serves the WordPress login page
3. **Tracks failed login attempts** and automatically blocks IPs after threshold is reached
4. **Allows whitelisting of trusted IPs** to prevent legitimate users from being blocked
5. **Provides a comprehensive admin interface** for managing all settings and viewing blocked IPs

### Security Benefits

- **Protects against automated attacks** - Bots scanning for `/wp-login.php` will receive a 404 error
- **Prevents brute force attacks** - Automatic IP blocking after multiple failed attempts
- **Reduces server load** - Fewer malicious requests reaching your login page
- **Customizable security** - Whitelist your own IPs for safe administration
- **No information disclosure** - Blocked requests receive generic 404 responses

---

## Installation

### Automatic Installation (Recommended)

1. Download the plugin ZIP file from GitHub or your source
2. Go to **Plugins → Add New → Upload Plugin** in your WordPress admin
3. Choose the ZIP file and click **Install Now**
4. Click **Activate Plugin**

### Manual Installation via FTP

1. Download and extract the plugin ZIP file
2. Upload the `jpkcom-hide-login` folder to `/wp-content/plugins/`
3. Activate the plugin through the **Plugins** menu in WordPress

### After Activation

1. You'll see a success notice showing your new login URL (default: `https://yourdomain.com/jpkcom-login/`)
2. **Bookmark this URL immediately!**
3. Go to **Settings → Hide Login** to customize your settings
4. (Optional) Add your IP to the whitelist to prevent accidental lockout

---

### Configuration

#### Basic Settings

Navigate to **Settings → Hide Login** in your WordPress admin.

##### Custom Login Slug

1. Enter your desired slug in the **Custom Login URL Slug** field
2. Avoid using these forbidden slugs:
   - `login`, `admin`, `dashboard`, `wp-admin`, `wp-login`
3. The slug cannot be the same as an existing page or post URL
4. Click **Save Changes**

Your new login URL will be: `https://yourdomain.com/your-custom-slug/`

#### Brute Force Protection

**Automatic Protection** - Fully customizable!

- Default settings: **5 failed login attempts** within **60 seconds** blocks the IP for **10 minutes**
- **Customize thresholds** via admin interface: max attempts, attempt window, and block duration
- Blocked IPs are shown in the admin interface with expiration times
- View currently blocked IPs under **Currently Blocked IPs** section
- Click **Clear All Blocked IPs** to manually unblock all IPs

#### IP Whitelist Management

Prevent trusted IPs from being blocked:

1. Go to **Settings → Hide Login**
2. Scroll to **IP Whitelist** section
3. Your current IP is displayed for reference
4. Enter an IP address or CIDR range (e.g., `192.168.1.0/24`)
5. Click **Add to Whitelist**

**Whitelisted IPs:**
- Will never be blocked by brute force protection
- Can access the login page even after failed attempts
- Can be removed at any time using the **Remove** button

**CIDR Range Examples:**
- Single IP: `192.168.1.100`
- Subnet: `192.168.1.0/24` (192.168.1.1 - 192.168.1.254)
- Large range: `10.0.0.0/8` (10.0.0.0 - 10.255.255.255)

#### Multisite Configuration

For **WordPress Multisite** installations:

##### Network-Wide Settings

1. Go to **Network Admin → Settings → Hide Login (Network)**
2. Set a global slug for all sites in the network
3. Leave empty to allow each site to use its own slug

##### Per-Site Settings

1. Each site can still access **Settings → Hide Login**
2. If a network-wide slug is set, it takes priority
3. Sites will see a notice indicating network-wide settings are active

#### WP-CLI Commands

Manage the plugin via command line with **WP-CLI**:

##### Plugin Status

```bash
# Display current configuration and status
wp jpkcom-hide-login status
```

##### Login Slug Management

```bash
# Get current login slug
wp jpkcom-hide-login get-slug

# Set new login slug
wp jpkcom-hide-login set-slug my-secure-login
```

##### IP Whitelist Management

```bash
# List all whitelisted IPs
wp jpkcom-hide-login whitelist list

# Add IP to whitelist (supports CIDR)
wp jpkcom-hide-login whitelist add 192.168.1.100
wp jpkcom-hide-login whitelist add 192.168.1.0/24

# Remove IP from whitelist
wp jpkcom-hide-login whitelist remove 192.168.1.100
```

##### Blocked IPs Management

```bash
# List currently blocked IPs
wp jpkcom-hide-login blocked list

# Clear all blocked IPs
wp jpkcom-hide-login blocked clear
```

##### Brute Force Protection Settings

```bash
# Set maximum login attempts (1-100)
wp jpkcom-hide-login protection max-attempts 10

# Set attempt tracking window in seconds (1-3600)
wp jpkcom-hide-login protection attempt-window 120

# Set block duration in seconds (1-86400)
wp jpkcom-hide-login protection block-duration 1800
```

##### Database Cleanup

```bash
# Manually cleanup expired login attempt data
# (This also runs automatically once per day via WordPress Cron)
wp jpkcom-hide-login cleanup
```

---

## FAQ

### I activated the plugin but can't find the login page!

The **default login URL** after activation is:

```
https://yourdomain.com/jpkcom-login/
```

If you changed the slug in the settings, use your custom URL instead.

**Recovery Methods:**

1. **Check your admin bar** (if still logged in) - go to Settings → Hide Login
2. **Check your browser bookmarks** for the saved login URL
3. **Disable the plugin via FTP** - rename the folder:
   ```
   /wp-content/plugins/jpkcom-hide-login/
   ```
   to
   ```
   /wp-content/plugins/jpkcom-hide-login-disabled/
   ```
4. **Add emergency slug to wp-config.php**:
   ```php
   define('JPKCOM_HIDE_LOGIN_DEFAULT_SLUG', 'emergency-login');
   ```

### I'm locked out due to IP blocking! How do I recover?

If you're blocked after too many failed login attempts:

#### Method 1: Wait 10 Minutes
The block automatically expires after 10 minutes.

#### Method 2: Add IP to Whitelist via Database

Execute this SQL query in phpMyAdmin or your database tool:

```sql
UPDATE wp_options
SET option_value = '["YOUR.IP.ADDRESS"]'
WHERE option_name = 'jpkcom_hide_login_ip_whitelist';
```

Replace `YOUR.IP.ADDRESS` with your actual IP address.

#### Method 3: Clear All Blocks via Database

```sql
DELETE FROM wp_options
WHERE option_name = 'jpkcom_hide_login_blocked_ips';
```

### Can I use this plugin on Multisite?

**Yes!** The plugin fully supports WordPress Multisite with two configuration modes:

1. **Network-wide slug** - Set one login URL for all sites
2. **Per-site slugs** - Let each site administrator set their own custom slug

Network administrators can access network settings at:
**Network Admin → Settings → Hide Login (Network)**

### What happens if someone tries to access wp-login.php?

They receive a **404 Not Found** error with no indication that the login page exists elsewhere. This provides better security than redirecting or showing a 403 error.

After **5 attempts within 60 seconds**, the IP is blocked for **10 minutes** with no further access to the site.

### Does this affect WordPress REST API or AJAX?

**No.** The plugin intelligently detects and allows:

- WordPress REST API requests
- Admin AJAX calls (`admin-ajax.php`)
- WooCommerce AJAX requests
- Other legitimate background requests

Only direct browser access to `wp-login.php` and `wp-admin` is blocked for non-logged-in users.

### Is it compatible with WooCommerce?

**Yes!** The plugin includes special compatibility for WooCommerce:

- My Account login forms work correctly
- Login/logout redirects are properly handled
- Checkout login is not affected
- WooCommerce AJAX requests are never blocked

### Can I customize the number of attempts or block duration?

**Yes!** All brute force protection thresholds are fully customizable:

Navigate to **Settings → Hide Login** and scroll to **Brute Force Protection Settings** to configure:

- **Maximum Login Attempts** (1-100) - Default: 5
- **Attempt Window** (1-3600 seconds) - Default: 60 seconds
- **Block Duration** (1-86400 seconds / 24 hours) - Default: 600 seconds (10 minutes)

You can also configure these settings via WP-CLI:

```bash
wp jpkcom-hide-login protection max-attempts 10
wp jpkcom-hide-login protection attempt-window 120
wp jpkcom-hide-login protection block-duration 1800
```

### Does this plugin modify core WordPress files?

**No.** The plugin uses only WordPress hooks and filters. It does not modify:
- `wp-login.php`
- `wp-admin` files
- Core WordPress files

This means WordPress updates are completely safe and won't break the plugin.

### Can I override default values in wp-config.php?

**Yes!** Add these constants to `wp-config.php` (before `/* That's all, stop editing! */`):

```php
// Custom default login slug
define( 'JPKCOM_HIDE_LOGIN_DEFAULT_SLUG', 'my-secret-login' );

// Custom option name for per-site slug
define( 'JPKCOM_HIDE_LOGIN_OPTION', 'my_custom_login_slug' );

// Custom option name for network slug (Multisite)
define( 'JPKCOM_HIDE_LOGIN_NETWORK_OPTION', 'my_network_login_slug' );
```

### Will this affect password reset emails?

**No.** Password reset emails automatically use the custom login URL. When users click the reset link, they're redirected to your custom slug with the reset token intact.

### Can I use this with other security plugins?

**Generally yes**, but avoid using multiple plugins that:
- Also hide the login URL (conflict)
- Implement their own brute force protection (may interfere)

Compatible with:
- Wordfence (disable Login Security features)
- Sucuri Security
- iThemes Security (disable Login URL changing)
- All in One WP Security (disable Login Page changing)

---

### Troubleshooting

#### Login page shows a white screen

This usually means there's a PHP error. Check your error logs:

1. Enable debugging in `wp-config.php`:
   ```php
   define( 'WP_DEBUG', true );
   define( 'WP_DEBUG_LOG', true );
   define( 'WP_DEBUG_DISPLAY', false );
   ```
2. Check `/wp-content/debug.log` for errors
3. Report any errors to the plugin support

#### Settings page doesn't save changes

1. Check that you have `manage_options` capability
2. Verify the slug doesn't conflict with existing pages
3. Check for JavaScript errors in browser console
4. Temporarily disable other plugins to identify conflicts

#### Logged in but still see 404 on wp-admin

This shouldn't happen. Possible causes:

1. Browser cache - Clear your browser cache and cookies
2. Plugin conflict - Temporarily disable other security plugins
3. Permalink structure - Go to **Settings → Permalinks** and click **Save Changes**

#### After logout, redirected to 404 page

The logout redirect should automatically use the custom login URL. If not:

1. Check if any other plugin is filtering `logout_redirect`
2. Temporarily disable other plugins
3. Report the issue with details about your WordPress version and active plugins

---

### Technical Details

#### Architecture

The plugin uses a modular, object-oriented architecture:

```
jpkcom-hide-login/
├── jpkcom-hide-login.php          # Bootstrap & initialization
└── includes/
    ├── class-ip-manager.php       # IP whitelist/blocklist management
    ├── class-login-protection.php # Brute force protection
    ├── class-mask-login.php       # Login URL masking
    ├── class-admin-settings.php   # Admin interface
    └── class-plugin-updater.php   # GitHub-based updates
```

#### Database Usage

The plugin uses WordPress options and transients:

**Options:**
- `jpkcom_hide_login_slug` - Per-site custom slug
- `jpkcom_hide_login_network_slug` - Network-wide slug (Multisite)
- `jpkcom_hide_login_ip_whitelist` - Array of whitelisted IPs
- `jpkcom_hide_login_notice_shown` - First-time activation notice flag

**Transients:**
- `jpkcom_hide_login_blocked_ips` - Currently blocked IP list with expiration
- `jpkcom_hide_login_attempts_{hash}` - Failed login attempt counters per IP

**Automatic Cleanup:**
- Expired login attempt transients are automatically cleaned up daily via WordPress Cron
- Manual cleanup available via WP-CLI: `wp jpkcom-hide-login cleanup`
- All data is removed on plugin deactivation

#### PHP Requirements

- **PHP 8.3+**

#### WordPress Compatibility

- **WordPress 6.8+** - Tested with latest WordPress versions
- **Multisite** - Full support for network activation
- **WooCommerce** - Compatible with WooCommerce 8.0+

---

## Changelog

### 1.2.0 (2025-11-12)

#### Added
- **IP Whitelist Management** - Add trusted IPs that will never be blocked
- **CIDR Range Support** - Whitelist entire IP ranges (e.g., `192.168.1.0/24`)
- **Enhanced Admin Interface** - Professional settings page with all features
- **Blocked IP Viewer** - See currently blocked IPs with expiration times
- **Brute Force Protection** - Automatic IP blocking after failed login attempts
- **Customizable Protection Thresholds** - Configure max attempts, attempt window, and block duration
- **Login Attempt Counter** - Shows remaining attempts on failed logins
- **Current IP Display** - See your current IP in admin settings
- **One-Click Block Clearing** - Clear all blocked IPs with a button
- **Automatic Database Cleanup** - Daily WordPress Cron job removes expired login attempt data
- **WP-CLI Cleanup Command** - Manual database cleanup via `wp jpkcom-hide-login cleanup`
- **Full WP-CLI Support** - Complete command-line management for all plugin features

…

### 1.0.0 (2024-11-30)

- Initial Release
- Basic login URL masking
- Simple IP blocking
- Multisite support
- Basic admin settings

---
