==== Security Hardener ===
Contributors: marc4
Tags: security, hardening, headers, brute force, login protection
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 8.0
Stable tag: 0.8
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Basic hardening: secure headers, user enumeration blocking, generic login errors, IP-based rate limiting, and WordPress security improvements.

== Description ==

**Security Hardener** implements the official WordPress hardening guidelines from the [WordPress Advanced Administration / Security / Hardening](https://developer.wordpress.org/advanced-administration/security/hardening/) documentation. It uses WordPress core functions and follows best practices without modifying core files.

= Key Features =

**File Security:**
* Disable file editor in WordPress admin
* Optionally disable all file modifications (blocks updates - use with caution)

**XML-RPC Protection:**
* Disable XML-RPC completely (enabled by default)
* Remove pingback methods
* Disable self-pingbacks

**User Enumeration Protection:**
* Block `/?author=N` queries (returns 404)
* Secure REST API user endpoints (require authentication)
* Remove users from XML sitemaps
* Prevent canonical redirects that expose usernames

**Login Security:**
* Generic error messages (no username/password hints)
* IP-based rate limiting with configurable thresholds
* Security event logging (last 100 events)
* Automatic blocking after failed attempts

**Security Headers:**
* `X-Frame-Options: SAMEORIGIN` (clickjacking protection)
* `X-Content-Type-Options: nosniff` (MIME sniffing protection)
* `Referrer-Policy: strict-origin-when-cross-origin`
* `Permissions-Policy` (restricts geolocation, microphone, camera)
* Optional HSTS (HTTP Strict Transport Security) for HTTPS sites

**Additional Hardening:**
* Hide WordPress version
* Clean up `wp_head` output
* Remove unnecessary meta tags and links
* Security event logging system

> ⚠️ **Important:** Always test security settings in a staging environment first. Some features may affect third-party integrations or plugins.

**Privacy:** This plugin does not send data to external services and does not create custom database tables. It stores plugin settings and a security event log in the WordPress options table, and uses transients for temporary login attempt tracking. All data is deleted on uninstall.

== Installation ==

= Automatic Installation =

1. Go to **Plugins > Add New Plugin**
2. Search for **Security Hardener**
3. Click **Install Now** and then **Activate**
4. Configure settings at **Settings > Security Hardener**

== Frequently Asked Questions ==

= What are the default settings? =

By default, the plugin enables:
* File editor disabled
* XML-RPC disabled
* User enumeration blocking
* Generic login errors
* Login rate limiting (5 attempts per 15 minutes)
* Security headers
* WordPress version hiding
* Clean wp_head output
* Security event logging

HSTS is disabled by default and should only be enabled if your entire site uses HTTPS.

= Does this plugin slow down my site? =

No. The plugin uses lightweight WordPress hooks and native functions. Security headers add negligible overhead, and rate limiting only checks transients during login attempts.

= I use a CDN or proxy (Cloudflare, etc.). How do I get the correct IP? =

By default, rate limiting uses `REMOTE_ADDR`. If behind a trusted proxy, add this to `wp-config.php`:

`define('WPSH_TRUSTED_PROXIES', array(
    '173.245.48.0',  // Example: Cloudflare IP range
    // Add your proxy IPs here
));`

The plugin will then check `HTTP_CF_CONNECTING_IP` (Cloudflare) or `HTTP_X_FORWARDED_FOR` headers.

= What headers does this plugin add? =

When security headers are enabled:
* `X-Frame-Options: SAMEORIGIN`
* `X-Content-Type-Options: nosniff`
* `Referrer-Policy: strict-origin-when-cross-origin`
* `Permissions-Policy: geolocation=(), microphone=(), camera=()`

When HSTS is enabled (HTTPS only):
* `Strict-Transport-Security: max-age=31536000; includeSubDomains` (configurable)

= Does the plugin work with page caching? =

Yes. Security headers are sent at the PHP level before caching. However, if you use aggressive server-level caching, you may need to configure your cache to allow these headers through.

= Can I use this with other security plugins? =

Yes, but be careful of conflicts. If another plugin also:
* Sends security headers, you may get duplicates (usually harmless)
* Blocks user enumeration, one should be disabled
* Has login rate limiting, choose one to avoid confusion

This plugin is designed to be lightweight and focused on core WordPress hardening.

= What happens to my data when I uninstall? =

When you **uninstall** (not just deactivate) the plugin:
* All plugin settings are deleted
* All security logs are deleted
* All login rate limiting transients are cleared
* Your WordPress installation is returned to its default state

**Note:** Deactivating the plugin preserves all settings.

= Does this block the WordPress REST API? =

No. The plugin only secures user-related endpoints by requiring authentication. All other REST API functionality works normally. Public endpoints like oEmbed continue to work.

= I'm locked out after too many failed attempts. What do I do? =

Failed login blocks expire automatically based on your configured window (default: 15 minutes). Wait for the block period to expire, or:

1. Access your database (phpMyAdmin, etc.)
2. Search for options with `_transient_wpsh_login_` in the name
3. Delete those transient options
4. Try logging in again

= How do I know if the plugin is working? =

1. Check **Settings > Security Hardener** for active features
2. Review the "Recent Security Events" log
3. Use browser dev tools to inspect HTTP headers
4. Try accessing `/?author=1` (should return 404 if blocking is enabled)
5. Test failed login attempts to verify rate limiting

= Does this plugin require HTTPS? =

Not required, but **strongly recommended**. HSTS features require HTTPS. For maximum security, your entire site should use HTTPS with a valid SSL certificate.

= Is this plugin compatible with multisite? =

The plugin is designed for single-site installations. Multisite compatibility has not been tested and is not officially supported at this time.

== Changelog ==

= 0.8 - 2026-02-26 =
* Improved: Moved define_security_constants() from plugins_loaded hook to the constructor, ensuring DISALLOW_FILE_EDIT and DISALLOW_FILE_MODS are defined as early as possible in the WordPress lifecycle
* Improved: Expanded @param docblock for render_checkbox_field() to document all $args keys
* Added: WordPress Playground blueprint (assets/blueprints/blueprint.json) enabling live plugin preview directly from the WordPress.org plugin directory
* Fixed: Plugin header description updated to remove REST API restriction option removed in 0.5
* Fixed: Removed stale phpcs:ignore comment in show_admin_notices() — nonce verification is now correctly documented inline
* Fixed: Wrapped login block error message with wp_kses_post() for consistent output escaping
* Fixed: Added esc_url() and esc_html__() to add_settings_link() sprintf output
* Fixed: Removed redundant get_client_ip() call in log_security_event() — IP resolved once per event
* Fixed: Added autoload=false to wpsh_security_logs option — logs are only needed on the settings page, not loaded on every request

= 0.7 - 2026-02-21 =
* Fixed: WPSH_VERSION constant updated to match plugin header version
* Fixed: Added wp_unslash() and sanitize_text_field() to $_GET['author'] in prevent_author_redirect()
* Fixed: Moved HTML markup outside translatable strings in generic_login_errors(), check_login_rate_limit(), and field descriptions for "Disable all file modifications" and "Enable HSTS"
* Security: Added CSRF protection to "Clear Logs" action via wp_nonce_url() and wp_verify_nonce()
* Improved: Added missing hardening recommendations to admin page: BasicAuth protection for wp-admin and changing the default database table prefix
* Fixed: Corrected date format in changelog entries (YYYY-MM-DD)

= 0.6 - 2026-02-21 =
* Fixed: Removed deprecated load_plugin_textdomain() call (automatic since WordPress 4.6)
* Fixed: Added wp_unslash() and sanitize_text_field() to $_GET['author'] before sanitization
* Fixed: Moved HTML markup outside translatable string in login confirmation message
* Fixed: Escaped $min and $max output in render_number_field() using absint()
* Fixed: Added phpcs:ignore for native WordPress constants DISALLOW_FILE_EDIT and DISALLOW_FILE_MODS
* Fixed: Removed error_log() debug call from uninstall.php
* Fixed: Suppressed false-positive direct database query warning in uninstall.php with inline justification comment
* Fixed: Removed redundant function_exists() check for wp_cache_flush() in uninstall.php

= 0.5 - 2026-02-09 =
* Complete rewrite following WordPress hardening best practices
* Increased minimum PHP requirement to 8.0 (PHP 7.4 is end-of-life)
* Added: Security event logging system (last 100 events)
* Added: File permission checking with admin notices
* Improved: User enumeration blocking (now also blocks REST endpoints and sitemaps)
* Improved: Rate limiting algorithm (more reliable, fewer race conditions)
* Improved: IP detection with proper proxy support via `WPSH_TRUSTED_PROXIES` constant
* Improved: Admin interface with better organization and descriptions
* Improved: Code quality following WordPress Coding Standards
* Removed: CSP (Content Security Policy) - requires per-site customization
* Removed: REST API restriction option - too broad, better handled per-case
* Fixed: All security vulnerabilities from previous versions
* Fixed: Proper sanitization and escaping throughout

= 0.3 - 2025-10-20 =
* Some corrections

= 0.2 - 2025-10-13 =
* Some corrections

= 0.1 - 2025-10-04 =
* Initial release