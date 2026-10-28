=== Security Hardener ===
Contributors: marc4
Tags: security, hardening, headers, brute force, login protection
Requires at least: 6.9
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 2.4.7
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Hardens WordPress with secure headers, login protection, user enumeration blocking, rate limiting, and a built-in security checklist.

== Description ==

**Security Hardener** applies WordPress security best practices based on the [WordPress Advanced Administration / Security / Hardening](https://developer.wordpress.org/advanced-administration/security/hardening/) documentation. It uses WordPress core functions and does not modify core files.

It is a hardening tool, not a firewall or a malware scanner: it reduces your attack surface, and its checklist points out measures that have to be applied on your server.

= Key Features =

**Files and updates:**
* Disable the file editor in WordPress admin
* Optionally disable all file modifications (blocks updates and installations)

**XML-RPC and pingbacks:**
* Disable XML-RPC completely, or keep it and remove only its pingback methods
* Remove the X-Pingback header and block incoming and self-pingbacks

**User enumeration:**
* Block `/?author=N` queries (returns 404) and the canonical redirects that expose usernames
* Require login for REST API user endpoints and remove users from XML sitemaps
* Optionally block author feed pages (`/author/username/feed/`)
* Optionally anonymize the author name in oEmbed responses

**Login security:**
* Generic error messages (no username/password hints)
* Login honeypot to silently block bots
* Block registration of unsafe usernames (admin, root, test…)
* Application Passwords disabled by default
* IP-based rate limiting with configurable thresholds
* Security event log (last 100 events, including IP addresses and usernames of failed attempts)

**Security headers:**
* `X-Frame-Options: SAMEORIGIN` and `X-Content-Type-Options: nosniff`
* `Referrer-Policy: strict-origin-when-cross-origin`
* `Permissions-Policy: geolocation=(), microphone=(), camera=()`
* Optional HSTS for HTTPS sites (max-age of 1 year, with optional `includeSubDomains` and `preload`)

**Additional hardening:**
* Hide the WordPress version (meta generator tag and asset query strings)
* Remove obsolete `wp_head` items (RSD, WLW manifest, shortlink, emoji scripts)
* System Status: file permissions, WP_DEBUG, user registration, administrator accounts, PHP version, and database version
* Interactive hardening checklist with saved progress, for measures that must be applied on your server

> ⚠️ **Important:** Always test security settings in a staging environment first. Some features may affect third-party integrations or plugins.

**Privacy:** This plugin does not send data to third parties and does not create custom database tables. It stores its settings, checklist progress, and a security event log in the WordPress options table. The log keeps the last 100 events, including IP addresses and the usernames used in failed login attempts, until you clear it. Login attempt tracking uses short-lived transients keyed by a hash of the IP address. The PHP check in System Status uses WordPress core's cached recommendation, which core may refresh from api.wordpress.org. All data is preserved on uninstall by default and only deleted if you explicitly enable "Delete all data on uninstall".

== Installation ==

= Automatic Installation =

1. Go to **Plugins > Add New Plugin**
2. Search for **Security Hardener**
3. Click **Install Now** and then **Activate**
4. Configure settings at **Settings > Security Hardener**

== Frequently Asked Questions ==

= What are the default settings? =

Everything is enabled by default except: disabling all file modifications, blocking author feeds, anonymizing the oEmbed author, HSTS (with its subdomains and preload options), and deleting data on uninstall. Rate limiting blocks an IP address for 15 minutes after 5 failed attempts. You can review and change every option under **Settings > Security Hardener**.

= An app or integration stopped working after I activated the plugin. What do I do? =

Two defaults can affect integrations: XML-RPC is disabled, and Application Passwords are disabled. If you use Jetpack, the WordPress mobile app, or other tools that rely on them, turn off **Disable XML-RPC** and/or **Disable Application Passwords** under **Settings > Security Hardener**.

= Does this plugin slow down my site? =

No. The plugin uses lightweight WordPress hooks and native functions. Security headers add negligible overhead, and rate limiting only checks transients during login attempts.

= I'm locked out after too many failed attempts. What do I do? =

Blocks are per IP address and expire automatically after your configured block duration (default: 15 minutes). Wait for the block to expire, try from a different IP address, or:

1. Access your database (phpMyAdmin, etc.)
2. Search the options table for names containing `wpsh_login_`
3. Delete those transient options
4. Try logging in again

If your site uses a persistent object cache (Redis, Memcached), flush the cache instead.

= I use a CDN or proxy (Cloudflare, etc.). How do I get the correct IP? =

By default, rate limiting uses `REMOTE_ADDR`. If your site is behind a trusted proxy, add the proxy's exact IP addresses to `wp-config.php` (IP ranges in CIDR notation are not supported):

`define( 'WPSH_TRUSTED_PROXIES', array( '203.0.113.10', '203.0.113.11' ) );`

For requests coming from those addresses, the plugin will then read the `HTTP_CF_CONNECTING_IP` (Cloudflare) or `HTTP_X_FORWARDED_FOR` header.

= Does the plugin work with page caching? =

It depends on the cache. Security headers are added by PHP when WordPress builds a response, so a full-page cache that serves pages without running PHP (some server-level caches do) may skip them. Check your response headers with your browser's developer tools and, if they are missing, add them at the server level.

= Can I use this with other security plugins? =

Yes, but watch for overlaps. If another plugin also sends security headers you may get duplicates (usually harmless). If it also blocks user enumeration or limits login attempts, enable only one of them to avoid confusion.

= Does this block the WordPress REST API? =

No. The plugin only requires login to read user-related endpoints, and WordPress's own permission checks still apply. All other REST API functionality, including public endpoints like oEmbed, works normally.

= What happens to my data when I uninstall? =

When you uninstall (not just deactivate) the plugin, data is preserved by default. If you enable **Delete all data on uninstall** under **Settings > Security Hardener > Other settings**, uninstalling deletes all plugin settings, security logs, and checklist progress. Temporary login-attempt data is not deleted right away: it expires on its own within 24 hours at most, and WordPress removes it automatically.

Deactivating the plugin always preserves all settings.

= Does this plugin require HTTPS? =

Not required, but strongly recommended. HSTS requires HTTPS, and for maximum security your entire site should use HTTPS with a valid certificate.

= Is this plugin compatible with multisite? =

The plugin is designed for single-site installations. Multisite compatibility has not been tested and is not officially supported at this time.

== Changelog ==

= 2.4.7 - 2026-10-28 =
* Fixed: Login honeypot now blocks the attempt even with valid credentials.
* Fixed: Checklist column divider in RTL languages.
* Fixed: Checklist no longer shows an item as saved when saving fails.
* Improved: Password reset no longer reveals whether an account exists.
* Improved: System Status checks.
* Improved: Security log shows the last 100 events in a scrollable box.
* Improved: Accessibility of the settings fields.
* Improved: Clear Logs now asks for confirmation.
* Updated: Some text improvements.

= 2.4.6 - 2026-10-27 =
* Security fix.
* Improved: System Status version checks.

= 2.4.5 - 2026-08-01 =
* Security fix.
* Improved: Security logs now show a message when empty instead of hiding the section.

= 2.4.4 - 2026-06-13 =
* Fixed: Security improvement in get_blocked_usernames().
* Fixed: Username length limited in security logs.
* Fixed: Type hints and docblock corrections.
* Updated: Some text improvements.
* Improved: Accessibility and UX improvements.

= 2.4.3 - 2026-05-25 =
* Updated: Tested up to WordPress 7.0.

= 2.4.2 - 2026-04-24 =
* Improved: Added RTL language support.
* Updated: Some text improvements.

= 2.4.1 - 2026-04-18 =
* Improved: System Status PHP version check now uses wp_check_php_version().
* Improved: System Status database version check now reads directly from wpdb.
* Improved: System Status administrator count now uses WP_User_Query with count_total.
* Improved: System Status PHP version and database version status messages are now consistent.
* Improved: System Status PHP and database checks now show yellow when below the recommended version, green when above.
* Fixed: Type hints added to get_option(), sanitize_options(), remove_xmlrpc_pingback(), remove_x_pingback(), and disable_self_pingbacks() for PHP 8.2+ consistency.
* Fixed: render_system_status() docblock updated to reflect all six checks.
* Fixed: WPSH_FILE constant removed — activation hooks now use __FILE__ directly.

= 2.4.0 - 2026-04-18 =
* Improved: Settings page reduced from 7 to 6 cards — HSTS options merged into Security headers card
* Improved: "Disable Application Passwords" moved to Login security card, between Block unsafe usernames and Login rate limiting
* Improved: System Status section now appears before Recent Security Events
* Improved: System Status expanded with four new checks — public user registration status, PHP version, number of administrator accounts, and database version
* Improved: System Status is now collapsible
* Improved: Hardening checklist now displays in two columns to reduce vertical space
* Improved: "Reset all" renamed to "Reset recommendations" and styled as a standard button for consistency with Clear Logs
* Improved: Removed persistent "Important" notice from the settings page header
* Improved: Added aria-label to all toggle inputs for screen reader accessibility
* Improved: Checklist items shortened to fit a single line in two-column layout
* Added: Four new checklist items — disable directory browsing, use SFTP instead of FTP, install plugins/themes from trusted sources only, keep active plugins minimal
* Removed: Two redundant checklist items — "Rename the default admin account" and "Disable WP_DEBUG on live sites"
* Fixed: AJAX checklist validation aligned with actual item count throughout

= 2.3.1 - 2026-04-17 =
* Fixed: Users with an existing unsafe username (e.g. admin) can now update their profile without being blocked — the restriction applies only to new user registration.

= 2.3.0 - 2026-04-17 =
* Added: Block unsafe usernames — prevents registration using commonly targeted usernames such as admin, root, test, or webmaster.
* Added: Anonymize oEmbed author — replaces the author name in oEmbed responses with the site name to prevent username exposure.
* Added: Two new items to the hardening checklist — remove wp-config.php backup files and remove publicly accessible database exports.
* Fixed: Honeypot POST check now uses sanitize_text_field() and wp_unslash(), resolving a PHPCS warning.
* Fixed: Duplicate wp_create_nonce() call removed from render_checklist().
* Fixed: block_author_feeds description updated to clarify it will break existing subscriptions, not merely affect them.
* Fixed: System Status table header corrected from "Check" to "Checks".
* Fixed: log_security_events fallback value normalized from true to 1 for consistency with the options array.

= 2.2.0 - 2026-04-01 =
* Added: Login honeypot — a hidden field added to the login form that silently blocks bots before any credential check.
* Added: Block author feeds — optionally blocks /author/username/feed/ pages that can confirm existing usernames.
* Added: Disable Application Passwords — disables REST API authentication via Application Passwords; enabled by default.
* Added: System Status section — replaces the separate File Permissions section; shows file permissions and WP_DEBUG status in a unified table, always visible with color-coded indicators.
* Added: Two new items to the hardening checklist — disable display_errors in PHP configuration, and disable WP_DEBUG_DISPLAY on live sites.

= 2.1.1 - 2026-03-29 =
* Improved: Interactive elements (toggles, checklist, progress bar) now use WordPress admin theme color variables.
* Fixed: "Settings saved." notice no longer appears twice after saving settings.
* Fixed: Checklist progress counter now stays translated when updated via AJAX.
* Fixed: Removed orphan comment from show_admin_notices().
* Fixed: Removed dead CSS for .wpsh-recommendations.

= 2.1.0 - 2026-03-26 =
* Added: Interactive hardening checklist — users can mark each recommendation as done.
* Improved: File permissions check moved from floating admin notice into the settings page.
* Fixed: "Enable preload" description now clarifies it only adds the preload directive to the HSTS header.
* Fixed: "Clean wp_head" description no longer uses HTML entities that rendered as literal text in some contexts.
* Fixed: wp-includes recommendation text no longer implies a code snippet follows.

= 2.0.2 - 2026-03-21 =
* Improved: Number fields now show allowed range as permanent help text (Min/Max) below the label.
* Fixed: Lost password flow now uses lostpassword_errors filter instead of login_messages.
* Fixed: "Clear Logs" replaced JavaScript confirm() with a proper POST form.
* Fixed: $_POST['wpsh_action'] sanitized with sanitize_key() before comparison, following WordPress Coding Standards.

= 2.0.1 - 2026-03-21 =
* Fixed: "Block user enumeration" description now mentions canonical redirect blocking
* Fixed: "Login rate limiting" toggle and number fields now have descriptions for consistency with all other options
* Fixed: Removed unused WPSH_DIR and WPSH_URL constants
* Fixed: Removed misleading inline comment about file editing in init()
* Fixed: readme — "Disable self-pingbacks" moved from XML-RPC section to its own Pingback Protection section
* Fixed: Unused parameters in clear_login_attempts() prefixed with underscore following WordPress Coding Standards
* Fixed: @return docblock for get_default_options() updated to array<string, int> for accuracy
* Fixed: Activation and deactivation log messages now pass through __() for translation
* Fixed: remove_login_hints() no longer relies on hardcoded English string comparison
* Fixed: strpos() replaced with str_starts_with() in disable_self_pingbacks() — consistent with PHP 8.2+ usage throughout the plugin
* Fixed: Explicit string types added to log_security_event() method signature
* Fixed: @param docblock of clear_login_attempts() updated to reflect renamed parameters $_user_login and $_user

= 2.0.0 - 2026-03-20 =
* Improved: Complete redesign of the settings page — responsive 3-column card grid replaces the default WordPress Settings API table layout
* Improved: Checkboxes replaced with CSS toggles for clearer on/off state at a glance
* Improved: "Clear Logs" button moved inline next to the section heading
* Improved: Minimal inline CSS scoped to .wpsh-* classes — no external stylesheet enqueued
* Removed: "Enable security headers" master toggle — each header is now controlled individually
* Removed: Configurable HSTS max-age field — hardcoded to 31536000 seconds (1 year), the universally recommended value
* Fixed: HSTS "Include subdomains" now defaults to disabled — users must opt in explicitly
* Improved: "Hide WordPress version" now also strips the WordPress version from script and style asset URLs (?ver=), preventing version detection via asset URLs
* Improved: "Hide WordPress version" moved from "User Enumeration" to "Other Settings"
* Improved: "Clean wp_head" no longer removes feed links extra — avoids conflicts with plugins that rely on category and tag feeds
* Improved: "Clean wp_head" no longer removes wp_generator — already covered by "Hide WordPress version"
* Improved: All toggle descriptions updated for consistency — each option now explains what value or behaviour it applies
* Added: New "Additional Hardening Recommendations" section in the plugin admin page and readme, including four measures from the official WordPress Hardening Guide not previously listed: rename admin account, restrict database user privileges, protect wp-config.php, and block direct access to wp-includes/

= 1.0 - 2026-03-05 =
* Updated: Minimum WordPress requirement raised to 6.9
* Updated: Minimum PHP requirement raised to 8.2
* Improved: Applied PHP 8.3 modern syntax throughout — typed class properties, explicit return types on all methods, short array syntax, and `match` expression in `sanitize_options()`
* Added: `delete_data_on_uninstall` option (default: disabled) — users must explicitly opt in to data deletion on uninstall; data is preserved by default
* Fixed: `uninstall.php` no longer uses direct SQL queries; deletion is now conditional on the opt-in option and uses WordPress APIs exclusively
* Fixed: `WPSH_VERSION` constant kept in sync with plugin header at `1.0`

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
