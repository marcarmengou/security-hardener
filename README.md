# Description

**Security Hardener** applies WordPress security best practices based on the [WordPress Advanced Administration / Security / Hardening](https://developer.wordpress.org/advanced-administration/security/hardening/) documentation and widely accepted hardening measures. It uses WordPress core functions and follows best practices without modifying core files.

## Key Features

**File Security:**
* Disable file editor in WordPress admin
* Optionally disable all file modifications (blocks updates - use with caution)

**XML-RPC Protection:**
* Disable XML-RPC completely (enabled by default)
* Remove pingback methods when XML-RPC is enabled

**Pingback Protection:**
* Disable self-pingbacks
* Remove X-Pingback header
* Block incoming pingbacks

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
* Optional HSTS (HTTP Strict Transport Security) for HTTPS sites — max-age set to 1 year

**Additional Hardening:**
* Hide WordPress version (meta generator tag and asset query strings)
* Remove obsolete wp_head items (RSD, WLW manifest, shortlink, emoji scripts)
* Security event logging system

> ⚠️ **Important:** Always test security settings in a staging environment first. Some features may affect third-party integrations or plugins.

**Privacy:** This plugin does not send data to external services and does not create custom database tables. It stores plugin settings and a security event log in the WordPress options table, and uses transients for temporary login attempt tracking. All data is preserved on uninstall by default and only deleted if the "Delete all data on uninstall" option is explicitly enabled.

## Resources
WordPress Plugin Repository: [https://wordpress.org/plugins/security-hardener/](https://wordpress.org/plugins/security-hardener/)
