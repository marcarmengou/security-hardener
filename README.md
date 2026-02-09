# Description

**Security Hardener** implements the official WordPress hardening guidelines from the [WordPress Advanced Administration / Security / Hardening](https://developer.wordpress.org/advanced-administration/security/hardening/) documentation. It uses WordPress core functions and follows best practices without modifying core files.

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

**Privacy:** This plugin does not send data to external services, does not create custom database tables, and only uses WordPress transients for temporary login attempt tracking.

## Resources
WordPress Plugin Repository: [https://wordpress.org/plugins/security-hardener/](https://wordpress.org/plugins/security-hardener/)
