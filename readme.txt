=== Security Hardener ===
Contributors: marc4
Tags: security, hardening, headers, brute force
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 0.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Basic hardening: secure headers, enumeration blocking, generic login errors, IP-based rate limiting, and optional restriction of the REST API.

== Description ==

**Security Hardener** is inspired by the official WordPress hardening guide (Advanced Administration / Security / Hardening). It uses the platform’s standard functions and does not override core. Applies a prudent set of defenses:

- **Security headers**: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP/CORP`.  
- **HSTS** (optional; HTTPS only).  
- **Basic nonce-based CSP** (optional; requires testing).  
- **Disable XML-RPC and pingbacks** (optional; enabled by default).  
- **Hide the WordPress version** in the `<head>`.  
- **Block user enumeration** via `/?author=` by returning 404.  
- **Generic login errors** (prevents information leakage).  
- **IP-based login rate limiting** with transients (configurable threshold and window).  
- **Restrict the REST API** to authenticated users, with a **minimal allowlist** for oEmbed/index.

> ⚠️ **Important:** The **restrict REST API** option and **CSP** can affect integrations and plugins. Test it in *staging* first.

**Privacy**: the plugin does not send data to external services or create new tables. It only uses transients to count failed login attempts.

== Installation ==

1. Go to **Plugins > Add New Plugin**.
2. Search for **Security Hardener**.
3. Install and activate the **Security Hardener** plugin.

== Frequently Asked Questions ==

= Does restricting the REST API “block everything”? =

No. By default it allows the **index** and the **oEmbed** namespace for basic compatibility. The rest requires an authenticated user. If you need additional public routes, do not enable the restriction or create specific solutions in your theme/plugin (with their `permission_callback`).

= I use a CDN or proxy. What about the IP? =

By default, rate limiting takes the IP from `REMOTE_ADDR`. If you use a trusted proxy (CDN/load balancer), define in `wp-config.php`:
`define('WPH_TRUST_PROXY', true);`
With that, the plugin will try to use `HTTP_CF_CONNECTING_IP` or `X-Forwarded-For` (first element), validating the IP.

= Which headers does it add exactly? =

`X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=(), microphone=(), camera=()`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and optionally `Strict-Transport-Security` and `Content-Security-Policy` (with nonce).

= Does the plugin clean up its data upon uninstall? =

Yes. `uninstall.php` deletes the main option and the rate-limit transients.

== Changelog ==

= [0.3] - 2025-10-20 =
* Some corrections.

= [0.2] - 2025-10-13 =
* Some corrections.

= [0.1] - 2025-10-04 =
* Initial release.
