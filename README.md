# Description

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

## Resources
WordPress Plugin Repository: [https://wordpress.org/plugins/security-hardener/](https://wordpress.org/plugins/security-hardener/)
