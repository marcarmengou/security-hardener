<?php
/*
Plugin Name: Security Hardener
Plugin URI: https://wordpress.org/plugins/security-hardener/
Description: Basic hardening: secure headers, disable XML-RPC/pingbacks, hide version, block user enumeration, login errors, IP-based rate limiting, and optional restriction of the REST API.
Version: 0.3
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 7.4
Tested up to PHP: 8.3
Author: Marc Armengou
Author URI: https://www.marcarmengou.com/
Text Domain: security-hardener
License: GPLv2 or later
*/

if ( ! defined('ABSPATH') ) { exit; }
define('SECURITY_HARDENER_FILE', __FILE__);
define('SECURITY_HARDENER_DIR', plugin_dir_path(__FILE__));
define('SECURITY_HARDENER_URL', plugin_dir_url(__FILE__));
define('SECURITY_HARDENER_BASENAME', plugin_basename(__FILE__));
if ( ! class_exists('WPHN_Hardener') ) :

/**
 * Main plugin class
 */
class WPHN_Hardener {

	const OPT = 'wphn_hardener_options';

	/** @var string|null Nonce for CSP (only if the option is enabled) */
	protected ?string $csp_nonce = null;

	public function __construct() {
		// Activation: set default options
		register_activation_hook(__FILE__, [ $this, 'activate' ]);

		// Load constants on startup
		add_action('plugins_loaded', [ $this, 'maybe_define_constants' ]);

		// Security headers
		add_action('send_headers', [ $this, 'send_security_headers' ]);

		// Misc hardening
		add_filter('xmlrpc_enabled', [ $this, 'xmlrpc_toggle' ]);
		add_action('init', [ $this, 'disable_pingbacks_header' ]);
		add_filter('the_generator', '__return_empty_string'); // hide WP version
		add_action('init', [ $this, 'cleanup_wp_head' ]);

		// Block user enumeration /?author=
		add_action('template_redirect', [ $this, 'block_user_enumeration' ]);

		// Prevent canonical redirect for ?author=N → /author/slug/
		add_filter('redirect_canonical', [ $this, 'avoid_author_canonical' ], 10, 2);

		// (Optional) Lock user-related REST endpoints to authenticated users
		add_filter('rest_endpoints', [ $this, 'lock_user_rest_endpoints' ]);

		// (Optional) Remove users provider from core sitemaps
		add_filter('wp_sitemaps_add_provider', [ $this, 'remove_users_from_sitemaps' ], 10, 2);

		// Generic login errors
		add_filter('login_errors', [ $this, 'hide_login_errors' ]);

		// Login rate limit (simple, by IP)
		add_filter('authenticate', [ $this, 'rate_limit_auth' ], 1, 3);
		add_action('wp_login_failed', [ $this, 'record_failed_login' ]);
		add_action('wp_login', [ $this, 'clear_failed_login' ], 10, 2);

		// REST API (optional: restrict unauthenticated users with a minimal allowlist)
		add_filter('rest_authentication_errors', [ $this, 'maybe_restrict_rest' ]);

		// Admin
		add_action('admin_menu', [ $this, 'admin_menu' ]);
		add_action('admin_init', [ $this, 'register_settings' ]);
		add_action('admin_notices', [ $this, 'file_permissions_notice' ]);

		// Prepare nonce for CSP if applicable
		add_action('wp_enqueue_scripts', [ $this, 'maybe_prepare_csp_nonce' ], 0);
	}

	/**
	 * Set default options on activation
	 */
	public function activate(): void {
		$defaults = [
			'disable_file_editor' => 1,
			'disable_xmlrpc'      => 1,
			'restrict_rest'       => 0,
			'security_headers'    => 1,
			'hsts'                => 0,
			'csp'                 => 0,
			'block_user_enum'     => 1,
			'rate_limit'          => 1,
			'rate_limit_threshold'=> 5,
			'rate_limit_window'   => 15, // minutes
		];
		$opts = get_option(self::OPT, []);
		update_option(self::OPT, wp_parse_args((array) $opts, $defaults));
		flush_rewrite_rules();
	}

	/**
	 * Get specific option
	 */
	public function get_opt(string $key, $default = null) {
		$opts = (array) get_option(self::OPT, []);
		return array_key_exists($key, $opts) ? $opts[$key] : $default;
	}

	/**
	 * Define security constants if not already defined
	 */
	public function maybe_define_constants(): void {
	if ( $this->get_opt('disable_file_editor', 1) ) {
		if ( ! defined('DISALLOW_FILE_EDIT') ) {
			define('DISALLOW_FILE_EDIT', true);
		}
		// Note: DISALLOW_FILE_MODS can break updates. Keep commented out unless explicitly needed.
		// if ( ! defined('DISALLOW_FILE_MODS') ) { define('DISALLOW_FILE_MODS', true); }
	}
}

/**
 * Prepare CSP nonce if the option is active
 */
public function maybe_prepare_csp_nonce(): void {
	if ( (int) $this->get_opt('csp', 0) !== 1 ) {
		return;
	}
	// Base64 nonce, reusable for enqueues that need it.
	$this->csp_nonce = base64_encode( wp_generate_password(16, false) );
}

/**
 * Send security headers (if the option is active)
 */
public function send_security_headers(): void {
	if ( (int) $this->get_opt('security_headers', 1) !== 1 ) {
		return;
	}

	// Basic headers
	header('X-Frame-Options: SAMEORIGIN');               // clickjacking
	header('X-Content-Type-Options: nosniff');           // MIME sniffing
	header('Referrer-Policy: strict-origin-when-cross-origin');
	header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

	// COOP/CORP (optional; some sites may require adjustment)
	header('Cross-Origin-Opener-Policy: same-origin');
	header('Cross-Origin-Resource-Policy: same-origin');

	// HSTS (HTTPS only)
	if ( (int) $this->get_opt('hsts', 0) === 1 && is_ssl() ) {
		header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
	}

	// Basic CSP (opt-in). Requires prior testing on each site.
	if ( (int) $this->get_opt('csp', 0) === 1 && ! empty($this->csp_nonce) ) {
		$csp = "default-src 'self'; "
		     . "script-src 'self' 'nonce-{$this->csp_nonce}' https:; "
		     . "style-src 'self' 'unsafe-inline' https:; "
		     . "img-src 'self' data: https:; "
		     . "font-src 'self' data: https:; "
		     . "connect-src 'self' https:;";
		header('Content-Security-Policy: ' . $csp);
	}
}

/**
 * Disable XML-RPC (by default)
 */
public function xmlrpc_toggle($enabled) {
	return $this->get_opt('disable_xmlrpc', 1) ? false : $enabled;
}

/**
 * Remove references to pingbacks, RSD and WLW
 */
public function disable_pingbacks_header(): void {
	remove_action('wp_head', 'rsd_link');
	remove_action('wp_head', 'wlwmanifest_link');
	add_filter('pre_option_default_ping_status', '__return_zero');
	add_filter('pre_option_default_pingback_flag', '__return_zero');
	add_filter('pings_open', '__return_false');
}

/**
 * Additional cleanup of the <head>
 */
public function cleanup_wp_head(): void {
	// Emojis
	remove_action('wp_head', 'print_emoji_detection_script', 7);
	remove_action('wp_print_styles', 'print_emoji_styles');
	// Extra feed links
	remove_action('wp_head', 'feed_links_extra', 3);
	// WLW/RSD already removed above
}

/**
 * Block user enumeration via `?author=NUM` while allowing normal author archives.
 */
public function block_user_enumeration(): void {
	// Feature toggle
	if ( (int) $this->get_opt('block_user_enum', 1) !== 1 ) {
		return;
	}

	// Don't interfere in admin screens
	if ( is_admin() ) {
		return;
	}

	// Always block numeric author enumeration (?author=NUM), even for logged-in users
	$author_param = filter_input(INPUT_GET, 'author', FILTER_VALIDATE_INT);
	if ( $author_param !== null && $author_param !== false ) {
		global $wp_query;
		if ( isset($wp_query) ) {
			$wp_query->set_404();
			status_header(404);
			nocache_headers();
		}
		// Load 404 template if available
		include get_query_template('404');
		exit;
	}

	// Allow normal author archives (/author/slug/ or ?author_name=slug)
	if ( is_author() ) {
		return;
	}

	// Fallback: detect raw querystring pattern to be extra safe
	$query_string = '';
	if ( isset($_SERVER['QUERY_STRING']) ) {
		$query_string = sanitize_text_field( wp_unslash( (string) $_SERVER['QUERY_STRING'] ) );
	}

	if ( $query_string !== '' && preg_match('/(^|&)author=\d+/i', $query_string) ) {
		global $wp_query;
		if ( isset($wp_query) ) {
			$wp_query->set_404();
			status_header(404);
			nocache_headers();
		}
		include get_query_template('404');
		exit;
	}
}

/**
 * Do not perform canonical redirect when enumerating authors via ?author=N.
 */
public function avoid_author_canonical($redirect_url, $requested_url) {
    if ( is_admin() ) { // Do not interfere in admin screens
        return $redirect_url;
    }
    if ( (int) $this->get_opt('block_user_enum', 1) !== 1 ) {
        return $redirect_url;
    }

    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check on front-end, no state change or sensitive action is performed.
    $author_param = filter_input(INPUT_GET, 'author', FILTER_VALIDATE_INT);

    if ( $author_param ) {
        // Cancel the redirect so the pretty URL /author/slug/ is never exposed
        return false;
    }
    return $redirect_url;
}

/**
 * (Optional) Require authentication for user REST endpoints to avoid user harvesting.
 */
public function lock_user_rest_endpoints($endpoints) {
    if ( ! is_array($endpoints) ) {
        return $endpoints;
    }
    // Guard: only enforce if the feature is enabled (same toggle as enumeration block)
    if ( (int) $this->get_opt('block_user_enum', 1) !== 1 ) {
        return $endpoints;
    }

    $protect = static function () {
        return is_user_logged_in();
    };

    if ( isset($endpoints['/wp/v2/users']) && is_array($endpoints['/wp/v2/users']) ) {
        foreach ($endpoints['/wp/v2/users'] as &$route) {
            if ( is_array($route) ) {
                $route['permission_callback'] = $protect;
            }
        }
    }
    if ( isset($endpoints['/wp/v2/users/(?P<id>[\d]+)']) && is_array($endpoints['/wp/v2/users/(?P<id>[\d]+)']) ) {
        foreach ($endpoints['/wp/v2/users/(?P<id>[\d]+)'] as &$route) {
            if ( is_array($route) ) {
                $route['permission_callback'] = $protect;
            }
        }
    }

    return $endpoints;
}

/**
 * (Optional) Remove the users provider from the core sitemap.
 */
public function remove_users_from_sitemaps($provider, $name) {
    if ( 'users' === $name ) {
        return false;
    }
    return $provider;
}

/**
 * Generic login error messages
 */
public function hide_login_errors($error) {
	/* translators: Generic login error with no hints to the user. */
	return __('Incorrect login credentials.', 'security-hardener');
}

/**
 * Transient key for per-IP failure counter
 */
protected function failed_key(string $ip): string {
	return 'wph_failed_' . md5($ip);
}

/**
 * Record failed login attempt
 */
public function record_failed_login(string $username): void {
	if ( (int) $this->get_opt('rate_limit', 1) !== 1 ) {
		return;
	}
	$ip   = $this->ip();
	$key  = $this->failed_key($ip);
	$data = (array) get_transient($key);

	$count = isset($data['count']) ? (int) $data['count'] : 0;
	$count++;

	$window_minutes = max(1, (int) $this->get_opt('rate_limit_window', 15));
	$ttl            = $window_minutes * 60;

	set_transient($key, [ 'count' => $count, 'since' => time() ], $ttl);
}

/**
 * Clear failure counter upon successful login
 */
public function clear_failed_login(string $user_login, $user): void {
	$ip  = $this->ip();
	$key = $this->failed_key($ip);
	delete_transient($key);
}

/**
 * Apply rate limiting in authenticate
 */
public function rate_limit_auth($user, string $username, string $password) {
	if ( (int) $this->get_opt('rate_limit', 1) !== 1 ) {
		return $user;
	}
	$ip   = $this->ip();
	$key  = $this->failed_key($ip);
	$data = get_transient($key);

	$threshold = max(1, (int) $this->get_opt('rate_limit_threshold', 5));

	if ( is_array($data) && isset($data['count']) && (int) $data['count'] >= $threshold ) {
		$window = max(1, (int) $this->get_opt('rate_limit_window', 15));
		return new WP_Error(
			'too_many_attempts',
			sprintf(
				/* translators: %d: number of minutes to wait before next login attempt. */
				__('Too many attempts. Try again in %d minutes.', 'security-hardener'),
				$window
			),
			[ 'status' => 429 ]
		);
	}

	return $user;
}

/**
 * Get the client IP.
 * If your installation uses a trusted proxy/load balancer,
 * define the constant WPH_TRUST_PROXY to true in wp-config.php.
 */
	protected function ip(): string {
	$trusted_proxy = defined('WPH_TRUST_PROXY') && WPH_TRUST_PROXY;

	if ( $trusted_proxy ) {
		// Cloudflare
		$cf = filter_input(INPUT_SERVER, 'HTTP_CF_CONNECTING_IP', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		if ( is_string($cf) && $cf !== '' ) {
			$cf = trim( wp_unslash($cf) );
			$ip = filter_var($cf, FILTER_VALIDATE_IP);
			if ( $ip ) {
				return $ip;
			}
		}

		// X-Forwarded-For
		$xff = filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		if ( is_string($xff) && $xff !== '' ) {

			$xff   = trim( wp_unslash($xff) );
			$parts = array_map('trim', explode(',', $xff));
			$cand  = $parts[0] ?? '';
			$ip    = filter_var($cand, FILTER_VALIDATE_IP);
			if ( $ip ) {
				return $ip;
			}
		}
	}

	// REMOTE_ADDR as a last resort
	$ra_raw = filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	$ra_raw = is_string($ra_raw) ? trim( wp_unslash($ra_raw) ) : '';
	$ip     = filter_var($ra_raw, FILTER_VALIDATE_IP);

	return $ip ?: '0.0.0.0';
}

/**
 * REST API: optionally restrict to authenticated users,
 * allowing minimal public routes (index and oEmbed)
 */
public function maybe_restrict_rest($result) {
	if ( (int) $this->get_opt('restrict_rest', 0) !== 1 ) {
		return $result;
	}
	if ( is_user_logged_in() ) {
		return $result;
	}

	// Get current request from REST Server (if it exists)
	$server  = rest_get_server();
	$request = $server ? $server->get_current_request() : null;
	$route   = $request ? $request->get_route() : '';

	// Allowlist: API index and oEmbed
	$public_whitelist = [
		'#^/?$#',                // API index
		'#^/oembed/1\.0#',       // oEmbed namespace
	];

	foreach ( $public_whitelist as $rx ) {
		if ( @preg_match($rx, $route) === 1 && preg_match($rx, $route) ) {
			return $result;
		}
	}

	return new WP_Error(
		'rest_forbidden',
		/* translators: Message shown when unauthenticated access to REST is blocked by the plugin. */
		__('The REST API requires authentication on this site.', 'security-hardener'),
		[ 'status' => rest_authorization_required_code() ]
	);
}

/**
 * Admin: settings page
 */
public function admin_menu(): void {
	add_options_page(
		'Security Hardener',
		'Security Hardener',
		'manage_options',
		'security-hardener',
		[ $this, 'render_settings' ]
	);
}

/**
 * Register settings and fields with sanitization
 */
public function register_settings(): void {
	register_setting(
		'wphn_hardener',
		self::OPT,
		[
			'type'              => 'array',
			'sanitize_callback' => [ $this, 'sanitize_options' ],
			'show_in_rest'      => false,
			'default'           => [],
		]
	);

	add_settings_section(
		'wphn_hardener_main',
		__('Hardening options', 'security-hardener'),
		function () {
			echo '<p>' . esc_html__('Enable only what you have tested in your installation.', 'security-hardener') . '</p>';
		},
		'security-hardener'
	);

	$fields = [
		'disable_file_editor' => __('Disable built-in file editor', 'security-hardener'),
		'disable_xmlrpc'      => __('Disable XML-RPC and pingbacks', 'security-hardener'),
		'restrict_rest'       => __('Restrict REST API to authenticated users (may break public integrations)', 'security-hardener'),
		'security_headers'    => __('Add basic security headers', 'security-hardener'),
		'hsts'                => __('Enable HSTS (HTTPS only)', 'security-hardener'),
		'csp'                 => __('Enable basic CSP (requires testing)', 'security-hardener'),
		'block_user_enum'     => __('Block user enumeration (?author=N) and protect user endpoints', 'security-hardener'),
		'rate_limit'          => __('Limit login attempts by IP', 'security-hardener'),
	];

	foreach ( $fields as $key => $label ) {
		add_settings_field(
			$key,
			esc_html($label),
			function () use ( $key ) {
				$opts          = (array) get_option(self::OPT, []);
				$is_checked    = ! empty($opts[$key]);
				$checked_attr  = checked( $is_checked, true, false ); // prints checked="checked" or empty (safe)
				printf(
					'<label><input type="checkbox" name="%1$s[%2$s]" value="1" %3$s /></label>',
					esc_attr(self::OPT),
					esc_attr($key),
					$checked_attr // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- checked() generates a safe attribute
				);
			},
			'security-hardener',
			'wphn_hardener_main'
		);
	}
		// Rate limit fields
add_settings_field(
	'rate_limit_threshold',
	esc_html__('Allowed attempts before blocking', 'security-hardener'),
	function () {
		$opts = (array) get_option(self::OPT, []);
		$v    = isset($opts['rate_limit_threshold']) ? (int) $opts['rate_limit_threshold'] : 5;
		printf(
			'<input type="number" min="1" step="1" name="%1$s[rate_limit_threshold]" value="%2$s" />',
			esc_attr(self::OPT),
			esc_attr((string) $v)
		);
	},
	'security-hardener',
	'wphn_hardener_main'
);

add_settings_field(
	'rate_limit_window',
	esc_html__('Blocking window (minutes)', 'security-hardener'),
	function () {
		$opts = (array) get_option(self::OPT, []);
		$v    = isset($opts['rate_limit_window']) ? (int) $opts['rate_limit_window'] : 15;
		printf(
			'<input type="number" min="1" step="1" name="%1$s[rate_limit_window]" value="%2$s" />',
			esc_attr(self::OPT),
			esc_attr((string) $v)
		);
	},
	'security-hardener',
	'wphn_hardener_main'
);
}

/**
 * Sanitization/normalization of all plugin options
 */
public function sanitize_options($raw): array {
	$raw   = is_array($raw) ? $raw : [];
	$clean = [];

	$bools = [
		'disable_file_editor',
		'disable_xmlrpc',
		'restrict_rest',
		'security_headers',
		'hsts',
		'csp',
		'block_user_enum',
		'rate_limit',
	];

	foreach ( $bools as $k ) {
		$clean[$k] = ! empty($raw[$k]) ? 1 : 0;
	}

	$clean['rate_limit_threshold'] = max(1, absint($raw['rate_limit_threshold'] ?? 5));
	$clean['rate_limit_window']    = max(1, absint($raw['rate_limit_window'] ?? 15));

	return $clean;
}

/**
 * Render settings page
 */
public function render_settings(): void {
	if ( ! current_user_can('manage_options') ) {
		wp_die( esc_html__('You do not have permission to view this page.', 'security-hardener') );
	}
	echo '<div class="wrap">';
	echo '<h1>' . esc_html__('Security Hardener', 'security-hardener') . '</h1>';
	echo '<form method="post" action="options.php">';
	settings_fields('wphn_hardener');
	do_settings_sections('security-hardener');
	submit_button();
	echo '</form>';

	echo '<hr />';
	echo '<p><strong>' . esc_html__('Additional tips:', 'security-hardener') . '</strong> '
	   . esc_html__('Test first in staging, review integrations that use the REST API, and apply CSP policies carefully. Also harden the hosting (separation of privileges, SSH, backups, monitoring).', 'security-hardener')
	   . '</p>';

	echo '</div>';
}

/**
 * Basic notice about file permissions (only on the plugin screen)
 */
public function file_permissions_notice(): void {
	if ( ! current_user_can('manage_options') ) { return; }

	$screen = function_exists('get_current_screen') ? get_current_screen() : null;
	if ( ! $screen || $screen->id !== 'settings_page_security-hardener' ) { return; }

		$uploads = wp_upload_dir();
		if ( ! function_exists( 'get_home_path' ) ) {
    		require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$paths = [
    		( defined('SECURITY_HARDENER_DIR') ? SECURITY_HARDENER_DIR : plugin_dir_path(__FILE__) ) => __( 'Plugin (path)', 'security-hardener' ),
    		( isset($uploads['basedir']) ? trailingslashit($uploads['basedir']) : '' )                => __( 'Uploads base (path)', 'security-hardener' ),
    		( function_exists('get_home_path') ? trailingslashit( get_home_path() ) : '' )            => __( 'Site root (path)', 'security-hardener' ),
    		trailingslashit( get_stylesheet_directory() )                                             => __( 'Active theme (path)', 'security-hardener' ),
    		( function_exists('get_home_path') ? trailingslashit( get_home_path() ) . 'wp-config.php' : '' ) => __( 'wp-config.php', 'security-hardener' ),
		];
		$problems = [];


	foreach ( $paths as $path => $label ) {
		if ( ! @file_exists($path) ) { continue; }

		$perms = @substr(sprintf('%o', @fileperms($path)), -4);
		if ( ! $perms ) { continue; }

		if ( is_dir($path) ) {
			if ( ! in_array($perms, [ '0755', '0750' ], true ) ) {
				$problems[] = sprintf(
					/* translators: 1: label of the path being checked; 2: current permission bits, e.g. 0777 */
					__('%1$s has permissions %2$s (recommended 0755/0750)', 'security-hardener'),
					$label,
					$perms
				);
			}
		} else {
			$recommended = (str_ends_with($path, 'wp-config.php')) ? [ '0640', '0644' ] : [ '0644', '0640' ];
			if ( ! in_array($perms, $recommended, true ) ) {
				$problems[] = sprintf(
					/* translators: 1: label of the file being checked; 2: current permission bits, e.g. 0666 */
					__('%1$s has permissions %2$s (recommended 0640/0644)', 'security-hardener'),
					$label,
					$perms
				);
			}
		}
	}

	if ( ! empty($problems) ) {
		echo '<div class="notice notice-warning"><p><strong>'
		   . esc_html__('Security Hardener:', 'security-hardener')
		   . '</strong> '
		   . esc_html__('Check file/directory permissions:', 'security-hardener')
		   . '</p><ul>';
		foreach ( $problems as $pr ) {
			echo '<li>' . esc_html($pr) . '</li>';
		}
		echo '</ul></div>';
	}
}
}

endif; // class exists

// Flush rewrite rules on deactivation as well
register_deactivation_hook(__FILE__, function () {
    flush_rewrite_rules();
});

new WPHN_Hardener();