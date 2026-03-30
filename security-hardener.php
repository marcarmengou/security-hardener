<?php
/*
Plugin Name: Security Hardener
Plugin URI: https://wordpress.org/plugins/security-hardener/
Description: Basic hardening: secure headers, disable XML-RPC/pingbacks, hide version, block user enumeration, generic login errors, and IP-based rate limiting.
Version: 2.1.1
Requires at least: 6.9
Tested up to: 6.9
Requires PHP: 8.2
Author: Marc Armengou
Author URI: https://www.marcarmengou.com/
Text Domain: security-hardener
License: GPLv2 or later
*/

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin constants
define( 'WPSH_VERSION', '2.1.1' );
define( 'WPSH_FILE', __FILE__ );
define( 'WPSH_BASENAME', plugin_basename( __FILE__ ) );

if ( ! class_exists( 'WPHN_Hardener' ) ) :

	/**
	 * Main plugin class applying WordPress security best practices
	 */
	class WPHN_Hardener {

		/**
		 * Option name in database
		 */
		const OPTION_NAME = 'wpsh_options';

		/**
		 * Checklist state option name in database
		 */
		const CHECKLIST_OPTION = 'wpsh_checklist';

		/**
		 * Singleton instance
		 *
		 * @var WPHN_Hardener|null
		 */
		private static ?self $instance = null;

		/**
		 * Plugin options
		 *
		 * @var array<string, mixed>
		 */
		private array $options = [];

		/**
		 * Get singleton instance
		 *
		 * @return WPHN_Hardener
		 */
		public static function get_instance(): static {
			if ( null === self::$instance ) {
				self::$instance = new self();
			}
			return self::$instance;
		}

		/**
		 * Constructor - private for singleton
		 */
		private function __construct() {
			// Load options
			$this->options = $this->get_options();

			// Define security constants as early as possible
			$this->define_security_constants();

			// Activation/Deactivation hooks
			register_activation_hook( WPSH_FILE, array( $this, 'activate' ) );
			register_deactivation_hook( WPSH_FILE, array( $this, 'deactivate' ) );

			// Core initialization
			add_action( 'plugins_loaded', array( $this, 'init' ) );
		}

		/**
		 * Initialize plugin
		 */
		public function init(): void {
			// Security headers
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );

			// XML-RPC hardening
			if ( $this->get_option( 'disable_xmlrpc', true ) ) {
				add_filter( 'xmlrpc_enabled', '__return_false' );
				add_filter( 'xmlrpc_methods', array( $this, 'remove_xmlrpc_pingback' ) );
			}

			// Remove version info
			if ( $this->get_option( 'hide_wp_version', true ) ) {
				add_filter( 'the_generator', '__return_empty_string' );
				remove_action( 'wp_head', 'wp_generator' );
				add_filter( 'script_loader_src', array( $this, 'remove_wp_version_from_assets' ) );
				add_filter( 'style_loader_src', array( $this, 'remove_wp_version_from_assets' ) );
			}

			// User enumeration protection
			if ( $this->get_option( 'block_user_enum', true ) ) {
				add_action( 'template_redirect', array( $this, 'prevent_user_enumeration' ), 1 );
				add_filter( 'redirect_canonical', array( $this, 'prevent_author_redirect' ), 10, 2 );
				add_filter( 'rest_endpoints', array( $this, 'secure_user_endpoints' ) );
				add_filter( 'wp_sitemaps_add_provider', array( $this, 'remove_users_sitemap' ), 10, 2 );
			}

			// Login security
			if ( $this->get_option( 'secure_login', true ) ) {
				add_filter( 'login_errors', array( $this, 'generic_login_errors' ) );
				add_action( 'login_init', array( $this, 'remove_login_hints' ) );
			}

			// Login rate limiting
			if ( $this->get_option( 'rate_limit_login', true ) ) {
				add_filter( 'authenticate', array( $this, 'check_login_rate_limit' ), 30, 3 );
				add_action( 'wp_login_failed', array( $this, 'log_failed_login' ) );
				add_action( 'wp_login', array( $this, 'clear_login_attempts' ), 10, 2 );
			}

			// Disable pingbacks
			if ( $this->get_option( 'disable_pingbacks', true ) ) {
				add_action( 'pre_ping', array( $this, 'disable_self_pingbacks' ) );
				add_filter( 'wp_headers', array( $this, 'remove_x_pingback' ) );
				add_filter( 'pings_open', '__return_false', 9999 );
			}

			// Clean wp_head
			if ( $this->get_option( 'clean_head', true ) ) {
				$this->cleanup_wp_head();
			}

			// Admin interface
			if ( is_admin() ) {
				add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
				add_action( 'admin_init', array( $this, 'register_settings' ) );
				add_action( 'admin_notices', array( $this, 'show_admin_notices' ) );
				add_filter( 'plugin_action_links_' . WPSH_BASENAME, array( $this, 'add_settings_link' ) );
				add_action( 'wp_ajax_wpsh_toggle_checklist', array( $this, 'ajax_toggle_checklist' ) );
				add_action( 'wp_ajax_wpsh_reset_checklist', array( $this, 'ajax_reset_checklist' ) );
			}
		}

		/**
		 * Plugin activation
		 */
		public function activate(): void {
			// Set default options only if they don't exist
			if ( false === get_option( self::OPTION_NAME ) ) {
				$defaults = $this->get_default_options();
				update_option( self::OPTION_NAME, $defaults );
			}

			// Log activation
			$this->log_security_event( 'plugin_activated', __( 'Security Hardener plugin activated', 'security-hardener' ) );
		}

		/**
		 * Plugin deactivation
		 */
		public function deactivate(): void {
			// Log deactivation
			$this->log_security_event( 'plugin_deactivated', __( 'Security Hardener plugin deactivated', 'security-hardener' ) );
		}

		/**
		 * Get default options
		 *
		 * @return array<string, int>
		 */
		private function get_default_options(): array {
			return [
				// File editing
				'disable_file_edit'        => 1,
				'disable_file_mods'        => 0, // Disabled by default as it breaks updates

				// XML-RPC
				'disable_xmlrpc'           => 1,

				// Version hiding
				'hide_wp_version'          => 1,

				// User enumeration
				'block_user_enum'          => 1,

				// Login security
				'secure_login'             => 1,
				'rate_limit_login'         => 1,
				'rate_limit_attempts'      => 5,
				'rate_limit_minutes'       => 15,

				// Pingbacks
				'disable_pingbacks'        => 1,

				// Clean wp_head
				'clean_head'               => 1,

				// Security headers
				'header_x_frame'           => 1,
				'header_x_content'         => 1,
				'header_referrer'          => 1,
				'header_permissions'       => 1,

				// HTTPS
				'enable_hsts'              => 0, // Off by default - requires HTTPS
				'hsts_subdomains'          => 0,
				'hsts_preload'             => 0,

				// Advanced
				'log_security_events'      => 1,
				'delete_data_on_uninstall' => 0,
			];
		}

		/**
		 * Get all options
		 *
		 * @return array
		 */
		private function get_options(): array {
			$options  = get_option( self::OPTION_NAME, array() );
			$defaults = $this->get_default_options();
			return wp_parse_args( $options, $defaults );
		}

		/**
		 * Get single option value
		 *
		 * @param string $key Option key.
		 * @param mixed  $default Default value.
		 * @return mixed
		 */
		private function get_option( $key, $default = null ): mixed {
			if ( isset( $this->options[ $key ] ) ) {
				return $this->options[ $key ];
			}
			return $default;
		}

		/**
		 * Define security constants based on plugin settings
		 */
		private function define_security_constants(): void {
			// Disable file editing in WordPress admin
			if ( $this->get_option( 'disable_file_edit', true ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
				define( 'DISALLOW_FILE_EDIT', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Native WordPress constant
			}

			// Disable all file modifications (updates, installs) - CAUTION: This breaks updates!
			if ( $this->get_option( 'disable_file_mods', false ) && ! defined( 'DISALLOW_FILE_MODS' ) ) {
				define( 'DISALLOW_FILE_MODS', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Native WordPress constant
			}
		}

		/**
		 * Send security headers
		 */
		public function send_security_headers(): void {
			// Prevent sent headers warning
			if ( headers_sent() ) {
				return;
			}

			// X-Frame-Options: Prevent clickjacking
			if ( $this->get_option( 'header_x_frame', true ) ) {
				header( 'X-Frame-Options: SAMEORIGIN' );
			}

			// X-Content-Type-Options: Prevent MIME sniffing
			if ( $this->get_option( 'header_x_content', true ) ) {
				header( 'X-Content-Type-Options: nosniff' );
			}

			// Referrer-Policy
			if ( $this->get_option( 'header_referrer', true ) ) {
				header( 'Referrer-Policy: strict-origin-when-cross-origin' );
			}

			// Permissions-Policy (formerly Feature-Policy)
			if ( $this->get_option( 'header_permissions', true ) ) {
				header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
			}

			// HSTS (only if HTTPS and enabled)
			if ( $this->get_option( 'enable_hsts', false ) && is_ssl() ) {
				$hsts_header = 'Strict-Transport-Security: max-age=31536000';

				if ( $this->get_option( 'hsts_subdomains', false ) ) {
					$hsts_header .= '; includeSubDomains';
				}

				if ( $this->get_option( 'hsts_preload', false ) ) {
					$hsts_header .= '; preload';
				}

				header( $hsts_header );
			}
		}

		/**
		 * Remove XML-RPC pingback method
		 *
		 * @param array $methods XML-RPC methods.
		 * @return array
		 */
		public function remove_xmlrpc_pingback( $methods ): array {
			unset( $methods['pingback.ping'] );
			unset( $methods['pingback.extensions.getPingbacks'] );
			return $methods;
		}

		/**
		 * Remove WordPress version number from script and style URLs.
		 *
		 * Only strips ?ver= when its value matches the WordPress core version,
		 * leaving plugin and theme asset versions intact.
		 *
		 * @param string $src Asset URL.
		 * @return string
		 */
		public function remove_wp_version_from_assets( string $src ): string {
			global $wp_version;
			if ( str_contains( $src, "ver={$wp_version}" ) ) {
				$src = remove_query_arg( 'ver', $src );
			}
			return $src;
		}

		/**
		 * Prevent user enumeration via ?author=N
		 */
		public function prevent_user_enumeration(): void {
			// Don't interfere in admin
			if ( is_admin() ) {
				return;
			}

			// Check for author query parameter with numeric value
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check
			$author = isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( $_GET['author'] ) ) : null;

			// Block numeric author parameter
			if ( null !== $author && is_numeric( $author ) ) {
				wp_die(
					esc_html__( 'Page not found.', 'security-hardener' ),
					esc_html__( '404 Not Found', 'security-hardener' ),
					array( 'response' => 404 )
				);
			}
		}

		/**
		 * Prevent canonical redirect from ?author=N to /author/username/
		 *
		 * @param string $redirect_url Redirect URL.
		 * @param string $requested_url Requested URL.
		 * @return string|false
		 */
		public function prevent_author_redirect( $redirect_url, $requested_url ): string|false {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check
			$author = isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( $_GET['author'] ) ) : null;
			if ( null !== $author && is_numeric( $author ) ) {
				return false; // Cancel redirect
			}
			return $redirect_url;
		}

		/**
		 * Secure user REST API endpoints
		 *
		 * @param array $endpoints REST endpoints.
		 * @return array
		 */
		public function secure_user_endpoints( $endpoints ): array {
			if ( ! is_array( $endpoints ) ) {
				return $endpoints;
			}

			// Require authentication for user endpoints
			$user_endpoints = array(
				'/wp/v2/users',
				'/wp/v2/users/(?P<id>[\d]+)',
			);

			foreach ( $user_endpoints as $endpoint ) {
				if ( isset( $endpoints[ $endpoint ] ) ) {
					foreach ( $endpoints[ $endpoint ] as &$handler ) {
						if ( is_array( $handler ) ) {
							$handler['permission_callback'] = function () {
								return is_user_logged_in();
							};
						}
					}
				}
			}

			return $endpoints;
		}

		/**
		 * Remove users from XML sitemap
		 *
		 * @param WP_Sitemaps_Provider $provider Sitemap provider.
		 * @param string                $name Provider name.
		 * @return WP_Sitemaps_Provider|false
		 */
		public function remove_users_sitemap( $provider, $name ): \WP_Sitemaps_Provider|false {
			return ( 'users' === $name ) ? false : $provider;
		}

		/**
		 * Generic login error messages
		 *
		 * @param string $error Error message.
		 * @return string
		 */
		public function generic_login_errors( $error ): string {
			// Don't change the error if it's empty
			if ( empty( $error ) ) {
				return $error;
			}

			// Return generic error message
			return '<strong>' . esc_html__( 'Error:', 'security-hardener' ) . '</strong> ' . esc_html__( 'Invalid username or password.', 'security-hardener' );
		}

		/**
		 * Prevent username/email enumeration via the lost password form.
		 *
		 * WordPress shows different error messages depending on whether the submitted
		 * username or email exists in the database, allowing attackers to enumerate
		 * valid accounts. This replaces any lostpassword error with a single generic
		 * message that does not reveal whether an account exists.
		 *
		 * Uses lostpassword_errors (WP 5.5+) rather than login_messages so that only
		 * the lost password flow is affected — other login messages from WordPress or
		 * third-party plugins are left completely intact.
		 */
		public function remove_login_hints(): void {
			add_filter(
				'lostpassword_errors',
				function ( \WP_Error $errors ): \WP_Error {
					if ( $errors->has_errors() ) {
						return new \WP_Error(
							'generic_error',
							esc_html__( 'If an account exists with that email, you will receive a reset link shortly.', 'security-hardener' )
						);
					}
					return $errors;
				}
			);
		}

		/**
		 * Check login rate limit
		 *
		 * @param WP_User|WP_Error|null $user User object or error.
		 * @param string                 $username Username.
		 * @param string                 $password Password.
		 * @return WP_User|WP_Error
		 */
		public function check_login_rate_limit( $user, $username, $password ): \WP_User|\WP_Error|null {
			// Skip if credentials are empty
			if ( empty( $username ) || empty( $password ) ) {
				return $user;
			}

			$ip            = $this->get_client_ip();
			$attempts_key  = 'wpsh_login_attempts_' . md5( $ip );
			$blocked_key   = 'wpsh_login_blocked_' . md5( $ip );

			// Check if IP is currently blocked
			if ( get_transient( $blocked_key ) ) {
				$minutes = $this->get_option( 'rate_limit_minutes', 15 );
				return new WP_Error(
					'too_many_attempts',
					wp_kses_post(
						'<strong>' . esc_html__( 'Error:', 'security-hardener' ) . '</strong> ' . sprintf(
							/* translators: %d: number of minutes */
							esc_html__( 'Too many failed login attempts. Please try again in %d minutes.', 'security-hardener' ),
							$minutes
						)
					)
				);
			}

			return $user;
		}

		/**
		 * Log failed login attempt
		 *
		 * @param string $username Username used in failed attempt.
		 */
		public function log_failed_login( $username ): void {
			$ip           = $this->get_client_ip();
			$attempts_key = 'wpsh_login_attempts_' . md5( $ip );
			$blocked_key  = 'wpsh_login_blocked_' . md5( $ip );

			// Get current attempts
			$attempts = get_transient( $attempts_key );
			$attempts = ( false === $attempts ) ? 1 : absint( $attempts ) + 1;

			// Store attempts
			$minutes = $this->get_option( 'rate_limit_minutes', 15 );
			set_transient( $attempts_key, $attempts, $minutes * MINUTE_IN_SECONDS );

			// Check if threshold exceeded
			$threshold = $this->get_option( 'rate_limit_attempts', 5 );
			if ( $attempts >= $threshold ) {
				set_transient( $blocked_key, 1, $minutes * MINUTE_IN_SECONDS );
				$this->log_security_event(
					'login_blocked',
					sprintf(
						/* translators: 1: IP address, 2: username, 3: number of attempts */
						__( 'Login blocked for IP %1$s after %3$d failed attempts (username: %2$s)', 'security-hardener' ),
						$ip,
						$username,
						$attempts
					)
				);
			} else {
				$this->log_security_event(
					'login_failed',
					sprintf(
						/* translators: 1: IP address, 2: username, 3: number of attempts */
						__( 'Failed login from IP %1$s (username: %2$s, attempt %3$d)', 'security-hardener' ),
						$ip,
						$username,
						$attempts
					)
				);
			}
		}

		/**
		 * Clear login attempts on successful login
		 *
		 * @param string  $_user_login Username (unused, required by hook).
		 * @param WP_User $_user       User object (unused, required by hook).
		 */
		public function clear_login_attempts( $_user_login, $_user ): void {
			$ip           = $this->get_client_ip();
			$attempts_key = 'wpsh_login_attempts_' . md5( $ip );
			$blocked_key  = 'wpsh_login_blocked_' . md5( $ip );

			delete_transient( $attempts_key );
			delete_transient( $blocked_key );
		}

		/**
		 * Get client IP address
		 *
		 * @return string
		 */
		private function get_client_ip(): string {
			$ip = '0.0.0.0';

			// Check for trusted proxy header (only if explicitly configured)
			if ( defined( 'WPSH_TRUSTED_PROXIES' ) && is_array( WPSH_TRUSTED_PROXIES ) ) {
				$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

				// Only trust proxy headers if request comes from trusted proxy
				if ( in_array( $remote_addr, WPSH_TRUSTED_PROXIES, true ) ) {
					// Try Cloudflare header
					if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
						$cf_ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
						if ( filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
							return $cf_ip;
						}
					}

					// Try X-Forwarded-For
					if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
						$xff = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
						$ips = array_map( 'trim', explode( ',', $xff ) );
						if ( ! empty( $ips[0] ) && filter_var( $ips[0], FILTER_VALIDATE_IP ) ) {
							return $ips[0];
						}
					}
				}
			}

			// Default to REMOTE_ADDR
			if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
				$remote_addr = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
				if ( filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
					$ip = $remote_addr;
				}
			}

			return $ip;
		}

		/**
		 * Disable self-pingbacks
		 *
		 * @param array $links Links to ping.
		 */
		public function disable_self_pingbacks( &$links ): void {
			$home = home_url();
			foreach ( $links as $l => $link ) {
				if ( str_starts_with( $link, $home ) ) {
					unset( $links[ $l ] );
				}
			}
		}

		/**
		 * Remove X-Pingback header
		 *
		 * @param array $headers HTTP headers.
		 * @return array
		 */
		public function remove_x_pingback( $headers ): array {
			unset( $headers['X-Pingback'] );
			return $headers;
		}

		/**
		 * Clean up wp_head
		 */
		private function cleanup_wp_head(): void {
			// Remove RSD link
			remove_action( 'wp_head', 'rsd_link' );

			// Remove Windows Live Writer manifest link
			remove_action( 'wp_head', 'wlwmanifest_link' );

			// Remove shortlink
			remove_action( 'wp_head', 'wp_shortlink_wp_head' );

			// Remove emoji scripts
			remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
			remove_action( 'wp_print_styles', 'print_emoji_styles' );
			remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
			remove_action( 'admin_print_styles', 'print_emoji_styles' );
		}

		/**
		 * Log security event
		 *
		 * @param string $event_type Event type.
		 * @param string $message Event message.
		 */
		private function log_security_event( string $event_type, string $message ): void {
			if ( ! $this->get_option( 'log_security_events', true ) ) {
				return;
			}

			// Get existing logs
			$logs = get_option( 'wpsh_security_logs', array() );

			// Resolve IP once to avoid calling get_client_ip() twice
			$ip = $this->get_client_ip();

			// Add new log entry
			$logs[] = array(
				'timestamp' => current_time( 'mysql' ),
				'type'      => $event_type,
				'message'   => $message,
				'ip'        => $ip,
			);

			// Keep only last 100 entries
			if ( count( $logs ) > 100 ) {
				$logs = array_slice( $logs, -100 );
			}

			// autoload=false: logs are only needed on the settings page, not on every request
			update_option( 'wpsh_security_logs', $logs, false );
		}

		/**
		 * Add admin menu
		 */
		public function add_admin_menu(): void {
			add_options_page(
				__( 'Security Hardener', 'security-hardener' ),
				__( 'Security Hardener', 'security-hardener' ),
				'manage_options',
				'security-hardener',
				array( $this, 'render_settings_page' )
			);
		}

		/**
		 * Register settings
		 *
		 * Only register_setting() is needed here — sanitize_callback handles validation,
		 * and settings_fields() in the form generates the nonce. Sections and fields are
		 * rendered manually in render_settings_page() via the custom card grid.
		 */
		public function register_settings(): void {
			register_setting(
				'wpsh_settings',
				self::OPTION_NAME,
				array(
					'type'              => 'array',
					'sanitize_callback' => array( $this, 'sanitize_options' ),
				)
			);
		}

		/**
		 * Sanitize options
		 *
		 * @param array $input Raw input.
		 * @return array
		 */
		public function sanitize_options( $input ): array {
			if ( ! is_array( $input ) ) {
				$input = [];
			}

			$sanitized = [];

			// Boolean fields — use match to be explicit about the 1/0 cast.
			$boolean_fields = [
				'disable_file_edit',
				'disable_file_mods',
				'disable_xmlrpc',
				'disable_pingbacks',
				'hide_wp_version',
				'block_user_enum',
				'secure_login',
				'rate_limit_login',
				'header_x_frame',
				'header_x_content',
				'header_referrer',
				'header_permissions',
				'enable_hsts',
				'hsts_subdomains',
				'hsts_preload',
				'clean_head',
				'log_security_events',
				'delete_data_on_uninstall',
			];

			foreach ( $boolean_fields as $field ) {
				$sanitized[ $field ] = match ( true ) {
					! empty( $input[ $field ] ) => 1,
					default                     => 0,
				};
			}

			// Numeric fields
			$raw_attempts = isset( $input['rate_limit_attempts'] ) ? absint( $input['rate_limit_attempts'] ) : 5;
			$sanitized['rate_limit_attempts'] = max( 3, min( 20, $raw_attempts ) );
			if ( $raw_attempts !== $sanitized['rate_limit_attempts'] ) {
				add_settings_error(
					self::OPTION_NAME,
					'rate_limit_attempts_range',
					__( '"Failed attempts before block" must be between 3 and 20. Value has been adjusted.', 'security-hardener' ),
					'warning'
				);
			}

			$raw_minutes = isset( $input['rate_limit_minutes'] ) ? absint( $input['rate_limit_minutes'] ) : 15;
			$sanitized['rate_limit_minutes'] = max( 5, min( 1440, $raw_minutes ) );
			if ( $raw_minutes !== $sanitized['rate_limit_minutes'] ) {
				add_settings_error(
					self::OPTION_NAME,
					'rate_limit_minutes_range',
					__( '"Block duration" must be between 5 and 1440 minutes. Value has been adjusted.', 'security-hardener' ),
					'warning'
				);
			}

			return $sanitized;
		}

		/**
		 * Output inline admin styles for the settings page grid layout and toggles.
		 * Uses only WordPress admin colour variables so it adapts to any admin theme.
		 */
		private function render_admin_styles(): void {
			?>
			<style>
				.wpsh-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin-top:16px;}
				.wpsh-card{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:0;}
				.wpsh-card-header{padding:12px 16px;border-bottom:1px solid #c3c4c7;}
				.wpsh-card-title{margin:0;font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:#646970;}
				.wpsh-card-body{padding:4px 0;}
				.wpsh-row{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:10px 16px;border-bottom:1px solid #f0f0f1;}
				.wpsh-row:last-child{border-bottom:none;}
				.wpsh-row-text{flex:1;min-width:0;}
				.wpsh-row-label{font-size:13px;color:#1d2327;line-height:1.4;}
				.wpsh-row-desc{font-size:12px;color:#646970;margin-top:2px;line-height:1.4;}
				.wpsh-row-number{display:flex;align-items:center;gap:6px;flex-shrink:0;}
				.wpsh-row-number input{width:60px;}
				.wpsh-row-number span{font-size:12px;color:#646970;}
				.wpsh-toggle{position:relative;display:inline-block;width:36px;height:20px;flex-shrink:0;margin-top:1px;}
				.wpsh-toggle input{opacity:0;width:0;height:0;position:absolute;}
				.wpsh-toggle-track{position:absolute;inset:0;background:#c3c4c7;border-radius:20px;transition:background .15s;}
				.wpsh-toggle input:checked~.wpsh-toggle-track{background:var(--wp-admin-theme-color,#2271b1);}
				.wpsh-toggle-thumb{position:absolute;width:14px;height:14px;background:#fff;border-radius:50%;top:3px;left:3px;transition:left .15s;pointer-events:none;}
				.wpsh-toggle input:checked~.wpsh-toggle-thumb{left:19px;}
				.wpsh-toggle input:focus~.wpsh-toggle-track{box-shadow:0 0 0 2px var(--wp-admin-theme-color,#2271b1),0 0 0 4px var(--wp-admin-theme-color-darker-10,rgba(34,113,177,.3));}
				.wpsh-badge{display:inline-block;font-size:10px;font-weight:600;padding:1px 5px;border-radius:3px;margin-left:5px;vertical-align:middle;text-transform:uppercase;letter-spacing:.03em;}
				.wpsh-badge-warn{background:#fcf9e8;color:#996800;border:1px solid #f0c33c;}
				.wpsh-badge-https{background:#f0f6fc;color:var(--wp-admin-theme-color,#2271b1);border:1px solid var(--wp-admin-theme-color-darker-10,#72aee6);}
				.wpsh-hsts-warn{font-size:12px;color:#d63638;padding:8px 16px 0;font-weight:600;}
				.wpsh-section-header{display:flex;align-items:center;justify-content:space-between;padding:20px 0 8px;}
				.wpsh-logs-table{margin-top:8px;}
				.wpsh-save-bar{margin:20px 0 4px;}
				.wpsh-cl-header{display:flex;align-items:center;justify-content:space-between;margin-top:24px;}
				.wpsh-cl-progress{display:flex;align-items:center;gap:8px;}
				.wpsh-cl-bar{height:6px;width:120px;background:#c3c4c7;border-radius:3px;overflow:hidden;}
				.wpsh-cl-bar-fill{height:100%;background:var(--wp-admin-theme-color,#2271b1);border-radius:3px;transition:width .2s;}
				.wpsh-cl-pct{font-size:12px;color:#646970;white-space:nowrap;}
				.wpsh-cl-item{display:flex;align-items:flex-start;gap:10px;padding:10px 16px;border-bottom:1px solid #f0f0f1;cursor:pointer;transition:background .1s;}
				.wpsh-cl-item:last-child{border-bottom:none;}
				.wpsh-cl-item:hover{background:#f6f7f7;}
				.wpsh-cl-item:focus{outline:2px solid var(--wp-admin-theme-color,#2271b1);outline-offset:-2px;}
				.wpsh-cl-item.wpsh-cl-done{background:#f0f6f0;}
				.wpsh-cl-check{flex-shrink:0;width:18px;height:18px;border:1.5px solid #c3c4c7;border-radius:3px;margin-top:1px;display:flex;align-items:center;justify-content:center;transition:all .15s;}
				.wpsh-cl-item.wpsh-cl-done .wpsh-cl-check{background:var(--wp-admin-theme-color,#2271b1);border-color:var(--wp-admin-theme-color,#2271b1);}
				.wpsh-cl-check svg{display:none;}
				.wpsh-cl-item.wpsh-cl-done .wpsh-cl-check svg{display:block;}
				.wpsh-cl-label{font-size:13px;line-height:1.45;color:#1d2327;}
				.wpsh-cl-item.wpsh-cl-done .wpsh-cl-label{color:#646970;text-decoration:line-through;text-decoration-color:#c3c4c7;}
				@media(max-width:1200px){.wpsh-grid{grid-template-columns:repeat(2,minmax(0,1fr));}}
				@media(max-width:782px){.wpsh-grid{grid-template-columns:minmax(0,1fr);}}
			</style>
			<?php
		}

		/**
		 * Render a single card row with a toggle.
		 *
		 * @param string $field_id    Option key.
		 * @param string $label       Row label.
		 * @param string $description Optional description.
		 * @param string $badge_html  Optional badge HTML (already escaped).
		 */
		private function render_toggle_row( string $field_id, string $label, string $description = '', string $badge_html = '' ): void {
			$value      = $this->get_option( $field_id, 0 );
			$checked    = checked( 1, $value, false );
			$input_name = esc_attr( self::OPTION_NAME ) . '[' . esc_attr( $field_id ) . ']';
			?>
			<div class="wpsh-row">
				<div class="wpsh-row-text">
					<div class="wpsh-row-label">
						<?php echo esc_html( $label ); ?>
						<?php echo $badge_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pre-escaped by caller ?>
					</div>
					<?php if ( $description ) : ?>
						<div class="wpsh-row-desc"><?php echo wp_kses_post( $description ); ?></div>
					<?php endif; ?>
				</div>
				<label class="wpsh-toggle">
					<input type="checkbox" name="<?php echo $input_name; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- fully escaped above ?>" value="1" <?php echo $checked; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- output of checked() ?>>
					<div class="wpsh-toggle-track"></div>
					<div class="wpsh-toggle-thumb"></div>
				</label>
			</div>
			<?php
		}

		/**
		 * Render a single card row with a number input.
		 *
		 * @param string $field_id    Field ID.
		 * @param string $label       Row label.
		 * @param int    $min         Minimum value.
		 * @param int    $max         Maximum value.
		 * @param int    $default     Default value.
		 * @param string $unit        Unit label shown after the input.
		 * @param string $description Optional description shown below the label.
		 */
		private function render_number_row( string $field_id, string $label, int $min, int $max, int $default, string $unit = '', string $description = '' ): void {
			$value      = $this->get_option( $field_id, $default );
			$input_name = esc_attr( self::OPTION_NAME ) . '[' . esc_attr( $field_id ) . ']';
			?>
			<div class="wpsh-row">
				<div class="wpsh-row-text">
					<div class="wpsh-row-label"><?php echo esc_html( $label ); ?></div>
					<?php if ( $description ) : ?>
						<div class="wpsh-row-desc"><?php echo esc_html( $description ); ?></div>
					<?php endif; ?>
				</div>
				<div class="wpsh-row-number">
					<input type="number"
						name="<?php echo $input_name; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- fully escaped above ?>"
						value="<?php echo esc_attr( $value ); ?>"
						min="<?php echo absint( $min ); ?>"
						max="<?php echo absint( $max ); ?>"
						class="small-text" />
					<?php if ( $unit ) : ?>
						<span><?php echo esc_html( $unit ); ?></span>
					<?php endif; ?>
				</div>
			</div>
			<?php
		}

		/**
		 * AJAX handler — toggle a single checklist item.
		 *
		 * Expects POST: nonce, item_id (int 0-13), checked (0|1).
		 */
		public function ajax_toggle_checklist(): void {
			check_ajax_referer( 'wpsh_checklist_nonce', 'nonce' );

			if ( ! current_user_can( 'manage_options' ) ) {
				wp_send_json_error( 'Unauthorized', 403 );
			}

			$item_id = isset( $_POST['item_id'] ) ? absint( $_POST['item_id'] ) : null;
			$checked = isset( $_POST['checked'] ) && '1' === $_POST['checked'];

			if ( null === $item_id || $item_id > 13 ) {
				wp_send_json_error( 'Invalid item', 400 );
			}

			$state = get_option( self::CHECKLIST_OPTION, [] );

			if ( $checked ) {
				$state[ $item_id ] = true;
			} else {
				unset( $state[ $item_id ] );
			}

			update_option( self::CHECKLIST_OPTION, $state, false );
			wp_send_json_success( [ 'done' => count( $state ), 'total' => 14 ] );
		}

		/**
		 * AJAX handler — reset all checklist items.
		 *
		 * Expects POST: nonce.
		 */
		public function ajax_reset_checklist(): void {
			check_ajax_referer( 'wpsh_checklist_nonce', 'nonce' );

			if ( ! current_user_can( 'manage_options' ) ) {
				wp_send_json_error( 'Unauthorized', 403 );
			}

			update_option( self::CHECKLIST_OPTION, [], false );
			wp_send_json_success( [ 'done' => 0, 'total' => 14 ] );
		}

		/**
		 * Render the interactive hardening recommendations checklist.
		 *
		 * State is persisted in wpsh_checklist via AJAX (no page reload needed).
		 */
		private function render_checklist(): void {
			$state = get_option( self::CHECKLIST_OPTION, [] );
			$done  = count( $state );
			$total = 14;
			$pct   = $total > 0 ? round( $done / $total * 100 ) : 0;

			$items = [
				__( 'Use strong passwords and enable two-factor authentication', 'security-hardener' ),
				__( 'Keep WordPress, themes, and plugins updated', 'security-hardener' ),
				__( 'Use HTTPS (SSL/TLS) for your entire site', 'security-hardener' ),
				__( 'Regular backups stored off-site', 'security-hardener' ),
				__( 'Limit login attempts at the server/firewall level', 'security-hardener' ),
				__( 'Use security plugins for malware scanning', 'security-hardener' ),
				__( 'Restrict file permissions (directories: 755, files: 644)', 'security-hardener' ),
				__( 'Consider using a Web Application Firewall (WAF)', 'security-hardener' ),
				__( 'Protect the wp-admin directory with an additional HTTP authentication layer (BasicAuth)', 'security-hardener' ),
				__( 'Change the default database table prefix from wp_ to a custom value', 'security-hardener' ),
				__( 'Rename the default admin account to a non-obvious username', 'security-hardener' ),
				__( 'Restrict database user privileges to SELECT, INSERT, UPDATE and DELETE only', 'security-hardener' ),
				__( 'Protect wp-config.php by moving it one directory above the WordPress root or restricting access via .htaccess', 'security-hardener' ),
				__( 'Block direct access to files in wp-includes/ via .htaccess rules — see the WordPress Hardening Guide for the full snippet.', 'security-hardener' ),
			];

			$nonce = wp_create_nonce( 'wpsh_checklist_nonce' );
			?>
			<hr style="margin: 24px 0;">

			<div class="wpsh-cl-header">
				<h2 style="margin:0;"><?php esc_html_e( 'Additional Hardening Recommendations', 'security-hardener' ); ?></h2>
				<div class="wpsh-cl-progress">
					<div class="wpsh-cl-bar">
						<div class="wpsh-cl-bar-fill" id="wpsh-bar-fill" style="width:<?php echo absint( $pct ); ?>%"></div>
					</div>
					<span class="wpsh-cl-pct" id="wpsh-cl-pct">
						<?php
						printf(
							/* translators: 1: completed items, 2: total items */
							esc_html__( '%1$d / %2$d done', 'security-hardener' ),
							absint( $done ),
							absint( $total )
						);
						?>
					</span>
				</div>
			</div>

			<div class="wpsh-card" style="margin-top:12px;" id="wpsh-checklist">
				<?php foreach ( $items as $id => $label ) : ?>
					<div class="wpsh-cl-item<?php echo isset( $state[ $id ] ) ? ' wpsh-cl-done' : ''; ?>"
						data-id="<?php echo absint( $id ); ?>"
						data-nonce="<?php echo esc_attr( $nonce ); ?>"
						role="checkbox"
						aria-checked="<?php echo isset( $state[ $id ] ) ? 'true' : 'false'; ?>"
						tabindex="0">
						<div class="wpsh-cl-check" aria-hidden="true">
							<svg width="10" height="8" viewBox="0 0 10 8" fill="none" xmlns="http://www.w3.org/2000/svg">
								<path d="M1 4l3 3 5-6" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
							</svg>
						</div>
						<span class="wpsh-cl-label"><?php echo esc_html( $label ); ?></span>
					</div>
				<?php endforeach; ?>
			</div>

			<div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px;">
				<p style="margin:0;font-size:12px;color:#646970;">
					<?php esc_html_e( 'Your progress is saved automatically.', 'security-hardener' ); ?>
				</p>
				<button type="button" id="wpsh-cl-reset" class="button-link"
					data-nonce="<?php echo esc_attr( $nonce ); ?>"
					style="font-size:12px;color:#2271b1;">
					<?php esc_html_e( 'Reset all', 'security-hardener' ); ?>
				</button>
			</div>

			<p style="margin-top:16px;">
				<?php
				printf(
					/* translators: %s: URL to WordPress hardening guide */
					wp_kses_post( __( 'For more information, see the official <a href="%s" target="_blank">WordPress Hardening Guide</a>.', 'security-hardener' ) ),
					'https://developer.wordpress.org/advanced-administration/security/hardening/'
				);
				?>
			</p>

			<script>
			(function() {
				var ajaxUrl  = <?php echo wp_json_encode( admin_url( 'admin-ajax.php' ) ); ?>;
				var total    = <?php echo absint( $total ); ?>;
				var doneText = <?php
					/* translators: 1: completed items count, 2: total items count */
					echo wp_json_encode( __( '%1$d / %2$d done', 'security-hardener' ) );
				?>;

				function updateProgress( done ) {
					var pct  = total > 0 ? Math.round( done / total * 100 ) : 0;
					var text = doneText.replace( '%1$d', done ).replace( '%2$d', total );
					document.getElementById( 'wpsh-bar-fill' ).style.width = pct + '%';
					document.getElementById( 'wpsh-cl-pct' ).textContent   = text;
				}

				function sendToggle( id, checked, nonce ) {
					var fd = new FormData();
					fd.append( 'action',  'wpsh_toggle_checklist' );
					fd.append( 'nonce',   nonce );
					fd.append( 'item_id', id );
					fd.append( 'checked', checked ? '1' : '0' );
					fetch( ajaxUrl, { method: 'POST', body: fd, credentials: 'same-origin' } )
						.then( function( r ) { return r.json(); } )
						.then( function( data ) { if ( data.success ) updateProgress( data.data.done ); } );
				}

				document.querySelectorAll( '.wpsh-cl-item' ).forEach( function( el ) {
					function toggle() {
						var done    = el.classList.toggle( 'wpsh-cl-done' );
						var checked = el.classList.contains( 'wpsh-cl-done' );
						el.setAttribute( 'aria-checked', checked ? 'true' : 'false' );
						sendToggle( el.dataset.id, checked, el.dataset.nonce );
					}
					el.addEventListener( 'click', toggle );
					el.addEventListener( 'keydown', function( e ) {
						if ( e.key === ' ' || e.key === 'Enter' ) { e.preventDefault(); toggle(); }
					} );
				} );

				var resetBtn = document.getElementById( 'wpsh-cl-reset' );
				if ( resetBtn ) {
					resetBtn.addEventListener( 'click', function() {
						var fd = new FormData();
						fd.append( 'action', 'wpsh_reset_checklist' );
						fd.append( 'nonce',  resetBtn.dataset.nonce );
						fetch( ajaxUrl, { method: 'POST', body: fd, credentials: 'same-origin' } )
							.then( function( r ) { return r.json(); } )
							.then( function( data ) {
								if ( data.success ) {
									document.querySelectorAll( '.wpsh-cl-item' ).forEach( function( el ) {
										el.classList.remove( 'wpsh-cl-done' );
										el.setAttribute( 'aria-checked', 'false' );
									} );
									updateProgress( 0 );
								}
							} );
					} );
				}
			})();
			</script>
			<?php
		}

		/**
		 * Render settings page
		 */
		public function render_settings_page(): void {
			if ( ! current_user_can( 'manage_options' ) ) {
				wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'security-hardener' ) );
			}

			$this->render_admin_styles();

			$warn_badge  = '<span class="wpsh-badge wpsh-badge-warn">' . esc_html__( 'Caution', 'security-hardener' ) . '</span>';
			$https_badge = '<span class="wpsh-badge wpsh-badge-https">' . esc_html__( 'HTTPS only', 'security-hardener' ) . '</span>';
			?>
			<div class="wrap">
				<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

				<div class="notice notice-info inline" style="margin-top:12px;">
					<p>
						<strong><?php esc_html_e( 'Important:', 'security-hardener' ); ?></strong>
						<?php esc_html_e( 'Test these settings in a staging environment first. Some options may break functionality or third-party integrations.', 'security-hardener' ); ?>
					</p>
				</div>

				<form method="post" action="options.php">
					<?php settings_fields( 'wpsh_settings' ); ?>

					<div class="wpsh-grid">

						<!-- File Editing -->
						<div class="wpsh-card">
							<div class="wpsh-card-header">
								<h2 class="wpsh-card-title"><?php esc_html_e( 'File editing', 'security-hardener' ); ?></h2>
							</div>
							<div class="wpsh-card-body">
								<?php
								$this->render_toggle_row(
									'disable_file_edit',
									__( 'Disable file editor', 'security-hardener' ),
									__( 'Prevents editing theme and plugin files in WordPress admin.', 'security-hardener' )
								);
								$this->render_toggle_row(
									'disable_file_mods',
									__( 'Disable all file modifications', 'security-hardener' ),
									__( 'Blocks plugin/theme updates and installations.', 'security-hardener' ),
									$warn_badge
								);
								?>
							</div>
						</div>

						<!-- XML-RPC & Pingbacks -->
						<div class="wpsh-card">
							<div class="wpsh-card-header">
								<h2 class="wpsh-card-title"><?php esc_html_e( 'XML-RPC &amp; pingbacks', 'security-hardener' ); ?></h2>
							</div>
							<div class="wpsh-card-body">
								<?php
								$this->render_toggle_row(
									'disable_xmlrpc',
									__( 'Disable XML-RPC', 'security-hardener' ),
									__( 'Recommended unless you use Jetpack or the mobile app.', 'security-hardener' )
								);
								$this->render_toggle_row(
									'disable_pingbacks',
									__( 'Disable pingbacks', 'security-hardener' ),
									__( 'Removes the X-Pingback header and disables incoming and self-referencing pingbacks.', 'security-hardener' )
								);
								?>
							</div>
						</div>

						<!-- User Enumeration -->
						<div class="wpsh-card">
							<div class="wpsh-card-header">
								<h2 class="wpsh-card-title"><?php esc_html_e( 'User enumeration', 'security-hardener' ); ?></h2>
							</div>
							<div class="wpsh-card-body">
								<?php
								$this->render_toggle_row(
									'block_user_enum',
									__( 'Block user enumeration', 'security-hardener' ),
									__( 'Blocks ?author=N queries, canonical redirects, REST API user endpoints, and removes users from sitemaps.', 'security-hardener' )
								);
								?>
							</div>
						</div>

						<!-- Login Security -->
						<div class="wpsh-card">
							<div class="wpsh-card-header">
								<h2 class="wpsh-card-title"><?php esc_html_e( 'Login security', 'security-hardener' ); ?></h2>
							</div>
							<div class="wpsh-card-body">
								<?php
								$this->render_toggle_row(
									'secure_login',
									__( 'Generic login errors', 'security-hardener' ),
									__( "Don't reveal whether the username or password was incorrect.", 'security-hardener' )
								);
								$this->render_toggle_row(
									'rate_limit_login',
									__( 'Login rate limiting', 'security-hardener' ),
									__( 'Blocks an IP after repeated failed login attempts.', 'security-hardener' )
								);
								$this->render_number_row(
									'rate_limit_attempts',
									__( 'Failed attempts before block', 'security-hardener' ),
									3, 20, 5,
									__( 'attempts', 'security-hardener' ),
									__( 'Min. 3 — Max. 20', 'security-hardener' )
								);
								$this->render_number_row(
									'rate_limit_minutes',
									__( 'Block duration', 'security-hardener' ),
									5, 1440, 15,
									__( 'minutes', 'security-hardener' ),
									__( 'Min. 5 — Max. 1440', 'security-hardener' )
								);
								?>
							</div>
						</div>

						<!-- Security Headers -->
						<div class="wpsh-card">
							<div class="wpsh-card-header">
								<h2 class="wpsh-card-title"><?php esc_html_e( 'Security headers', 'security-hardener' ); ?></h2>
							</div>
							<div class="wpsh-card-body">
								<?php
								$this->render_toggle_row(
									'header_x_frame',
									__( 'X-Frame-Options', 'security-hardener' ),
									__( 'Clickjacking protection. Set to SAMEORIGIN.', 'security-hardener' )
								);
								$this->render_toggle_row(
									'header_x_content',
									__( 'X-Content-Type-Options', 'security-hardener' ),
									__( 'MIME sniffing protection. Set to nosniff.', 'security-hardener' )
								);
								$this->render_toggle_row(
									'header_referrer',
									__( 'Referrer-Policy', 'security-hardener' ),
									__( 'Controls referrer information sent to external sites. Set to strict-origin-when-cross-origin.', 'security-hardener' )
								);
								$this->render_toggle_row(
									'header_permissions',
									__( 'Permissions-Policy', 'security-hardener' ),
									__( 'Restricts access to geolocation, microphone and camera.', 'security-hardener' )
								);
								?>
							</div>
						</div>

						<!-- HSTS -->
						<div class="wpsh-card">
							<div class="wpsh-card-header">
								<h2 class="wpsh-card-title">
									<?php esc_html_e( 'HSTS', 'security-hardener' ); ?>
									<?php echo $https_badge; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pre-escaped ?>
								</h2>
							</div>
							<div class="wpsh-card-body">
								<?php if ( ! is_ssl() ) : ?>
									<p class="wpsh-hsts-warn"><?php esc_html_e( '⚠ Your site is not using HTTPS. Do not enable HSTS.', 'security-hardener' ); ?></p>
								<?php endif; ?>
								<?php
								$this->render_toggle_row(
									'enable_hsts',
									__( 'Enable HSTS', 'security-hardener' ),
									__( 'Forces HTTPS. Only enable if your entire site supports HTTPS.', 'security-hardener' )
								);
								$this->render_toggle_row(
									'hsts_subdomains',
									__( 'Include subdomains', 'security-hardener' ),
									__( 'Applies the HSTS policy to all subdomains. Only enable if all your subdomains also use HTTPS.', 'security-hardener' )
								);
								$this->render_toggle_row(
									'hsts_preload',
									__( 'Enable preload', 'security-hardener' ),
									sprintf(
										/* translators: %s: URL to HSTS preload list */
										wp_kses_post( __( 'Adds the preload directive to the HSTS header. Required before submitting manually to <a href="%s" target="_blank">hstspreload.org</a>.', 'security-hardener' ) ),
										'https://hstspreload.org/'
									)
								);
								?>
							</div>
						</div>

						<!-- Other Settings -->
						<div class="wpsh-card">
							<div class="wpsh-card-header">
								<h2 class="wpsh-card-title"><?php esc_html_e( 'Other settings', 'security-hardener' ); ?></h2>
							</div>
							<div class="wpsh-card-body">
								<?php
								$this->render_toggle_row(
									'hide_wp_version',
									__( 'Hide WordPress version', 'security-hardener' ),
									__( 'Removes the generator meta tag and WordPress version from asset URLs (?ver=).', 'security-hardener' )
								);
								$this->render_toggle_row(
									'clean_head',
									__( 'Clean wp_head', 'security-hardener' ),
									__( 'Removes RSD link, Windows Live Writer manifest, shortlink, and emoji scripts from the page head.', 'security-hardener' )
								);
								$this->render_toggle_row(
									'log_security_events',
									__( 'Log security events', 'security-hardener' ),
									__( 'Keeps a log of the last 100 security events.', 'security-hardener' )
								);
								$this->render_toggle_row(
									'delete_data_on_uninstall',
									__( 'Delete all data on uninstall', 'security-hardener' ),
									__( 'Permanently deletes all settings and logs on uninstall. Disabled by default.', 'security-hardener' ),
									$warn_badge
								);
								?>
							</div>
						</div>

					</div><!-- .wpsh-grid -->

					<div class="wpsh-save-bar">
						<?php submit_button( null, 'primary', 'submit', false ); ?>
					</div>

				</form>

				<?php $this->render_security_logs(); ?>

				<?php $this->render_file_permissions(); ?>

				<?php $this->render_checklist(); ?>

			</div><!-- .wrap -->
			<?php
		}

		/**
		 * Render security logs section
		 */
		private function render_security_logs(): void {
			if ( ! $this->get_option( 'log_security_events', true ) ) {
				return;
			}

			$logs = get_option( 'wpsh_security_logs', array() );

			if ( empty( $logs ) ) {
				return;
			}

			// Reverse to show newest first, limit to 20
			$logs = array_slice( array_reverse( $logs ), 0, 20 );
			?>
			<hr style="margin: 24px 0;">
			<div class="wpsh-section-header">
				<h2 style="margin: 0;"><?php esc_html_e( 'Recent Security Events', 'security-hardener' ); ?></h2>
				<form method="post" action="">
					<?php wp_nonce_field( 'wpsh_clear_logs' ); ?>
					<input type="hidden" name="wpsh_action" value="clear_logs" />
					<button type="submit" class="button">
						<?php esc_html_e( 'Clear Logs', 'security-hardener' ); ?>
					</button>
				</form>
			</div>
			<table class="wp-list-table widefat fixed striped wpsh-logs-table">
				<thead>
					<tr>
						<th style="width:160px;"><?php esc_html_e( 'Timestamp', 'security-hardener' ); ?></th>
						<th style="width:140px;"><?php esc_html_e( 'Event Type', 'security-hardener' ); ?></th>
						<th><?php esc_html_e( 'Message', 'security-hardener' ); ?></th>
						<th style="width:120px;"><?php esc_html_e( 'IP Address', 'security-hardener' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $logs as $log ) : ?>
						<tr>
							<td><?php echo esc_html( $log['timestamp'] ); ?></td>
							<td><?php echo esc_html( $log['type'] ); ?></td>
							<td><?php echo esc_html( $log['message'] ); ?></td>
							<td><?php echo esc_html( $log['ip'] ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<?php
		}

		/**
		 * Show admin notices
		 */
		public function show_admin_notices(): void {
			// Clear logs action — verify nonce and capability via POST
			$wpsh_action = isset( $_POST['wpsh_action'] ) ? sanitize_key( wp_unslash( $_POST['wpsh_action'] ) ) : '';
			if (
				'clear_logs' === $wpsh_action &&
				current_user_can( 'manage_options' )
			) {
				if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'wpsh_clear_logs' ) ) {
					wp_die( esc_html__( 'Security check failed.', 'security-hardener' ) );
				}
				delete_option( 'wpsh_security_logs' );
				?>
				<div class="notice notice-success is-dismissible">
					<p><?php esc_html_e( 'Security logs cleared.', 'security-hardener' ); ?></p>
				</div>
				<?php
			}
		}

		/**
		 * Render file permissions check as an inline section on the settings page.
		 *
		 * Shows a success notice when all paths are correct, or a table listing
		 * only the paths with issues when problems are found.
		 */
		private function render_file_permissions(): void {
			if ( ! function_exists( 'get_home_path' ) ) {
				require_once ABSPATH . 'wp-admin/includes/file.php';
			}

			$upload_dir = wp_upload_dir();
			$checks     = array(
				array(
					'path'        => ABSPATH . 'wp-config.php',
					'recommended' => array( '0600', '0640', '0644' ),
					'label'       => 'wp-config.php',
				),
				array(
					'path'        => get_home_path(),
					'recommended' => array( '0755', '0750' ),
					'label'       => __( 'WordPress root directory', 'security-hardener' ),
				),
				array(
					'path'        => WP_CONTENT_DIR,
					'recommended' => array( '0755', '0750' ),
					'label'       => 'wp-content',
				),
				array(
					'path'        => $upload_dir['basedir'],
					'recommended' => array( '0755', '0750' ),
					'label'       => __( 'Uploads directory', 'security-hardener' ),
				),
			);

			$issues = array();

			foreach ( $checks as $check ) {
				if ( ! file_exists( $check['path'] ) ) {
					continue;
				}
				$perms = substr( sprintf( '%o', fileperms( $check['path'] ) ), -4 );
				if ( ! in_array( $perms, $check['recommended'], true ) ) {
					$issues[] = array(
						'label'       => $check['label'],
						'current'     => $perms,
						'recommended' => implode( ', ', $check['recommended'] ),
					);
				}
			}
			?>
			<hr style="margin:24px 0;">
			<h2><?php esc_html_e( 'File Permissions', 'security-hardener' ); ?></h2>

			<?php if ( empty( $issues ) ) : ?>
				<div style="display:flex;align-items:center;gap:8px;padding:10px 14px;background:#f0f6f0;border:1px solid #c3c4c7;border-radius:4px;font-size:13px;color:#1d2327;">
					<span style="width:8px;height:8px;border-radius:50%;background:#00a32a;flex-shrink:0;display:inline-block;"></span>
					<?php esc_html_e( 'All checked paths have correct file permissions.', 'security-hardener' ); ?>
				</div>
			<?php else : ?>
				<div style="border:1px solid #c3c4c7;border-radius:4px;overflow:hidden;">
					<table class="wp-list-table widefat fixed striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Path', 'security-hardener' ); ?></th>
								<th style="width:120px;"><?php esc_html_e( 'Current', 'security-hardener' ); ?></th>
								<th style="width:200px;"><?php esc_html_e( 'Recommended', 'security-hardener' ); ?></th>
								<th style="width:140px;"><?php esc_html_e( 'Status', 'security-hardener' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $issues as $issue ) : ?>
								<tr>
									<td><code><?php echo esc_html( $issue['label'] ); ?></code></td>
									<td><code><?php echo esc_html( $issue['current'] ); ?></code></td>
									<td><code><?php echo esc_html( $issue['recommended'] ); ?></code></td>
									<td>
										<span style="display:inline-flex;align-items:center;gap:5px;">
											<span style="width:7px;height:7px;border-radius:50%;background:#d63638;display:inline-block;flex-shrink:0;"></span>
											<?php esc_html_e( 'Too permissive', 'security-hardener' ); ?>
										</span>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				</div>
			<?php endif; ?>

			<p style="font-size:12px;color:#646970;margin-top:8px;">
				<?php
				printf(
					/* translators: %s: URL to file permissions documentation */
					wp_kses_post( __( 'Learn more about <a href="%s" target="_blank">WordPress file permissions</a>.', 'security-hardener' ) ),
					'https://developer.wordpress.org/advanced-administration/server/file-permissions/'
				);
				?>
			</p>
			<?php
		}

		/**
		 * Add settings link to plugins page
		 *
		 * @param array $links Plugin action links.
		 * @return array
		 */
		public function add_settings_link( $links ): array {
			$settings_link = sprintf(
				'<a href="%s">%s</a>',
				esc_url( admin_url( 'options-general.php?page=security-hardener' ) ),
				esc_html__( 'Settings', 'security-hardener' )
			);
			array_unshift( $links, $settings_link );
			return $links;
		}
	}

endif;

// Initialize plugin
WPHN_Hardener::get_instance();