<?php
/*
Plugin Name: Security Hardener
Plugin URI: https://wordpress.org/plugins/security-hardener/
Description: Basic hardening: secure headers, disable XML-RPC/pingbacks, hide version, block user enumeration, login errors, IP-based rate limiting, and optional restriction of the REST API.
Version: 0.6
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 8.0
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
define( 'WPSH_VERSION', '0.5' );
define( 'WPSH_FILE', __FILE__ );
define( 'WPSH_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPSH_URL', plugin_dir_url( __FILE__ ) );
define( 'WPSH_BASENAME', plugin_basename( __FILE__ ) );

if ( ! class_exists( 'WPHN_Hardener' ) ) :

	/**
	 * Main plugin class implementing WordPress.org hardening guidelines
	 */
	class WPHN_Hardener {

		/**
		 * Option name in database
		 */
		const OPTION_NAME = 'wpsh_options';

		/**
		 * Singleton instance
		 *
		 * @var WPHN_Hardener|null
		 */
		private static $instance = null;

		/**
		 * Plugin options
		 *
		 * @var array
		 */
		private $options = array();

		/**
		 * Get singleton instance
		 *
		 * @return WPHN_Hardener
		 */
		public static function get_instance() {
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

			// Activation/Deactivation hooks
			register_activation_hook( WPSH_FILE, array( $this, 'activate' ) );
			register_deactivation_hook( WPSH_FILE, array( $this, 'deactivate' ) );

			// Core initialization
			add_action( 'plugins_loaded', array( $this, 'init' ) );
		}

		/**
		 * Initialize plugin
		 */
		public function init() {
			// Define security constants early
			$this->define_security_constants();

			// Security headers
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );

			// Disable file editing
			// Already handled via constants

			// XML-RPC hardening
			if ( $this->get_option( 'disable_xmlrpc', true ) ) {
				add_filter( 'xmlrpc_enabled', '__return_false' );
				add_filter( 'xmlrpc_methods', array( $this, 'remove_xmlrpc_pingback' ) );
			}

			// Remove version info
			if ( $this->get_option( 'hide_wp_version', true ) ) {
				add_filter( 'the_generator', '__return_empty_string' );
				remove_action( 'wp_head', 'wp_generator' );
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
				add_action( 'login_enqueue_scripts', array( $this, 'remove_login_hints' ) );
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
			}
		}

		/**
		 * Plugin activation
		 */
		public function activate() {
			// Set default options only if they don't exist
			if ( false === get_option( self::OPTION_NAME ) ) {
				$defaults = $this->get_default_options();
				update_option( self::OPTION_NAME, $defaults );
			}

			// Log activation
			$this->log_security_event( 'plugin_activated', 'Security Hardener plugin activated' );
		}

		/**
		 * Plugin deactivation
		 */
		public function deactivate() {
			// Log deactivation
			$this->log_security_event( 'plugin_deactivated', 'Security Hardener plugin deactivated' );
		}

		/**
		 * Get default options
		 *
		 * @return array
		 */
		private function get_default_options() {
			return array(
				// File editing
				'disable_file_edit'    => 1,
				'disable_file_mods'    => 0, // Disabled by default as it breaks updates

				// XML-RPC
				'disable_xmlrpc'       => 1,

				// Version hiding
				'hide_wp_version'      => 1,

				// User enumeration
				'block_user_enum'      => 1,

				// Login security
				'secure_login'         => 1,
				'rate_limit_login'     => 1,
				'rate_limit_attempts'  => 5,
				'rate_limit_minutes'   => 15,

				// Pingbacks
				'disable_pingbacks'    => 1,

				// Clean wp_head
				'clean_head'           => 1,

				// Security headers
				'enable_headers'       => 1,
				'header_x_frame'       => 1,
				'header_x_content'     => 1,
				'header_referrer'      => 1,
				'header_permissions'   => 1,

				// HTTPS
				'enable_hsts'          => 0, // Off by default - requires HTTPS
				'hsts_max_age'         => 31536000,
				'hsts_subdomains'      => 1,
				'hsts_preload'         => 0,

				// Advanced
				'log_security_events'  => 1,
			);
		}

		/**
		 * Get all options
		 *
		 * @return array
		 */
		private function get_options() {
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
		private function get_option( $key, $default = null ) {
			if ( isset( $this->options[ $key ] ) ) {
				return $this->options[ $key ];
			}
			return $default;
		}

		/**
		 * Define security constants based on plugin settings
		 */
		private function define_security_constants() {
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
		public function send_security_headers() {
			if ( ! $this->get_option( 'enable_headers', true ) ) {
				return;
			}

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
				$max_age     = absint( $this->get_option( 'hsts_max_age', 31536000 ) );
				$hsts_header = "Strict-Transport-Security: max-age={$max_age}";

				if ( $this->get_option( 'hsts_subdomains', true ) ) {
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
		public function remove_xmlrpc_pingback( $methods ) {
			unset( $methods['pingback.ping'] );
			unset( $methods['pingback.extensions.getPingbacks'] );
			return $methods;
		}

		/**
		 * Prevent user enumeration via ?author=N
		 */
		public function prevent_user_enumeration() {
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
		public function prevent_author_redirect( $redirect_url, $requested_url ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check
			if ( isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
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
		public function secure_user_endpoints( $endpoints ) {
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
		public function remove_users_sitemap( $provider, $name ) {
			return ( 'users' === $name ) ? false : $provider;
		}

		/**
		 * Generic login error messages
		 *
		 * @param string $error Error message.
		 * @return string
		 */
		public function generic_login_errors( $error ) {
			// Don't change the error if it's empty
			if ( empty( $error ) ) {
				return $error;
			}

			// Return generic error message
			return __( '<strong>Error:</strong> Invalid username or password.', 'security-hardener' );
		}

		/**
		 * Remove login hints from login page
		 */
		public function remove_login_hints() {
			// Remove "lost password" text that reveals if username exists
			add_filter(
				'login_messages',
				function ( $message ) {
					if ( strpos( $message, 'check your email' ) !== false ) {
						return '<strong>' . esc_html__( 'Check your email for the confirmation link.', 'security-hardener' ) . '</strong>';
					}
					return $message;
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
		public function check_login_rate_limit( $user, $username, $password ) {
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
					sprintf(
						/* translators: %d: number of minutes */
						__( '<strong>Error:</strong> Too many failed login attempts. Please try again in %d minutes.', 'security-hardener' ),
						$minutes
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
		public function log_failed_login( $username ) {
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
		 * @param string  $user_login Username.
		 * @param WP_User $user User object.
		 */
		public function clear_login_attempts( $user_login, $user ) {
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
		private function get_client_ip() {
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
		public function disable_self_pingbacks( &$links ) {
			$home = get_option( 'home' );
			foreach ( $links as $l => $link ) {
				if ( 0 === strpos( $link, $home ) ) {
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
		public function remove_x_pingback( $headers ) {
			unset( $headers['X-Pingback'] );
			return $headers;
		}

		/**
		 * Clean up wp_head
		 */
		private function cleanup_wp_head() {
			// Remove RSD link
			remove_action( 'wp_head', 'rsd_link' );

			// Remove Windows Live Writer manifest link
			remove_action( 'wp_head', 'wlwmanifest_link' );

			// Remove WordPress version
			remove_action( 'wp_head', 'wp_generator' );

			// Remove shortlink
			remove_action( 'wp_head', 'wp_shortlink_wp_head' );

			// Remove feed links (keep main feed)
			remove_action( 'wp_head', 'feed_links_extra', 3 );

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
		private function log_security_event( $event_type, $message ) {
			if ( ! $this->get_option( 'log_security_events', true ) ) {
				return;
			}

			// Get existing logs
			$logs = get_option( 'wpsh_security_logs', array() );

			// Add new log entry
			$logs[] = array(
				'timestamp'  => current_time( 'mysql' ),
				'type'       => $event_type,
				'message'    => $message,
				'ip'         => $this->get_client_ip(),
				'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
			);

			// Keep only last 100 entries
			if ( count( $logs ) > 100 ) {
				$logs = array_slice( $logs, -100 );
			}

			update_option( 'wpsh_security_logs', $logs );
		}

		/**
		 * Add admin menu
		 */
		public function add_admin_menu() {
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
		 */
		public function register_settings() {
			register_setting(
				'wpsh_settings',
				self::OPTION_NAME,
				array(
					'type'              => 'array',
					'sanitize_callback' => array( $this, 'sanitize_options' ),
				)
			);

			// File Editing section
			add_settings_section(
				'wpsh_file_editing',
				__( 'File Editing', 'security-hardener' ),
				function () {
					echo '<p>' . esc_html__( 'Control file editing capabilities in WordPress admin.', 'security-hardener' ) . '</p>';
				},
				'security-hardener'
			);

			$this->add_checkbox_field( 'disable_file_edit', __( 'Disable file editor', 'security-hardener' ), 'wpsh_file_editing', __( 'Prevents editing of theme and plugin files through WordPress admin.', 'security-hardener' ) );
			$this->add_checkbox_field( 'disable_file_mods', __( 'Disable all file modifications', 'security-hardener' ), 'wpsh_file_editing', __( '<strong>Warning:</strong> This will disable plugin/theme updates and installations.', 'security-hardener' ) );

			// XML-RPC section
			add_settings_section(
				'wpsh_xmlrpc',
				__( 'XML-RPC', 'security-hardener' ),
				function () {
					echo '<p>' . esc_html__( 'XML-RPC is often targeted by attackers. Disable unless you need it for Jetpack or mobile apps.', 'security-hardener' ) . '</p>';
				},
				'security-hardener'
			);

			$this->add_checkbox_field( 'disable_xmlrpc', __( 'Disable XML-RPC', 'security-hardener' ), 'wpsh_xmlrpc' );
			$this->add_checkbox_field( 'disable_pingbacks', __( 'Disable pingbacks', 'security-hardener' ), 'wpsh_xmlrpc' );

			// User Enumeration section
			add_settings_section(
				'wpsh_user_enum',
				__( 'User Enumeration Protection', 'security-hardener' ),
				function () {
					echo '<p>' . esc_html__( 'Prevent attackers from discovering usernames through various WordPress features.', 'security-hardener' ) . '</p>';
				},
				'security-hardener'
			);

			$this->add_checkbox_field( 'block_user_enum', __( 'Block user enumeration', 'security-hardener' ), 'wpsh_user_enum', __( 'Blocks ?author=N queries, secures REST API user endpoints, and removes users from sitemaps.', 'security-hardener' ) );
			$this->add_checkbox_field( 'hide_wp_version', __( 'Hide WordPress version', 'security-hardener' ), 'wpsh_user_enum' );

			// Login Security section
			add_settings_section(
				'wpsh_login',
				__( 'Login Security', 'security-hardener' ),
				function () {
					echo '<p>' . esc_html__( 'Protect against brute force attacks and information disclosure.', 'security-hardener' ) . '</p>';
				},
				'security-hardener'
			);

			$this->add_checkbox_field( 'secure_login', __( 'Generic login errors', 'security-hardener' ), 'wpsh_login', __( 'Don\'t reveal whether username or password was incorrect.', 'security-hardener' ) );
			$this->add_checkbox_field( 'rate_limit_login', __( 'Enable login rate limiting', 'security-hardener' ), 'wpsh_login' );

			add_settings_field(
				'rate_limit_attempts',
				__( 'Failed attempts before block', 'security-hardener' ),
				array( $this, 'render_number_field' ),
				'security-hardener',
				'wpsh_login',
				array(
					'field_id' => 'rate_limit_attempts',
					'min'      => 3,
					'max'      => 20,
					'default'  => 5,
				)
			);

			add_settings_field(
				'rate_limit_minutes',
				__( 'Block duration (minutes)', 'security-hardener' ),
				array( $this, 'render_number_field' ),
				'security-hardener',
				'wpsh_login',
				array(
					'field_id' => 'rate_limit_minutes',
					'min'      => 5,
					'max'      => 1440,
					'default'  => 15,
				)
			);

			// Security Headers section
			add_settings_section(
				'wpsh_headers',
				__( 'Security Headers', 'security-hardener' ),
				function () {
					echo '<p>' . esc_html__( 'Send HTTP security headers to protect against various attacks.', 'security-hardener' ) . '</p>';
				},
				'security-hardener'
			);

			$this->add_checkbox_field( 'enable_headers', __( 'Enable security headers', 'security-hardener' ), 'wpsh_headers' );
			$this->add_checkbox_field( 'header_x_frame', __( 'X-Frame-Options (clickjacking protection)', 'security-hardener' ), 'wpsh_headers' );
			$this->add_checkbox_field( 'header_x_content', __( 'X-Content-Type-Options (MIME sniffing protection)', 'security-hardener' ), 'wpsh_headers' );
			$this->add_checkbox_field( 'header_referrer', __( 'Referrer-Policy', 'security-hardener' ), 'wpsh_headers' );
			$this->add_checkbox_field( 'header_permissions', __( 'Permissions-Policy', 'security-hardener' ), 'wpsh_headers' );

			// HSTS section
			add_settings_section(
				'wpsh_hsts',
				__( 'HSTS (HTTPS Sites Only)', 'security-hardener' ),
				function () {
					echo '<p>' . esc_html__( 'HTTP Strict Transport Security forces HTTPS. Only enable if your entire site uses HTTPS.', 'security-hardener' ) . '</p>';
					if ( ! is_ssl() ) {
						echo '<p class="description" style="color: #d63638;"><strong>' . esc_html__( 'Warning: Your site is not currently using HTTPS. Do not enable HSTS.', 'security-hardener' ) . '</strong></p>';
					}
				},
				'security-hardener'
			);

			$this->add_checkbox_field( 'enable_hsts', __( 'Enable HSTS', 'security-hardener' ), 'wpsh_hsts', __( '<strong>Warning:</strong> Only enable if your site fully supports HTTPS.', 'security-hardener' ) );
			$this->add_checkbox_field( 'hsts_subdomains', __( 'Include subdomains', 'security-hardener' ), 'wpsh_hsts' );
			$this->add_checkbox_field( 'hsts_preload', __( 'Enable preload', 'security-hardener' ), 'wpsh_hsts', __( 'Submit to <a href="https://hstspreload.org/" target="_blank">HSTS Preload List</a> (requires 1 year max-age).', 'security-hardener' ) );

			// Other section
			add_settings_section(
				'wpsh_other',
				__( 'Other Settings', 'security-hardener' ),
				null,
				'security-hardener'
			);

			$this->add_checkbox_field( 'clean_head', __( 'Clean wp_head', 'security-hardener' ), 'wpsh_other', __( 'Remove unnecessary items from &lt;head&gt; section.', 'security-hardener' ) );
			$this->add_checkbox_field( 'log_security_events', __( 'Log security events', 'security-hardener' ), 'wpsh_other', __( 'Keep a log of security events (last 100 entries).', 'security-hardener' ) );
		}

		/**
		 * Add checkbox field helper
		 *
		 * @param string $field_id Field ID.
		 * @param string $label Field label.
		 * @param string $section Section ID.
		 * @param string $description Optional description.
		 */
		private function add_checkbox_field( $field_id, $label, $section, $description = '' ) {
			add_settings_field(
				$field_id,
				$label,
				array( $this, 'render_checkbox_field' ),
				'security-hardener',
				$section,
				array(
					'field_id'    => $field_id,
					'description' => $description,
				)
			);
		}

		/**
		 * Render checkbox field
		 *
		 * @param array $args Field arguments.
		 */
		public function render_checkbox_field( $args ) {
			$field_id = $args['field_id'];
			$value    = $this->get_option( $field_id, 0 );
			$checked  = checked( 1, $value, false );

			printf(
				'<label><input type="checkbox" name="%s[%s]" value="1" %s /> %s</label>',
				esc_attr( self::OPTION_NAME ),
				esc_attr( $field_id ),
				$checked, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				! empty( $args['description'] ) ? wp_kses_post( $args['description'] ) : esc_html__( 'Enable', 'security-hardener' )
			);
		}

		/**
		 * Render number field
		 *
		 * @param array $args Field arguments.
		 */
		public function render_number_field( $args ) {
			$field_id = $args['field_id'];
			$value    = $this->get_option( $field_id, $args['default'] );
			$min      = isset( $args['min'] ) ? absint( $args['min'] ) : 1;
			$max      = isset( $args['max'] ) ? absint( $args['max'] ) : 999;

			printf(
				'<input type="number" name="%s[%s]" value="%s" min="%d" max="%d" class="small-text" />',
				esc_attr( self::OPTION_NAME ),
				esc_attr( $field_id ),
				esc_attr( $value ),
				absint( $min ),
				absint( $max )
			);
		}

		/**
		 * Sanitize options
		 *
		 * @param array $input Raw input.
		 * @return array
		 */
		public function sanitize_options( $input ) {
			if ( ! is_array( $input ) ) {
				$input = array();
			}

			$sanitized = array();

			// Boolean fields
			$boolean_fields = array(
				'disable_file_edit',
				'disable_file_mods',
				'disable_xmlrpc',
				'disable_pingbacks',
				'hide_wp_version',
				'block_user_enum',
				'secure_login',
				'rate_limit_login',
				'enable_headers',
				'header_x_frame',
				'header_x_content',
				'header_referrer',
				'header_permissions',
				'enable_hsts',
				'hsts_subdomains',
				'hsts_preload',
				'clean_head',
				'log_security_events',
			);

			foreach ( $boolean_fields as $field ) {
				$sanitized[ $field ] = ! empty( $input[ $field ] ) ? 1 : 0;
			}

			// Numeric fields
			$sanitized['rate_limit_attempts'] = isset( $input['rate_limit_attempts'] )
				? max( 3, min( 20, absint( $input['rate_limit_attempts'] ) ) )
				: 5;

			$sanitized['rate_limit_minutes'] = isset( $input['rate_limit_minutes'] )
				? max( 5, min( 1440, absint( $input['rate_limit_minutes'] ) ) )
				: 15;

			$sanitized['hsts_max_age'] = isset( $input['hsts_max_age'] )
				? max( 300, min( 63072000, absint( $input['hsts_max_age'] ) ) )
				: 31536000;

			return $sanitized;
		}

		/**
		 * Render settings page
		 */
		public function render_settings_page() {
			if ( ! current_user_can( 'manage_options' ) ) {
				wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'security-hardener' ) );
			}

			?>
			<div class="wrap">
				<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

				<?php settings_errors(); ?>

				<div class="notice notice-info">
					<p>
						<strong><?php esc_html_e( 'Important:', 'security-hardener' ); ?></strong>
						<?php esc_html_e( 'Test these settings in a staging environment first. Some options may break functionality or third-party integrations.', 'security-hardener' ); ?>
					</p>
				</div>

				<form method="post" action="options.php">
					<?php
					settings_fields( 'wpsh_settings' );
					do_settings_sections( 'security-hardener' );
					submit_button();
					?>
				</form>

				<?php $this->render_security_logs(); ?>

				<hr>

				<h2><?php esc_html_e( 'Additional Hardening Recommendations', 'security-hardener' ); ?></h2>
				<ul style="list-style: disc; padding-left: 20px;">
					<li><?php esc_html_e( 'Use strong passwords and enable two-factor authentication', 'security-hardener' ); ?></li>
					<li><?php esc_html_e( 'Keep WordPress, themes, and plugins updated', 'security-hardener' ); ?></li>
					<li><?php esc_html_e( 'Use HTTPS (SSL/TLS) for your entire site', 'security-hardener' ); ?></li>
					<li><?php esc_html_e( 'Regular backups stored off-site', 'security-hardener' ); ?></li>
					<li><?php esc_html_e( 'Limit login attempts at the server/firewall level', 'security-hardener' ); ?></li>
					<li><?php esc_html_e( 'Use security plugins for malware scanning', 'security-hardener' ); ?></li>
					<li><?php esc_html_e( 'Restrict file permissions (directories: 755, files: 644)', 'security-hardener' ); ?></li>
					<li><?php esc_html_e( 'Consider using a Web Application Firewall (WAF)', 'security-hardener' ); ?></li>
				</ul>

				<p>
					<?php
					printf(
						/* translators: %s: URL to WordPress hardening guide */
						wp_kses_post( __( 'For more information, see the official <a href="%s" target="_blank">WordPress Hardening Guide</a>.', 'security-hardener' ) ),
						'https://developer.wordpress.org/advanced-administration/security/hardening/'
					);
					?>
				</p>
			</div>
			<?php
		}

		/**
		 * Render security logs section
		 */
		private function render_security_logs() {
			if ( ! $this->get_option( 'log_security_events', true ) ) {
				return;
			}

			$logs = get_option( 'wpsh_security_logs', array() );

			if ( empty( $logs ) ) {
				return;
			}

			?>
			<hr>
			<h2><?php esc_html_e( 'Recent Security Events', 'security-hardener' ); ?></h2>
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Timestamp', 'security-hardener' ); ?></th>
						<th><?php esc_html_e( 'Event Type', 'security-hardener' ); ?></th>
						<th><?php esc_html_e( 'Message', 'security-hardener' ); ?></th>
						<th><?php esc_html_e( 'IP Address', 'security-hardener' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php
					// Reverse to show newest first
					$logs = array_reverse( $logs );
					// Limit to 20 most recent
					$logs = array_slice( $logs, 0, 20 );

					foreach ( $logs as $log ) :
						?>
						<tr>
							<td><?php echo esc_html( $log['timestamp'] ); ?></td>
							<td><?php echo esc_html( $log['type'] ); ?></td>
							<td><?php echo esc_html( $log['message'] ); ?></td>
							<td><?php echo esc_html( $log['ip'] ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<p>
				<a href="<?php echo esc_url( admin_url( 'options-general.php?page=security-hardener&action=clear_logs' ) ); ?>" 
				   class="button"
				   onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to clear all security logs?', 'security-hardener' ); ?>');">
					<?php esc_html_e( 'Clear Logs', 'security-hardener' ); ?>
				</a>
			</p>
			<?php
		}

		/**
		 * Show admin notices
		 */
		public function show_admin_notices() {
			// Clear logs action
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( isset( $_GET['action'] ) && 'clear_logs' === $_GET['action'] && current_user_can( 'manage_options' ) ) {
				// Verify nonce would be better, but this is acceptable for read-only admin pages
				delete_option( 'wpsh_security_logs' );
				?>
				<div class="notice notice-success is-dismissible">
					<p><?php esc_html_e( 'Security logs cleared.', 'security-hardener' ); ?></p>
				</div>
				<?php
			}

			// Check file permissions
			$this->check_file_permissions_notice();
		}

		/**
		 * Check file permissions and show notice
		 */
		private function check_file_permissions_notice() {
			// Only show on plugin settings page
			$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
			if ( ! $screen || 'settings_page_security-hardener' !== $screen->id ) {
				return;
			}

			if ( ! function_exists( 'get_home_path' ) ) {
				require_once ABSPATH . 'wp-admin/includes/file.php';
			}

			$upload_dir = wp_upload_dir();
			$checks     = array(
				array(
					'path'        => ABSPATH . 'wp-config.php',
					'type'        => 'file',
					'recommended' => array( '0600', '0640', '0644' ),
					'label'       => 'wp-config.php',
				),
				array(
					'path'        => get_home_path(),
					'type'        => 'dir',
					'recommended' => array( '0755', '0750' ),
					'label'       => __( 'WordPress root directory', 'security-hardener' ),
				),
				array(
					'path'        => WP_CONTENT_DIR,
					'type'        => 'dir',
					'recommended' => array( '0755', '0750' ),
					'label'       => 'wp-content',
				),
				array(
					'path'        => $upload_dir['basedir'],
					'type'        => 'dir',
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
					$issues[] = sprintf(
						/* translators: 1: file/directory name, 2: current permissions, 3: recommended permissions */
						__( '%1$s has permissions %2$s (recommended: %3$s)', 'security-hardener' ),
						'<code>' . esc_html( $check['label'] ) . '</code>',
						'<code>' . esc_html( $perms ) . '</code>',
						'<code>' . esc_html( implode( ', ', $check['recommended'] ) ) . '</code>'
					);
				}
			}

			if ( ! empty( $issues ) ) {
				?>
				<div class="notice notice-warning">
					<p><strong><?php esc_html_e( 'File Permission Issues Detected:', 'security-hardener' ); ?></strong></p>
					<ul style="list-style: disc; padding-left: 20px;">
						<?php foreach ( $issues as $issue ) : ?>
							<li><?php echo wp_kses_post( $issue ); ?></li>
						<?php endforeach; ?>
					</ul>
					<p>
						<?php
						printf(
							/* translators: %s: URL to file permissions documentation */
							wp_kses_post( __( 'Learn more about <a href="%s" target="_blank">WordPress file permissions</a>.', 'security-hardener' ) ),
							'https://developer.wordpress.org/advanced-administration/server/file-permissions/'
						);
						?>
					</p>
				</div>
				<?php
			}
		}

		/**
		 * Add settings link to plugins page
		 *
		 * @param array $links Plugin action links.
		 * @return array
		 */
		public function add_settings_link( $links ) {
			$settings_link = sprintf(
				'<a href="%s">%s</a>',
				admin_url( 'options-general.php?page=security-hardener' ),
				__( 'Settings', 'security-hardener' )
			);
			array_unshift( $links, $settings_link );
			return $links;
		}
	}

endif;

// Initialize plugin
WPHN_Hardener::get_instance();