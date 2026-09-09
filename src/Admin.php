<?php

namespace PRIVFILEUP;

if (!defined('ABSPATH')) {
    exit;
}

class Admin
{
    const OPTION_KEY = 'privfileup_settings';
    const SIDECAR_CLEANUP_OPTION = 'privfileup_sidecar_cleanup_121_v2';
    const ORPHAN_DIRECTORY = '.privfileup-orphans!';

    /**
     * Initialize admin hooks
     */
    public static function init(): void
    {
        add_action('admin_menu', [__CLASS__, 'register_menu']);
        add_action('admin_init', [__CLASS__, 'register_settings']);
        add_action('admin_init', [__CLASS__, 'add_privacy_policy_content']);
        add_action('admin_init', [__CLASS__, 'maybe_remove_legacy_sidecars']);
        add_action('admin_post_privfileup_delete_file', [__CLASS__, 'handle_delete_file']);
        add_action('admin_post_privfileup_safe_deactivate_handle', [__CLASS__, 'handle_safe_deactivate']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'enqueue_admin_styles']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'enqueue_library_uploader']);

        // User deletion hooks (single site)
        add_action('load-users.php', [__CLASS__, 'maybe_hook_users_notice']);
        add_action('delete_user_form', [__CLASS__, 'delete_user_form'], 10, 2);
        add_action('delete_user', [__CLASS__, 'handle_delete_user'], 10, 1);

        // Multisite user deletion
        add_action('wpmu_delete_user', [__CLASS__, 'handle_network_delete_user'], 10, 1);

        // Rename handler (admin-post.php?action=privfileup_rename_file)
        add_action('admin_post_privfileup_rename_file', [__CLASS__, 'handle_rename_file']);

        // Notice on the Library page
        add_action('admin_notices', [__CLASS__, 'library_notices']);
    }

    /**
     * Enqueue admin styles
     */
    public static function enqueue_admin_styles(string $hook): void
    {
        // Only load on our plugin pages
        if (strpos($hook, 'privfileup-') === false) {
            return;
        }

        // Register an empty handle and inject inline CSS on it
        wp_register_style('privfileup-admin', false, [], PRIVFILEUP_VERSION);
        wp_enqueue_style('privfileup-admin');
        wp_add_inline_style('privfileup-admin', self::get_admin_css());
    }

    public static function enqueue_library_uploader(string $hook): void
    {
        // Only load on the plugin Library page
        if (strpos($hook, 'privfileup-library') === false) {
            return;
        }

        // Core assets
        wp_enqueue_script('plupload-all');
        wp_enqueue_script('jquery');

        // Load the uploader after its Core dependencies.
        wp_register_script('privfileup-library-uploader', PRIVFILEUP_PLUGIN_URL . 'assets/js/library-uploader.js', ['plupload-all', 'jquery'], defined('PRIVFILEUP_VERSION') ? PRIVFILEUP_VERSION : '1.0.0', true);
        wp_enqueue_script('privfileup-library-uploader');

        // Data for upload via REST
        $policy_max = \PRIVFILEUP\Plugin::effective_max_upload_bytes();
        $rest_url   = rest_url(\PRIVFILEUP\Plugin::REST_NS . '/upload');
        $nonce      = wp_create_nonce('wp_rest');

        wp_add_inline_script('privfileup-library-uploader', sprintf(
            'window.PRIVFILEUP_UPLOADER = %s;',
            wp_json_encode([
                'restUrl'   => $rest_url,
                'restNonce' => $nonce,
                'maxBytes'  => $policy_max,
                'strings'   => [
                    'dropHere'  => __('Drop files here or', 'private-file-uploader'),
                    'choose'    => __('choose files', 'private-file-uploader'),
                    'uploading' => __('Uploading…', 'private-file-uploader'),
                    'done'      => __('Done', 'private-file-uploader'),
                    'failed'    => __('Failed', 'private-file-uploader'),
                    'error'     => __('Error', 'private-file-uploader'),
                    'confirmDelete' => __('Delete this file?', 'private-file-uploader'),
                ],
            ])
        ), 'before');

        // Stili minimi
        wp_register_style('privfileup-admin-uploader', false, [], PRIVFILEUP_VERSION);
        wp_enqueue_style('privfileup-admin-uploader');
        wp_add_inline_style('privfileup-admin-uploader', '
            .privfileup-uploader { margin:16px 0; padding:16px; border:2px dashed #ccd0d4; border-radius:8px; background:#fff; text-align:center; }
            .privfileup-uploader.dragover { background:#f7fbff; border-color:#72aee6; }
            .privfileup-uploader .privfileup-row { display:inline-flex; gap:8px; align-items:center; flex-wrap:wrap; justify-content:center; }
            .privfileup-uploader-progress { margin-top:10px; font-size:12px; color:#555; display:none; }
            .privfileup-uploader-list { margin-top:10px; text-align:left; max-width:760px; margin-inline:auto; }
            .privfileup-uploader-item { display:flex; justify-content:space-between; padding:6px 8px; background:#f7f7f7; border-radius:4px; margin-top:6px; }
            .privfileup-uploader-item .privfileup-status { margin-left:12px; }
        ');
    }


    /**
     * Get admin CSS
     *
     * @return string CSS content
     */
    private static function get_admin_css(): string
    {
        return '
            .privfileup-cards { display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }
            .privfileup-card { background: #fff; border: 1px solid #e3e3e3; border-radius: 8px; padding: 16px; min-width: 260px; }
            .privfileup-card h2 { margin: 0 0 8px; font-size: 16px; }
            .privfileup-list { margin: 8px 0 0 18px; }
            .privfileup-muted { color: #666; }
            .privfileup-actions { margin-top: 16px; }
            .privfileup-server-limits { margin-top: 16px; background: #fff; border: 1px solid #e3e3e3; border-radius: 8px; padding: 16px; }
            .privfileup-warning-box { margin-top: 8px; padding: 8px 12px; border-left: 4px solid #d63638; background: #fff3f3; }
            .column-privfileup-preview { width: 60px; }
            .privfileup-thumb { width: 48px; height: 48px; object-fit: cover; border-radius: 4px; background: #f3f3f3; display: block; }
            .privfileup-icon { width: 36px; height: 36px; opacity: .85; display: block; margin: 6px auto; }
            .privfileup-code-block { background: #f7f7f7; padding: 8px; overflow: auto; }
        ';
    }

    /**
     * Register admin menu: main page + subpages (Library for all, Settings for admins)
     */
    public static function register_menu(): void
    {
        $cap_library  = 'read';
        $cap_settings = 'manage_options';

        add_menu_page(
            __('Private Uploader', 'private-file-uploader'),
            __('Private Uploader', 'private-file-uploader'),
            $cap_library,
            'privfileup-overview',
            [__CLASS__, 'render_overview_page'],
            'dashicons-upload',
            27
        );

        // Sub: Overview
        add_submenu_page(
            'privfileup-overview',
            __('Overview', 'private-file-uploader'),
            __('Overview', 'private-file-uploader'),
            $cap_library,
            'privfileup-overview',
            [__CLASS__, 'render_overview_page']
        );

        // Sub: Library
        add_submenu_page(
            'privfileup-overview',
            __('Library', 'private-file-uploader'),
            __('Library', 'private-file-uploader'),
            $cap_library,
            'privfileup-library',
            [__CLASS__, 'render_library_page']
        );

        // Sub: Settings
        add_submenu_page(
            'privfileup-overview',
            __('Settings', 'private-file-uploader'),
            __('Settings', 'private-file-uploader'),
            $cap_settings,
            'privfileup-settings',
            [__CLASS__, 'render_settings_page']
        );

        // Hidden page: Safe Deactivate
        add_submenu_page(
            'privfileup-overview',
            __('Safe Deactivate', 'private-file-uploader'),
            __('Safe Deactivate', 'private-file-uploader'),
            'manage_options',
            'privfileup-safe-deactivate',
            [__CLASS__, 'render_safe_deactivate_page']
        );

        // Hide from sidebar but keep it routable
        add_action('admin_head', function () {
            remove_submenu_page('privfileup-overview', 'privfileup-safe-deactivate');
        });
    }

    /**
     * Register plugin settings
     */
    public static function register_settings(): void
    {
        register_setting(
            'privfileup_settings_group',
            self::OPTION_KEY,
            ['sanitize_callback' => [__CLASS__, 'sanitize_settings']]
        );

        add_settings_section(
            'privfileup_main',
            __('Upload policy', 'private-file-uploader'),
            [__CLASS__, 'render_settings_section'],
            'privfileup-settings'
        );

        add_settings_field(
            'privfileup_max_upload_bytes',
            __('Max upload size (bytes)', 'private-file-uploader'),
            [__CLASS__, 'render_field_privfileup_max_upload_bytes'],
            'privfileup-settings',
            'privfileup_main'
        );

        add_settings_field(
            'privfileup_allowed_mime_types',
            __('Allowed MIME types (one per line)', 'private-file-uploader'),
            [__CLASS__, 'render_field_privfileup_allowed_mime_types'],
            'privfileup-settings',
            'privfileup_main'
        );
    }

    /**
     * Add suggested text to WordPress' Privacy Policy Guide.
     */
    public static function add_privacy_policy_content(): void
    {
        if (!function_exists('wp_add_privacy_policy_content')) {
            return;
        }

        $content  = '<p>' . esc_html__('This plugin stores files uploaded by registered users in per-user folders inside the WordPress uploads directory. The user login is used as part of the folder path.', 'private-file-uploader') . '</p>';
        $content .= '<p>' . esc_html__('The plugin does not send files or personal data to external services and does not include telemetry. New uploads do not create request-metadata sidecars, and recognized legacy sidecars are removed during admin maintenance. Direct file URLs may be accessible to anyone who knows the URL, depending on the web server configuration.', 'private-file-uploader') . '</p>';
        $content .= '<p>' . esc_html__('When an administrator deletes a user, the administrator can delete, reassign, or quarantine that user\'s files outside the reusable login path. A normal plugin uninstall preserves uploaded files unless they were removed first with Safe Deactivate.', 'private-file-uploader') . '</p>';

        wp_add_privacy_policy_content(
            __('Private File Uploader', 'private-file-uploader'),
            wp_kses_post($content)
        );
    }

    /**
     * Remove recognized metadata sidecars written by older plugin versions.
     */
    public static function maybe_remove_legacy_sidecars(): void
    {
        if (get_option(self::SIDECAR_CLEANUP_OPTION, false)) {
            return;
        }

        $root = Plugin::storage_root_base();
        if (!is_dir($root)) {
            update_option(self::SIDECAR_CLEANUP_OPTION, PRIVFILEUP_VERSION, false);
            return;
        }

        $directories = scandir($root);
        if (!is_array($directories)) {
            return;
        }

        $failed = false;
        foreach ($directories as $directory_name) {
            if ($directory_name === '.' || $directory_name === '..') {
                continue;
            }

            $directory = trailingslashit($root) . $directory_name;
            if (
                !is_dir($directory) ||
                is_link($directory) ||
                !Utils::is_path_within_base($root, $directory)
            ) {
                continue;
            }

            $files = scandir($directory);
            if (!is_array($files)) {
                $failed = true;
                continue;
            }

            foreach ($files as $filename) {
                $metadata_path = trailingslashit($directory) . $filename;
                if (!Utils::is_legacy_metadata_sidecar($metadata_path)) {
                    continue;
                }

                if (!Utils::delete_legacy_metadata_sidecar($metadata_path)) {
                    $failed = true;
                }
            }
        }

        if (!$failed) {
            update_option(self::SIDECAR_CLEANUP_OPTION, PRIVFILEUP_VERSION, false);
        }
    }

    /**
     * Render settings section description
     */
    public static function render_settings_section(): void
    {
?>
        <p><?php esc_html_e('Configure max size and MIME allowlist for uploads handled by this plugin.', 'private-file-uploader'); ?></p>
    <?php
    }

    /**
     * Get plugin settings with defaults
     *
     * @return array Settings array
     */
    public static function get_settings(): array
    {
        $opt = get_option(self::OPTION_KEY, []);
        $opt = is_array($opt) ? $opt : [];
        $defaults = [
            'privfileup_max_upload_bytes'  => Plugin::DEFAULT_MAX_UPLOAD_BYTES,
            'privfileup_allowed_mime_types' => Plugin::DEFAULT_ALLOWED_MIME,
        ];

        $max = isset($opt['privfileup_max_upload_bytes']) ? absint($opt['privfileup_max_upload_bytes']) : 0;
        $opt['privfileup_max_upload_bytes'] = $max > 0 ? $max : $defaults['privfileup_max_upload_bytes'];

        $mime = $opt['privfileup_allowed_mime_types'] ?? $defaults['privfileup_allowed_mime_types'];
        $mime = self::sanitize_mime_list($mime);
        $opt['privfileup_allowed_mime_types'] = $mime ?: $defaults['privfileup_allowed_mime_types'];

        return $opt + $defaults;
    }

    /**
     * Sanitize the settings array
     *
     * @param mixed $input Raw input from form
     * @return array Sanitized settings
     */
    public static function sanitize_settings($input): array
    {
        $input = is_array($input) ? $input : [];
        $out = [];

        $max = isset($input['privfileup_max_upload_bytes']) ? absint($input['privfileup_max_upload_bytes']) : 0;
        if ($max <= 0) {
            $max = Plugin::DEFAULT_MAX_UPLOAD_BYTES;
        }
        $out['privfileup_max_upload_bytes'] = $max;

        if (isset($input['privfileup_allowed_mime_types'])) {
            $out['privfileup_allowed_mime_types'] = self::sanitize_mime_list($input['privfileup_allowed_mime_types']);
        }

        return $out;
    }

    /**
     * Sanitize a list of MIME types against WordPress' upload policy.
     *
     * @param mixed $value MIME array or newline-separated string.
     * @return string[] Sanitized MIME list.
     */
    private static function sanitize_mime_list($value): array
    {
        if (is_string($value)) {
            $value = preg_split('/\R+/', $value) ?: [];
        }
        if (!is_array($value)) {
            return [];
        }

        $core_mimes = array_values(\get_allowed_mime_types());
        $result     = [];

        foreach ($value as $mime) {
            if (!is_scalar($mime)) {
                continue;
            }

            $sanitized = sanitize_mime_type(wp_unslash(trim((string) $mime)));
            if ($sanitized !== '' && in_array($sanitized, $core_mimes, true)) {
                $result[] = $sanitized;
            }
        }

        return array_values(array_unique($result));
    }

    /**
     * Render max upload bytes field
     */
    public static function render_field_privfileup_max_upload_bytes(): void
    {
        $opt = self::get_settings();
    ?>
        <input type="number"
            name="<?php echo esc_attr(self::OPTION_KEY); ?>[privfileup_max_upload_bytes]"
            value="<?php echo esc_attr($opt['privfileup_max_upload_bytes']); ?>"
            min="1"
            step="1"
            class="regular-text" />
        <p class="description">
            <?php esc_html_e('Example: 52428800 for 50 MB', 'private-file-uploader'); ?>
        </p>
    <?php
    }

    /**
     * Render allowed MIME types field
     */
    public static function render_field_privfileup_allowed_mime_types(): void
    {
        $opt = self::get_settings();
        $val = implode("\n", (array)$opt['privfileup_allowed_mime_types']);
    ?>
        <textarea name="<?php echo esc_attr(self::OPTION_KEY); ?>[privfileup_allowed_mime_types]"
            rows="6"
            class="large-text code"><?php echo esc_textarea($val); ?></textarea>
        <p class="description">
            <?php esc_html_e('One MIME per line, e.g. application/zip', 'private-file-uploader'); ?>
        </p>
    <?php
    }

    /**
     * Render Safe Deactivate page
     */
    public static function render_safe_deactivate_page(): void
    {
        if (!self::can_safe_deactivate()) {
            wp_die(esc_html__('Safe Deactivate requires permission to deactivate this plugin on this site. Network-active plugins must be deactivated from Network Admin.', 'private-file-uploader'), '', ['response' => 403]);
        }

        $root = Plugin::storage_root_base();
        $htaccess_path = trailingslashit($root) . '.htaccess';
        $web_config_path = trailingslashit($root) . 'web.config';
        $exists = is_dir($root);
        $nonce = wp_create_nonce('privfileup_safe_deactivate');

    ?>
        <div class="wrap">
            <h1><?php esc_html_e('Safe Deactivate – Private Uploader', 'private-file-uploader'); ?></h1>

            <?php if (!$exists): ?>
                <p class="description">
                    <?php esc_html_e('Storage directory not found; nothing to clean.', 'private-file-uploader'); ?>
                </p>
            <?php else: ?>
                <p>
                    <strong><?php esc_html_e('Storage directory', 'private-file-uploader'); ?>:</strong>
                    <code><?php echo esc_html($root); ?></code>
                </p>
            <?php endif; ?>

            <p><?php esc_html_e('Choose what to do with stored files before deactivating the plugin.', 'private-file-uploader'); ?></p>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="privfileup_safe_deactivate_handle" />
                <input type="hidden" name="_wpnonce" value="<?php echo esc_attr($nonce); ?>" />

                <table class="form-table">
                    <tbody>
                        <tr>
                            <th scope="row"><?php esc_html_e('Delete all files', 'private-file-uploader'); ?></th>
                            <td>
                                <label>
                                    <input type="radio" name="privfileup_mode" value="delete" />
                                    <?php esc_html_e('Delete ALL user files from disk, then deactivate the plugin.', 'private-file-uploader'); ?>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('This cannot be undone. Consider backing up first.', 'private-file-uploader'); ?>
                                </p>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php esc_html_e('Keep files (block access)', 'private-file-uploader'); ?></th>
                            <td>
                                <label>
                                    <input type="radio" name="privfileup_mode" value="deny" checked />
                                    <?php esc_html_e('Keep files on disk and block direct web access where possible.', 'private-file-uploader'); ?>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('We will attempt to create deny rules for Apache/IIS. For Nginx, add the snippet below to your server config.', 'private-file-uploader'); ?>
                                </p>

                                <?php
                                self::render_deny_rules_preview($htaccess_path, $web_config_path);
                                ?>
                            </td>
                        </tr>
                    </tbody>
                </table>

                <?php submit_button(__('Proceed and deactivate', 'private-file-uploader')); ?>
                <a class="button button-secondary" href="<?php echo esc_url(admin_url('plugins.php')); ?>">
                    <?php esc_html_e('Cancel', 'private-file-uploader'); ?>
                </a>
            </form>
        </div>
    <?php
    }

    /**
     * Render deny rules preview for Apache, IIS, and Nginx
     *
     * @param string $htaccess_path Path to .htaccess
     * @param string $web_config_path Path to web.config
     */
    private static function render_deny_rules_preview(string $htaccess_path, string $web_config_path): void
    {
    ?>
        <h4><?php esc_html_e('Apache (.htaccess)', 'private-file-uploader'); ?></h4>
        <pre class="privfileup-code-block"><code><?php echo esc_html("Options -Indexes\nRequire all denied"); ?></code></pre>
        <p class="description">
            <?php esc_html_e('Target:', 'private-file-uploader'); ?>
            <code><?php echo esc_html($htaccess_path); ?></code>
        </p>

        <h4><?php esc_html_e('IIS (web.config)', 'private-file-uploader'); ?></h4>
        <pre class="privfileup-code-block"><code><?php
                                            echo esc_html('<configuration>
  <system.webServer>
    <security>
      <authorization>
        <remove users="*" roles="" verbs="" />
        <add accessType="Deny" users="*" />
      </authorization>
    </security>
    <directoryBrowse enabled="false" />
  </system.webServer>
</configuration>');
                                            ?></code></pre>
        <p class="description">
            <?php esc_html_e('Target:', 'private-file-uploader'); ?>
            <code><?php echo esc_html($web_config_path); ?></code>
        </p>

        <h4><?php esc_html_e('Nginx (add to server config)', 'private-file-uploader'); ?></h4>
        <?php $nginx_rule = self::get_nginx_deny_rule(); ?>
        <?php if ($nginx_rule !== ''): ?>
            <pre class="privfileup-code-block"><code><?php echo esc_html($nginx_rule); ?></code></pre>
        <?php else: ?>
            <p class="description"><?php esc_html_e('This storage URL needs a custom Nginx access rule. Ask your server administrator to block the storage URL below.', 'private-file-uploader'); ?></p>
        <?php endif; ?>
        <p class="description">
            <?php esc_html_e('Apply access controls on the server serving this storage URL. A separate uploads host or CDN needs its own configuration:', 'private-file-uploader'); ?>
            <code><?php echo esc_url(self::get_storage_url()); ?></code>
        </p>
    <?php
    }

    /** The effective public storage URL, including subdirectory installations. */
    private static function get_storage_url(): string
    {
        $uploads = wp_get_upload_dir();
        return empty($uploads['baseurl']) ? '' : trailingslashit($uploads['baseurl']) . Plugin::SUB_BASE . '/';
    }

    /** Generate a quoted Nginx prefix for its decoded request URI. */
    private static function get_nginx_deny_rule(): string
    {
        $path = wp_parse_url(self::get_storage_url(), PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            return '';
        }

        $path = rawurldecode($path);
        // Spaces and Unicode are safe in quotes. For configuration syntax,
        // control characters or dot segments, request a custom rule instead
        // of emitting an ambiguous, injectable or overly broad location.
        if (
            $path[0] !== '/' ||
            preg_match('/[\x00-\x1F\x7F"\\\\$;{}]/', $path) ||
            preg_match('#(?:^|/)\.{1,2}(?:/|$)#', $path)
        ) {
            return '';
        }

        return 'location ^~ "' . $path . '" {' . "\n    deny all;\n}";
    }

    /**
     * Render Overview page
     */
    public static function render_overview_page(): void
    {
        if (!is_user_logged_in()) {
            wp_die(esc_html__('You must be logged in.', 'private-file-uploader'));
        }

        $max_bytes = Plugin::effective_max_upload_bytes();
        $mimes = Plugin::effective_allowed_mime_types();

    ?>
        <div class="wrap">
            <h1><?php esc_html_e('Private Uploader – Overview', 'private-file-uploader'); ?></h1>

            <p><?php esc_html_e('This plugin provides a per-user upload area. REST operations are authenticated, while direct file URLs may be accessible to anyone who knows the URL. The rules below apply to uploads performed via the mobile app or REST API.', 'private-file-uploader'); ?></p>

            <div class="privfileup-cards">
                <?php self::render_max_size_card($max_bytes); ?>
                <?php self::render_mime_types_card($mimes); ?>
            </div>

            <?php self::render_server_limits_card(); ?>

            <div class="privfileup-actions">
                <a class="button button-primary" href="<?php echo esc_url(admin_url('admin.php?page=privfileup-library')); ?>">
                    <?php esc_html_e('Open your Library', 'private-file-uploader'); ?>
                </a>
                <?php if (current_user_can('manage_options')): ?>
                    <a class="button" href="<?php echo esc_url(admin_url('admin.php?page=privfileup-settings')); ?>">
                        <?php esc_html_e('Settings', 'private-file-uploader'); ?>
                    </a>
                <?php endif; ?>
            </div>
        </div>
    <?php
    }

    /**
     * Render max size card
     *
     * @param int $max_bytes Maximum upload size in bytes
     */
    private static function render_max_size_card(int $max_bytes): void
    {
    ?>
        <div class="privfileup-card">
            <h2><?php esc_html_e('Max upload size', 'private-file-uploader'); ?></h2>
            <p>
                <strong><?php echo esc_html(Utils::human_bytes($max_bytes)); ?></strong>
                <span class="privfileup-muted">(<?php echo esc_html(number_format($max_bytes)); ?> bytes)</span>
            </p>
            <p class="privfileup-muted">
                <?php esc_html_e('Requests exceeding this limit will be rejected.', 'private-file-uploader'); ?>
            </p>
        </div>
    <?php
    }

    /**
     * Render MIME types card
     *
     * @param array $mimes Allowed MIME types
     */
    private static function render_mime_types_card(array $mimes): void
    {
    ?>
        <div class="privfileup-card">
            <h2><?php esc_html_e('Allowed MIME types', 'private-file-uploader'); ?></h2>
            <?php if (empty($mimes)): ?>
                <p class="privfileup-muted">
                    <?php esc_html_e('No MIME types configured.', 'private-file-uploader'); ?>
                </p>
            <?php else: ?>
                <ul class="privfileup-list">
                    <?php foreach ($mimes as $mime): ?>
                        <li><code><?php echo esc_html($mime); ?></code></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            <p class="privfileup-muted">
                <?php esc_html_e('Uploads with unsupported types will be rejected.', 'private-file-uploader'); ?>
            </p>
        </div>
    <?php
    }

    /**
     * Render server limits card
     */
    private static function render_server_limits_card(): void
    {
        $policy_max = Plugin::effective_max_upload_bytes();
        list($up_human, $up_bytes, $up_raw) = Utils::get_ini_pair('upload_max_filesize');
        list($post_human, $post_bytes, $post_raw) = Utils::get_ini_pair('post_max_size');
        list($mem_human, $mem_bytes, $mem_raw) = Utils::get_ini_pair('memory_limit');
        $max_uploads = @ini_get('max_file_uploads');
        $exec_time = @ini_get('max_execution_time');

        $warnings = [];
        if ($policy_max > 0 && $up_bytes > 0 && $up_bytes < $policy_max) {
            $warnings[] = 'upload_max_filesize';
        }
        if ($policy_max > 0 && $post_bytes > 0 && $post_bytes < $policy_max) {
            $warnings[] = 'post_max_size';
        }

    ?>
        <div class="privfileup-server-limits">
            <h2 style="margin-top:0"><?php esc_html_e('Server limits (PHP)', 'private-file-uploader'); ?></h2>

            <table class="widefat striped" style="margin-top:8px">
                <tbody>
                    <tr>
                        <td><?php esc_html_e('upload_max_filesize', 'private-file-uploader'); ?></td>
                        <td>
                            <code><?php echo esc_html($up_raw); ?></code>
                            <span class="privfileup-muted">(<?php echo esc_html($up_human); ?>)</span>
                        </td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('post_max_size', 'private-file-uploader'); ?></td>
                        <td>
                            <code><?php echo esc_html($post_raw); ?></code>
                            <span class="privfileup-muted">(<?php echo esc_html($post_human); ?>)</span>
                        </td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('memory_limit', 'private-file-uploader'); ?></td>
                        <td>
                            <code><?php echo esc_html($mem_raw); ?></code>
                            <span class="privfileup-muted">(<?php echo esc_html($mem_human); ?>)</span>
                        </td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('max_file_uploads', 'private-file-uploader'); ?></td>
                        <td><code><?php echo esc_html((string)$max_uploads); ?></code></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('max_execution_time', 'private-file-uploader'); ?></td>
                        <td>
                            <code><?php echo esc_html((string)$exec_time); ?></code>
                            <span class="privfileup-muted"><?php esc_html_e('seconds', 'private-file-uploader'); ?></span>
                        </td>
                    </tr>
                </tbody>
            </table>

            <p class="privfileup-muted" style="margin-top:8px">
                <?php esc_html_e('Note: PHP/server limits must also allow the requested size. If uploads fail for large files, raise both upload_max_filesize and post_max_size (and check web server/proxy limits).', 'private-file-uploader'); ?>
            </p>

            <?php if (!empty($warnings)): ?>
                <div class="privfileup-warning-box">
                    <strong><?php esc_html_e('Warning:', 'private-file-uploader'); ?></strong>
                    <?php esc_html_e('Your PHP limits are below the plugin policy. Increase the following:', 'private-file-uploader'); ?>
                    <code><?php echo esc_html(implode(', ', $warnings)); ?></code>
                    <?php if ($policy_max > 0): ?>
                        – <?php esc_html_e('desired at least', 'private-file-uploader'); ?>:
                        <strong><?php echo esc_html(Utils::human_bytes($policy_max)); ?></strong>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    <?php
    }

    /**
     * Render Library page
     */
    public static function render_library_page(): void
    {
        if (!is_user_logged_in()) {
            wp_die(esc_html__('You must be logged in.', 'private-file-uploader'));
        }

        $user = wp_get_current_user();
        $base = Plugin::get_user_base($user);
        if (is_wp_error($base)) {
            wp_die(esc_html($base->get_error_message()), '', ['response' => 403]);
        }
        $files = self::get_user_files($base['path'], $base['url']);

    ?>
        <div class="wrap">
            <h1><?php esc_html_e('Your uploads', 'private-file-uploader'); ?></h1>
            <div id="privfileup-uploader" class="privfileup-uploader">
                <div class="privfileup-row">
                    <span><?php echo esc_html(__('Drop files here or', 'private-file-uploader')); ?></span>
                    <button id="privfileup-pick" type="button" class="button button-primary">
                        <?php echo esc_html(__('Choose files', 'private-file-uploader')); ?>
                    </button>
                </div>
                <div class="privfileup-uploader-progress" id="privfileup-progress"></div>
                <div class="privfileup-uploader-list" id="privfileup-list"></div>
            </div>
            <?php if (empty($files)): ?>
                <p><?php esc_html_e('You have not uploaded any files yet.', 'private-file-uploader'); ?></p>
            <?php else: ?>
                <?php self::render_files_table($files); ?>
            <?php endif; ?>
        </div>


    <?php
    }

    /**
     * Get user files from directory
     *
     * @param string $dir Directory path
     * @param string $url Base URL
     * @return array Array of file data
     */
    private static function get_user_files(string $dir, string $url): array
    {
        if (!is_dir($dir)) {
            return [];
        }

        $entries = @scandir($dir);
        if ($entries === false) {
            return [];
        }

        $files = [];

        foreach ($entries as $entry) {
            // Skip special entries
            if (in_array($entry, ['.', '..', 'index.html'], true) || strpos($entry, "\0") !== false) {
                continue;
            }

            // Skip metadata and system files
            if (Utils::is_metadata_file($entry) || Utils::is_system_file($entry)) {
                continue;
            }

            // Skip thumbnail files
            if (Utils::is_thumb_filename($entry)) {
                continue;
            }

            $abs = $dir . DIRECTORY_SEPARATOR . $entry;

            if (is_link($abs) || !is_file($abs)) {
                continue;
            }

            $size = @filesize($abs);
            $mtime = @filemtime($abs);
            $filetype = wp_check_filetype($entry);
            $mime = !empty($filetype['type']) ? $filetype['type'] : 'application/octet-stream';

            $files[] = [
                'name' => $entry,
                'url' => $url . '/' . rawurlencode($entry),
                'size' => is_int($size) ? $size : 0,
                'mtime' => is_int($mtime) ? $mtime : 0,
                'mime' => $mime,
            ];
        }

        // Sort by modification time (newest first)
        usort($files, fn($a, $b) => $b['mtime'] <=> $a['mtime']);

        return $files;
    }

    /**
     * Render files table
     *
     * @param array $files Array of file data
     */
    private static function render_files_table(array $files): void
    {
    ?>
        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th class="column-privfileup-preview"><?php esc_html_e('Preview', 'private-file-uploader'); ?></th>
                    <th><?php esc_html_e('File', 'private-file-uploader'); ?></th>
                    <th><?php esc_html_e('Size', 'private-file-uploader'); ?></th>
                    <th><?php esc_html_e('Modified', 'private-file-uploader'); ?></th>
                    <th><?php esc_html_e('MIME', 'private-file-uploader'); ?></th>
                    <th><?php esc_html_e('Actions', 'private-file-uploader'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($files as $file): ?>
                    <?php self::render_file_row($file); ?>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php
    }

    /**
     * Render a single file row
     *
     * @param array $file File data
     */
    private static function render_file_row(array $file): void
    {
        $name      = $file['name'];
        $url       = $file['url'];
        $is_image  = strpos($file['mime'], 'image/') === 0;

        // Try to build the adjacent thumbnail URL (name + "-privfileup-thumb").
        $thumb_url = null;
        if ($is_image) {
            // e.g. photo.jpg -> photo-privfileup-thumb.jpg.
            $thumb_basename = Utils::append_suffix($name, '-privfileup-thumb');
            $thumb_url      = Utils::path_replace_basename($url, $thumb_basename);
        }

        $nonce      = wp_create_nonce('privfileup_del_' . $name);
        $delete_url = admin_url('admin-post.php?action=privfileup_delete_file&file=' . rawurlencode($name) . '&_wpnonce=' . $nonce);

        $rename_action_url  = admin_url('admin-post.php');
    ?>
        <tr>
            <td class="column-privfileup-preview">
                <?php if ($is_image): ?>
                    <a href="<?php echo esc_url($url); ?>" target="_blank" rel="noopener">
                        <img
                            class="privfileup-thumb"
                            src="<?php echo esc_url($thumb_url ?: $url); ?>"
                            data-fallback="<?php echo esc_url($url); ?>"
                            alt=""
                            loading="lazy" />
                    </a>
                <?php else: ?>
                    <?php
                    $icon = wp_mime_type_icon($file['mime']) ?: wp_mime_type_icon('application/octet-stream');
                    ?>
                    <img class="privfileup-icon" src="<?php echo esc_url($icon); ?>" alt="" loading="lazy" />
                <?php endif; ?>
            </td>
            <td>
                <a href="<?php echo esc_url($url); ?>" target="_blank" rel="noopener">
                    <?php echo esc_html($name); ?>
                </a>
            </td>
            <td><?php echo esc_html(Utils::human_bytes($file['size'])); ?></td>
            <td><?php echo esc_html(gmdate('Y-m-d H:i', $file['mtime'])); ?></td>
            <td><?php echo esc_html($file['mime']); ?></td>
            <td>
                <a class="button button-small privfileup-delete-file"
                    href="<?php echo esc_url($delete_url); ?>">
                    <?php esc_html_e('Delete', 'private-file-uploader'); ?>
                </a>
                <details class="privfileup-rename" style="display:inline-block;margin-left:8px;">
                    <summary><?php esc_html_e('Rename', 'private-file-uploader'); ?></summary>
                    <form method="post" action="<?php echo esc_url($rename_action_url); ?>" style="margin-top:6px;display:flex;gap:6px;align-items:center;">
                        <input type="hidden" name="action" value="privfileup_rename_file" />
                        <input type="hidden" name="file" value="<?php echo esc_attr($name); ?>" />
                        <?php wp_nonce_field('privfileup_rename_' . $name, '_wpnonce', true); ?>
                        <input type="text"
                            name="new_name"
                            value="<?php echo esc_attr($name); ?>"
                            pattern="[^/]+"
                            required
                            style="width:220px;" />
                        <button type="submit" class="button button-small"><?php esc_html_e('Save', 'private-file-uploader'); ?></button>
                    </form>
                </details>
            </td>
        </tr>
    <?php
    }

    /**
     * Handle file deletion (admin-post action)
     */
    public static function handle_delete_file(): void
    {
        if (!current_user_can('upload_files')) {
            wp_die(esc_html__('Insufficient permissions', 'private-file-uploader'), '', ['response' => 403]);
        }

        $user = wp_get_current_user();
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Strict basename validation preserves the exact stored filename.
        $file = Plugin::sanitize_user_filename(isset($_GET['file']) ? wp_unslash($_GET['file']) : '');
        if (is_wp_error($file)) {
            wp_die(esc_html__('Invalid request.', 'private-file-uploader'));
        }

        check_admin_referer('privfileup_del_' . $file);

        $base_file = Plugin::sanitize_user_filename($file);
        if (is_wp_error($base_file)) {
            Utils::log_warning('Delete file failed: invalid filename', [
                'user' => $user->user_login,
                'file' => $file,
                'error' => $base_file->get_error_message()
            ]);
            wp_die(esc_html($base_file->get_error_message()));
        }

        $paths = Plugin::get_user_base($user);
        if (is_wp_error($paths)) {
            wp_die(esc_html($paths->get_error_message()), '', ['response' => 403]);
        }
        $abs = $paths['path'] . DIRECTORY_SEPARATOR . $base_file;

        if (!file_exists($abs) || !is_file($abs)) {
            Utils::log_warning('Delete file failed: file not found', [
                'user' => $user->user_login,
                'file' => $base_file
            ]);
            wp_safe_redirect(admin_url('admin.php?page=privfileup-library&privfileup_msg=notfound'));
            exit;
        }

        if (!Utils::is_path_within_base($paths['path'], $abs) || is_link($abs)) {
            Utils::log_error('Delete file failed: security check', [
                'user' => $user->user_login,
                'file' => $base_file,
                'path' => $abs
            ]);
            wp_die(esc_html__('Invalid path.', 'private-file-uploader'));
        }

        $ok = Utils::delete_file_with_metadata($abs);

        if ($ok) {
            Utils::log_info('File deleted via admin', [
                'user' => $user->user_login,
                'file' => $base_file
            ]);
        } else {
            Utils::log_error('Delete file failed: unlink error', [
                'user' => $user->user_login,
                'file' => $base_file
            ]);
        }

        $msg = $ok ? 'deleted' : 'delerror';
        wp_safe_redirect(admin_url('admin.php?page=privfileup-library&privfileup_msg=' . $msg));
        exit;
    }

    /** Whether the current user may safely deactivate this site activation. */
    public static function can_safe_deactivate(): bool
    {
        if (!function_exists('is_plugin_active_for_network')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugin = plugin_basename(PRIVFILEUP_PLUGIN_FILE);
        return current_user_can('manage_options') &&
            current_user_can('deactivate_plugin', $plugin) &&
            !is_plugin_active_for_network($plugin);
    }

    /** Handle deactivation of the current site's plugin and storage only. */
    public static function handle_safe_deactivate(): void
    {
        if (!self::can_safe_deactivate()) {
            wp_die(esc_html__('Safe Deactivate requires permission to deactivate this plugin on this site. Network-active plugins must be deactivated from Network Admin.', 'private-file-uploader'), '', ['response' => 403]);
        }

        check_admin_referer('privfileup_safe_deactivate');

        $mode = isset($_POST['privfileup_mode'])
            ? sanitize_key(wp_unslash($_POST['privfileup_mode']))
            : 'deny';

        if (!in_array($mode, ['delete', 'deny'], true)) {
            wp_die(
                esc_html__('Invalid deactivation mode.', 'private-file-uploader'),
                esc_html__('Invalid request', 'private-file-uploader'),
                ['response' => 400]
            );
        }

        $root = Plugin::storage_root_base();

        if (file_exists($root) && (!is_dir($root) || is_link($root))) {
            wp_die(
                esc_html__('The storage path is not a regular directory. No files were changed and the plugin remains active.', 'private-file-uploader'),
                esc_html__('Storage error', 'private-file-uploader'),
                ['response' => 500]
            );
        }

        Utils::log_info('Safe deactivate initiated', [
            'mode' => $mode,
            'root' => $root
        ]);

        if ($mode === 'delete') {
            $size_before = Utils::get_directory_size($root);
            $files_count = Utils::count_directory_files($root, true);

            $deleted = !is_dir($root) || Utils::recursive_rmdir($root);
            clearstatcache(true, $root);

            if (!$deleted || file_exists($root)) {
                Utils::log_error('Storage deletion failed during deactivation', ['root' => $root]);
                wp_die(
                    esc_html__('The storage directory could not be deleted completely. The plugin remains active.', 'private-file-uploader'),
                    esc_html__('Storage error', 'private-file-uploader'),
                    ['response' => 500]
                );
            }

            Utils::log_info('Storage deleted during deactivation', [
                'size_deleted' => Utils::human_bytes($size_before),
                'files_deleted' => $files_count
            ]);

            $msg = 'privfileup_deleted';
        } else {
            // Write deny rules for Apache/IIS if storage exists.
            $rules_written = !is_dir($root);
            require_once ABSPATH . 'wp-admin/includes/file.php';

            global $wp_filesystem;

            if (! $wp_filesystem) {
                WP_Filesystem();
            }

            if ($wp_filesystem && $wp_filesystem->is_dir($root) && $wp_filesystem->is_writable($root)) {
                $htaccess_content   = "Options -Indexes\nRequire all denied\n";
                $web_config_content = "<configuration>\n  <system.webServer>\n    <security>\n      <authorization>\n        <remove users=\"*\" roles=\"\" verbs=\"\" />\n        <add accessType=\"Deny\" users=\"*\" />\n      </authorization>\n    </security>\n    <directoryBrowse enabled=\"false\" />\n  </system.webServer>\n</configuration>\n";

                $htaccess_file = trailingslashit($root) . '.htaccess';
                $webconf_file  = trailingslashit($root) . 'web.config';

                $apache_written = (bool) $wp_filesystem->put_contents($htaccess_file, $htaccess_content, FS_CHMOD_FILE);
                $iis_written    = (bool) $wp_filesystem->put_contents($webconf_file, $web_config_content, FS_CHMOD_FILE);
                $rules_written  = $apache_written && $iis_written;
            }

            if (!$rules_written) {
                Utils::log_error('Deny rules could not be written during deactivation', ['root' => $root]);
                wp_die(
                    esc_html__('Access-control files could not be written. No files were changed and the plugin remains active.', 'private-file-uploader'),
                    esc_html__('Storage error', 'private-file-uploader'),
                    ['response' => 500]
                );
            }

            Utils::log_info('Deny rules written during deactivation', [
                'root' => $root
            ]);

            $msg = 'privfileup_denied';
        }

        // Deactivate plugin programmatically
        deactivate_plugins(plugin_basename(PRIVFILEUP_PLUGIN_FILE), false, false);

        // Redirect back to Plugins screen with admin notice
        $url = add_query_arg('privfileup_notice', $msg, admin_url('plugins.php'));
        wp_safe_redirect($url);
        exit;
    }

    /**
     * Render Settings page
     */
    public static function render_settings_page(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'private-file-uploader'));
        }
    ?>
        <div class="wrap">
            <h1><?php esc_html_e('Private Uploader – Settings', 'private-file-uploader'); ?></h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('privfileup_settings_group');
                do_settings_sections('privfileup-settings');
                submit_button();
                ?>
            </form>
        </div>
    <?php
    }

    /**
     * Render user deletion form options
     *
     * @param \WP_User $current_user Current administrator.
     * @param int[]    $user_ids     IDs selected for deletion.
     */
    public static function delete_user_form($current_user, array $user_ids = []): void
    {
        if (!current_user_can('delete_users')) {
            return;
        }

        unset($current_user);
        $exclude_ids = array_values(array_unique(array_filter(array_map('absint', $user_ids))));

    ?>
        <h2><?php esc_html_e('Private Uploader – User files', 'private-file-uploader'); ?></h2>
        <p><?php esc_html_e('Choose what to do with this user\'s uploaded files.', 'private-file-uploader'); ?></p>

        <?php wp_nonce_field('privfileup_delete_user_files', 'privfileup_nonce'); ?>

        <fieldset class="privfileup-box" style="border:1px solid #ccd0d4;padding:12px;max-width:680px;background:#fff">
            <label style="display:block;margin-bottom:8px">
                <input type="radio" name="privfileup_user_files_action" value="delete" />
                <strong><?php esc_html_e('Delete all files', 'private-file-uploader'); ?></strong> –
                <?php esc_html_e('remove this user\'s storage directory permanently.', 'private-file-uploader'); ?>
            </label>

            <label style="display:block;margin-bottom:8px">
                <input type="radio" name="privfileup_user_files_action" value="reassign" checked />
                <strong><?php esc_html_e('Reassign to another user', 'private-file-uploader'); ?></strong> –
                <?php esc_html_e('move the storage directory to the selected user.', 'private-file-uploader'); ?>
                <br />
                <?php
                wp_dropdown_users([
                    'name' => 'privfileup_reassign_user',
                    'selected' => '0',
                    'option_none_value' => '0',
                    'show_option_none' => __('— Select user —', 'private-file-uploader'),
                    'exclude' => $exclude_ids,
                    'orderby' => 'user_login',
                    'order' => 'ASC',
                    'show' => 'user_login',
                    'include_selected' => true,
                    'capability' => 'upload_files',
                ]);
                ?>
            </label>

            <label style="display:block;margin-bottom:8px">
                <input type="radio" name="privfileup_user_files_action" value="keep_deny" />
                <strong><?php esc_html_e('Keep files in quarantine', 'private-file-uploader'); ?></strong> –
                <?php esc_html_e('move the files outside the deleted user\'s reusable login folder and add Apache/IIS deny rules where possible.', 'private-file-uploader'); ?>
            </label>
        </fieldset>
<?php
    }

    /**
     * Handle user deletion and process file actions
     *
     * @param int $user_id User ID being deleted
     */
    public static function handle_delete_user(int $user_id): void
    {
        if (!self::process_deleted_user_files($user_id, true)) {
            self::stop_user_deletion();
        }
    }

    /** Quarantine storage across all sites, including former memberships. */
    public static function handle_network_delete_user(int $user_id): void
    {
        $offset = 0;
        do {
            $site_ids = get_sites(['fields' => 'ids', 'number' => 100, 'offset' => $offset, 'orderby' => 'id', 'order' => 'ASC']);
            foreach ($site_ids as $site_id) {
                switch_to_blog((int) $site_id);
                try {
                    $safe = self::process_deleted_user_files($user_id, false);
                } finally {
                    restore_current_blog();
                }
                if (!$safe) {
                    self::stop_user_deletion();
                }
            }
            $offset += count($site_ids);
        } while (count($site_ids) === 100);
    }

    /** Stop before Core removes the user and makes the login reusable. */
    private static function stop_user_deletion(): void
    {
        wp_die(
            esc_html__('The user was not deleted because their uploaded files could not be removed or quarantined. Check storage permissions and retry. Files already quarantined remain preserved.', 'private-file-uploader'),
            esc_html__('Storage error', 'private-file-uploader'),
            ['response' => 500]
        );
    }

    /** Process one site's files without creating storage or terminating a site switch. */
    private static function process_deleted_user_files(int $user_id, bool $interactive): bool
    {
        $user = get_user_by('id', $user_id);
        if (!$user) {
            return true;
        }

        $root = Plugin::storage_root_base();
        $paths = Plugin::get_user_base($user, false);
        if (is_wp_error($paths)) {
            // A dot/invalid login never identifies an owned storage directory.
            // In particular, never delete the parent directory on its behalf.
            return $paths->get_error_code() === 'privfileup_unsafe_username';
        }
        $username = $paths['username'];
        $src = $paths['path'];

        if (!is_dir($src)) {
            return true;
        }

        // Programmatic, CLI, multisite, or otherwise non-interactive deletion
        // must not leave data under a login that WordPress may reuse later.
        if (!$interactive || !current_user_can('delete_users') || !isset($_POST['privfileup_nonce'])) {
            return self::quarantine_user_storage($src, $root, $user_id);
        }

        check_admin_referer('privfileup_delete_user_files', 'privfileup_nonce');

        $action = isset($_POST['privfileup_user_files_action'])
            ? sanitize_key(wp_unslash($_POST['privfileup_user_files_action']))
            : '';

        if (!in_array($action, ['delete', 'reassign', 'keep_deny'], true)) {
            return self::quarantine_user_storage($src, $root, $user_id);
        }

        Utils::log_info('User deletion: processing files', [
            'user_id' => $user_id,
            'username' => $user->user_login,
            'action' => $action
        ]);

        switch ($action) {
            case 'delete':
                $size = Utils::get_directory_size($src);
                $count = Utils::count_directory_files($src, true);

                $deleted = Utils::recursive_rmdir($src);
                clearstatcache(true, $src);

                if (!$deleted || file_exists($src)) {
                    Utils::log_error('User file deletion failed', [
                        'user_id' => $user_id,
                        'username' => $username,
                    ]);
                    self::quarantine_user_storage($src, $root, $user_id);
                    set_transient('privfileup_notice_users', 'operation_failed', 60);
                    break;
                }

                Utils::log_info('User files deleted', [
                    'user_id' => $user_id,
                    'username' => $user->user_login,
                    'size_deleted' => Utils::human_bytes($size),
                    'files_deleted' => $count
                ]);

                set_transient('privfileup_notice_users', 'deleted_ok', 60);
                break;

            case 'reassign':
                $to_id = isset($_POST['privfileup_reassign_user'])
                    ? absint(wp_unslash($_POST['privfileup_reassign_user']))
                    : 0;
                $to = $to_id ? get_user_by('id', $to_id) : null;

                if ($to && $to_id !== $user_id && user_can($to, 'upload_files')) {
                    $destination = Plugin::get_user_base($to, false);
                    if (is_wp_error($destination)) {
                        self::quarantine_user_storage($src, $root, $user_id);
                        set_transient('privfileup_notice_users', 'operation_failed', 60);
                        break;
                    }
                    $dst = $destination['path'];

                    $moved = self::reassign_user_storage($src, $dst);
                    clearstatcache(true, $src);
                    clearstatcache(true, $dst);

                    if (!$moved || file_exists($src) || !is_dir($dst)) {
                        Utils::log_error('User file reassignment failed', [
                            'from_user_id' => $user_id,
                            'to_user_id' => $to_id,
                        ]);
                        self::quarantine_user_storage($src, $root, $user_id);
                        set_transient('privfileup_notice_users', 'operation_failed', 60);
                        break;
                    }

                    Utils::log_info('User files reassigned', [
                        'from_user_id' => $user_id,
                        'from_username' => $user->user_login,
                        'to_user_id' => $to_id,
                        'to_username' => $to->user_login,
                        'destination' => $dst
                    ]);
                    set_transient('privfileup_notice_users', 'reassigned_ok', 60);
                } else {
                    self::quarantine_user_storage($src, $root, $user_id);
                    set_transient('privfileup_notice_users', 'operation_failed', 60);
                }
                break;

            case 'keep_deny':
                $quarantined = self::quarantine_user_storage($src, $root, $user_id);
                Utils::log_info('User files kept in quarantine', [
                    'user_id' => $user_id,
                    'username' => $user->user_login,
                    'success' => $quarantined,
                ]);

                set_transient(
                    'privfileup_notice_users',
                    $quarantined ? 'kept_quarantined' : 'operation_failed',
                    60
                );
                break;
        }

        clearstatcache(true, $src);
        return !file_exists($src) && !is_link($src);
    }

    /**
     * Move retained data away from a reusable login-derived folder.
     *
     * @param string $source  Canonical user directory.
     * @param string $root    Plugin storage root.
     * @param int    $user_id Deleted user ID.
     * @return bool True when the directory was quarantined.
     */
    private static function quarantine_user_storage(string $source, string $root, int $user_id): bool
    {
        if (
            !is_dir($source) ||
            is_link($source) ||
            !Utils::is_path_within_base($root, $source)
        ) {
            return false;
        }

        require_once ABSPATH . 'wp-admin/includes/file.php';
        global $wp_filesystem;

        if (!$wp_filesystem && !WP_Filesystem()) {
            return false;
        }
        if (!$wp_filesystem) {
            return false;
        }

        // Keep quarantined data one level below an internal directory whose
        // name cannot be produced by sanitize_user(..., true). A WordPress
        // login can therefore never resolve to this storage path.
        $quarantine_root = trailingslashit($root) . self::ORPHAN_DIRECTORY;
        if (
            (!is_dir($quarantine_root) && !wp_mkdir_p($quarantine_root)) ||
            is_link($quarantine_root) ||
            !Utils::is_path_within_base($root, $quarantine_root)
        ) {
            return false;
        }

        $htaccess_content   = "Options -Indexes\nRequire all denied\n";
        $web_config_content = "<configuration>\n  <system.webServer>\n    <security>\n      <authorization>\n        <remove users=\"*\" roles=\"\" verbs=\"\" />\n        <add accessType=\"Deny\" users=\"*\" />\n      </authorization>\n    </security>\n    <directoryBrowse enabled=\"false\" />\n  </system.webServer>\n</configuration>\n";

        // Establish parent-level access controls before moving retained data.
        $wp_filesystem->put_contents(
            trailingslashit($quarantine_root) . 'index.html',
            '<!-- silence is golden -->',
            FS_CHMOD_FILE
        );
        $wp_filesystem->put_contents(
            trailingslashit($quarantine_root) . '.htaccess',
            $htaccess_content,
            FS_CHMOD_FILE
        );
        $wp_filesystem->put_contents(
            trailingslashit($quarantine_root) . 'web.config',
            $web_config_content,
            FS_CHMOD_FILE
        );

        $token       = strtolower(wp_generate_password(16, false, false));
        $folder_name = absint($user_id) . '-' . sanitize_key($token);
        $destination = trailingslashit($quarantine_root) . $folder_name;

        while (file_exists($destination)) {
            $token       = strtolower(wp_generate_password(16, false, false));
            $folder_name = absint($user_id) . '-' . sanitize_key($token);
            $destination = trailingslashit($quarantine_root) . $folder_name;
        }

        $moved = (bool) $wp_filesystem->move($source, $destination, false);
        clearstatcache(true, $source);
        clearstatcache(true, $destination);
        if (!$moved || file_exists($source) || !is_dir($destination)) {
            return false;
        }

        // Remove only sidecars matching the complete legacy schema. Uploaded
        // JSON documents with a similar suffix remain untouched.
        $legacy_cleanup_ok = true;
        $entries = scandir($destination);
        if (!is_array($entries)) {
            $legacy_cleanup_ok = false;
        } else {
            foreach ($entries as $entry) {
                $metadata = trailingslashit($destination) . $entry;
                if (
                    Utils::is_legacy_metadata_sidecar($metadata) &&
                    !Utils::delete_legacy_metadata_sidecar($metadata)
                ) {
                    $legacy_cleanup_ok = false;
                }
            }
        }

        $wp_filesystem->put_contents(
            trailingslashit($destination) . '.htaccess',
            $htaccess_content,
            FS_CHMOD_FILE
        );
        $wp_filesystem->put_contents(
            trailingslashit($destination) . 'web.config',
            $web_config_content,
            FS_CHMOD_FILE
        );

        return $legacy_cleanup_ok;
    }

    /**
     * Move a user's flat storage directory into another user's canonical one.
     *
     * Existing destination files are kept. Colliding source files receive a
     * numeric suffix, and their generated thumbnail moves with them.
     *
     * @param string $source      Existing source directory.
     * @param string $destination Canonical target directory.
     * @return bool True only when the complete move succeeds.
     */
    private static function reassign_user_storage(string $source, string $destination): bool
    {
        if (!is_dir($source) || is_link($source)) {
            return false;
        }

        require_once ABSPATH . 'wp-admin/includes/file.php';
        global $wp_filesystem;

        if (!$wp_filesystem && !WP_Filesystem()) {
            return false;
        }
        if (!$wp_filesystem) {
            return false;
        }

        // Remove legacy request-metadata sidecars before data changes owner.
        $legacy_entries = scandir($source);
        if (!is_array($legacy_entries)) {
            return false;
        }
        foreach ($legacy_entries as $legacy_entry) {
            $legacy_path = trailingslashit($source) . $legacy_entry;
            if (!Utils::is_legacy_metadata_sidecar($legacy_path)) {
                continue;
            }

            if (!Utils::delete_legacy_metadata_sidecar($legacy_path)) {
                return false;
            }
        }

        // The fast path preserves the directory atomically when the target has
        // never opened its library and therefore has no canonical folder yet.
        if (!file_exists($destination)) {
            $moved = (bool) $wp_filesystem->move($source, $destination, false);
            clearstatcache(true, $source);
            clearstatcache(true, $destination);
            return $moved && !file_exists($source) && is_dir($destination);
        }

        if (!is_dir($destination) || is_link($destination)) {
            return false;
        }

        $entries = scandir($source);
        if (!is_array($entries)) {
            return false;
        }

        $system_files = ['index.html', '.htaccess', 'web.config'];
        $originals    = [];
        $expected     = [];

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..' || in_array($entry, $system_files, true)) {
                continue;
            }

            $path = trailingslashit($source) . $entry;
            if (!is_file($path) || is_link($path)) {
                return false;
            }

            if (!Utils::is_thumb_filename($entry)) {
                $originals[] = $entry;
            }
        }

        // Preflight the directory before moving anything. Orphaned artifacts
        // are left untouched and make the operation fail safely.
        foreach ($originals as $entry) {
            $expected[$entry] = true;

            $metadata = $entry . '.meta.json';
            if (Utils::is_legacy_metadata_sidecar(trailingslashit($source) . $metadata)) {
                $expected[$metadata] = true;
            }

            $thumbnail = basename(Utils::append_suffix($entry, '-privfileup-thumb'));
            if (is_file(trailingslashit($source) . $thumbnail)) {
                $expected[$thumbnail] = true;
            }
        }

        foreach ($entries as $entry) {
            if (
                $entry === '.' ||
                $entry === '..' ||
                in_array($entry, $system_files, true) ||
                isset($expected[$entry])
            ) {
                continue;
            }
            return false;
        }

        $planned_names = [];
        $moves         = [];

        foreach ($originals as $entry) {
            $info      = pathinfo($entry);
            $stem      = isset($info['filename']) ? $info['filename'] : $entry;
            $extension = isset($info['extension']) ? '.' . $info['extension'] : '';
            $candidate = $entry;
            $counter   = 1;

            do {
                $dest_main  = trailingslashit($destination) . $candidate;
                $dest_meta  = $dest_main . '.meta.json';
                $dest_thumb = Utils::append_suffix($dest_main, '-privfileup-thumb');
                $collision  = file_exists($dest_main) ||
                    file_exists($dest_meta) ||
                    file_exists($dest_thumb) ||
                    isset($planned_names[$candidate]);

                if ($collision) {
                    $candidate = $stem . '-' . $counter . $extension;
                    ++$counter;
                }
            } while ($collision);

            $planned_names[$candidate] = true;
            $source_main               = trailingslashit($source) . $entry;
            $moves[]                   = [$source_main, $dest_main];

            $source_meta = $source_main . '.meta.json';
            if (Utils::is_legacy_metadata_sidecar($source_meta)) {
                $moves[] = [$source_meta, $dest_meta];
            }

            $source_thumb = Utils::append_suffix($source_main, '-privfileup-thumb');
            if (is_file($source_thumb)) {
                $moves[] = [$source_thumb, $dest_thumb];
            }
        }

        $completed = [];
        foreach ($moves as [$from, $to]) {
            if (!$wp_filesystem->move($from, $to, false)) {
                foreach (array_reverse($completed) as [$rollback_from, $rollback_to]) {
                    $wp_filesystem->move($rollback_to, $rollback_from, false);
                }
                return false;
            }
            $completed[] = [$from, $to];
        }

        if (!Utils::recursive_rmdir($source)) {
            wp_mkdir_p($source);
            foreach (array_reverse($completed) as [$rollback_from, $rollback_to]) {
                $wp_filesystem->move($rollback_to, $rollback_from, false);
            }
            return false;
        }

        return true;
    }

    /**
     * Hook to display admin notices on users.php after user deletion
     */
    public static function maybe_hook_users_notice(): void
    {
        $code = get_transient('privfileup_notice_users');
        if (!$code) {
            return;
        }

        add_action('admin_notices', function () use ($code) {
            $messages = [
                'kept_quarantined' => [
                    'type' => 'warning',
                    'text' => __('Private Uploader: files were kept in a quarantined folder outside the deleted user\'s login path. Verify your web-server access rules before restoring them.', 'private-file-uploader')
                ],
                'reassigned_ok' => [
                    'type' => 'success',
                    'text' => __('Private Uploader: user files have been reassigned.', 'private-file-uploader')
                ],
                'deleted_ok' => [
                    'type' => 'success',
                    'text' => __('Private Uploader: user files have been deleted.', 'private-file-uploader')
                ],
                'operation_failed' => [
                    'type' => 'error',
                    'text' => __('Private Uploader: the requested file operation could not be completed. Any retained files were quarantined where possible.', 'private-file-uploader')
                ]
            ];

            if (isset($messages[$code])) {
                $msg = $messages[$code];
                printf(
                    '<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
                    esc_attr($msg['type']),
                    esc_html($msg['text'])
                );
            }
        }, 1);

        delete_transient('privfileup_notice_users');
    }

    public static function library_notices(): void
    {
        // Show the notice only on the Library page, regardless of the full screen ID
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only screen selector; no state is changed.
        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
        if ($page !== 'privfileup-library') {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only redirect notice; value is sanitized.
        $code = isset($_GET['privfileup_notice']) ? sanitize_key(wp_unslash($_GET['privfileup_notice'])) : '';
        if ($code === 'renamed_ok') {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only redirect notice; value is sanitized.
            $old = isset($_GET['old']) ? sanitize_text_field(wp_unslash($_GET['old'])) : '';
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only redirect notice; value is sanitized.
            $new = isset($_GET['new']) ? sanitize_text_field(wp_unslash($_GET['new'])) : '';

            echo '<div class="notice notice-success is-dismissible"><p>'
                . esc_html__('File renamed successfully:', 'private-file-uploader') . ' '
                . '<code>' . esc_html($old) . '</code> → <code>' . esc_html($new) . '</code>'
                . '</p></div>';
        } elseif ($code === 'rename_err') {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only redirect notice; no state is changed.
            if (isset($_GET['msg'])) {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only redirect notice; value is sanitized.
                $msg = sanitize_text_field(wp_unslash($_GET['msg']));
            } else {
                $msg = __('Unable to rename file', 'private-file-uploader');
            }

            echo '<div class="notice notice-error is-dismissible"><p>'
                . esc_html__('Rename failed:', 'private-file-uploader') . ' ' . esc_html($msg)
                . '</p></div>';
        }
    }

    public static function handle_rename_file(): void
    {
        if (! current_user_can('upload_files')) {
            wp_die(
                esc_html__('Insufficient permissions', 'private-file-uploader'),
                esc_html__('Error', 'private-file-uploader'),
                ['response' => 403]
            );
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Strict basename validation must not normalize a lookup into another filename.
        $file = Plugin::sanitize_user_filename(isset($_POST['file']) ? wp_unslash($_POST['file']) : '');
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The exact basename is validated here and the target MIME is checked before moving.
        $new_name = Plugin::sanitize_user_filename(isset($_POST['new_name']) ? wp_unslash($_POST['new_name']) : '');
        if (is_wp_error($file) || is_wp_error($new_name)) {
            self::redirect_library('rename_err', ['msg' => __('Invalid filename', 'private-file-uploader')]);
        }

        // Nonce per singolo file
        check_admin_referer('privfileup_rename_' . $file);

        $base = \PRIVFILEUP\Plugin::sanitize_user_filename($file);
        if (is_wp_error($base)) {
            self::redirect_library('rename_err', ['msg' => $base->get_error_message()]);
        }

        $new = \PRIVFILEUP\Plugin::sanitize_user_filename($new_name);
        if (is_wp_error($new)) {
            self::redirect_library('rename_err', ['msg' => $new->get_error_message()]);
        }
        if ($base === $new) {
            self::redirect_library('renamed_ok', ['old' => $base, 'new' => $new]);
        }

        // No rename diretto di una thumbnail
        if (\PRIVFILEUP\Utils::is_thumb_filename($base)) {
            self::redirect_library('rename_err', ['msg' => __('Cannot rename generated thumbnails directly', 'private-file-uploader')]);
        }
        if (\PRIVFILEUP\Utils::is_metadata_file($base)) {
            self::redirect_library('rename_err', ['msg' => __('Cannot rename metadata files directly', 'private-file-uploader')]);
        }

        // Evita di rinominare verso nomi riservati
        if (\PRIVFILEUP\Utils::is_thumb_filename($new)) {
            self::redirect_library('rename_err', ['msg' => __('Target name cannot be a generated thumbnail', 'private-file-uploader')]);
        }
        if (str_ends_with($new, '.meta.json')) {
            self::redirect_library('rename_err', ['msg' => __('Target name cannot end with .meta.json', 'private-file-uploader')]);
        }

        $user = wp_get_current_user();
        $paths = \PRIVFILEUP\Plugin::get_user_base($user);
        if (is_wp_error($paths)) {
            self::redirect_library('rename_err', ['msg' => $paths->get_error_message()]);
        }
        $dir   = $paths['path'];

        // Ensure the folder exists (get_user_base already does this, but it is harmless)
        wp_mkdir_p($dir);

        // Keep the original extension if the new name does not have one
        $dotOld = strrpos($base, '.');
        $dotNew = strrpos($new, '.');
        if ($dotOld !== false && $dotNew === false) {
            $ext = substr($base, $dotOld);   // e.g. ".pdf"
            $new .= $ext;
        }

        // Build absolute paths (source and destination)
        $srcAbs = $dir . DIRECTORY_SEPARATOR . $base;
        $dstAbs = $dir . DIRECTORY_SEPARATOR . $new;
        $oldMeta = $srcAbs . '.meta.json';
        $newMeta = $dstAbs . '.meta.json';
        $oldThumb = \PRIVFILEUP\Utils::append_suffix($srcAbs, '-privfileup-thumb');
        $newThumb = \PRIVFILEUP\Utils::append_suffix($dstAbs, '-privfileup-thumb');

        // Normalize (forward slash) for robust comparison (also on Windows)
        $normBase = untrailingslashit(\wp_normalize_path($dir));
        $normSrc  = \wp_normalize_path($srcAbs);
        $normDst  = \wp_normalize_path($dstAbs);

        // The source MUST be under the base and MUST exist
        if (strpos($normSrc, $normBase . '/') !== 0 || !file_exists($srcAbs) || !is_file($srcAbs)) {
            self::redirect_library('rename_err', ['msg' => __('Invalid path', 'private-file-uploader')]);
        }

        $rename_validation = \PRIVFILEUP\Plugin::validate_rename_target($srcAbs, $base, $new);
        if (is_wp_error($rename_validation)) {
            self::redirect_library('rename_err', ['msg' => $rename_validation->get_error_message()]);
        }

        // The destination MUST be under the base and MUST NOT exist yet
        if (strpos($normDst, $normBase . '/') !== 0) {
            self::redirect_library('rename_err', ['msg' => __('Invalid path', 'private-file-uploader')]);
        }
        if (file_exists($dstAbs) || file_exists($newMeta) || file_exists($newThumb)) {
            self::redirect_library('rename_err', ['msg' => __('Target filename already exists', 'private-file-uploader')]);
        }

        // Hardens the destination directory as well
        $dstDir = \wp_normalize_path(dirname($dstAbs));
        if ($dstDir !== $normBase) {
            self::redirect_library('rename_err', ['msg' => __('Invalid path', 'private-file-uploader')]);
        }

        // Rename the original
        require_once ABSPATH . 'wp-admin/includes/file.php';
        global $wp_filesystem;

        if (! $wp_filesystem) {
            WP_Filesystem();
        }

        if (! $wp_filesystem) {
            self::redirect_library('rename_err', ['msg' => __('Filesystem not available', 'private-file-uploader')]);
        }

        // Remove no-longer-used legacy request metadata first.
        if (!\PRIVFILEUP\Utils::delete_legacy_metadata_sidecar($oldMeta)) {
            self::redirect_library('rename_err', ['msg' => __('Unable to rename file', 'private-file-uploader')]);
        }

        $thumb_moved = false;
        if (file_exists($oldThumb)) {
            if (!is_file($oldThumb) || is_link($oldThumb)) {
                self::redirect_library('rename_err', ['msg' => __('Unable to rename file', 'private-file-uploader')]);
            }

            $thumb_moved = (bool) $wp_filesystem->move($oldThumb, $newThumb, false);
            if (!$thumb_moved) {
                self::redirect_library('rename_err', ['msg' => __('Unable to rename file', 'private-file-uploader')]);
            }
        }

        // Move main file and roll back the thumbnail if it fails.
        if (! $wp_filesystem->move($srcAbs, $dstAbs, false)) {
            if ($thumb_moved) {
                $wp_filesystem->move($newThumb, $oldThumb, false);
            }
            self::redirect_library('rename_err', ['msg' => __('Unable to rename file', 'private-file-uploader')]);
        }

        self::redirect_library('renamed_ok', ['old' => $base, 'new' => $new]);
    }

    private static function redirect_library(string $code, array $args = []): void
    {
        $url = admin_url('admin.php?page=privfileup-library');
        $url = add_query_arg(array_merge(['privfileup_notice' => $code], $args), $url);
        wp_safe_redirect($url);
        exit;
    }
}
