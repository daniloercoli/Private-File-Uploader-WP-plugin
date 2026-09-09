<?php

/**
 * Plugin Name: Private File Uploader
 * Description: Self-hosted per-user uploads with a REST API, admin library, configurable limits, and image thumbnails.
 * Version: 1.2.2
 * Requires at least: 6.0
 * Requires PHP: 8.0
 * Author: Danilo Ercoli
 * Author URI:  https://wordpress.org/profiles/daniloercoli/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: private-file-uploader
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

define('PRIVFILEUP_PLUGIN_FILE', __FILE__);
define('PRIVFILEUP_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('PRIVFILEUP_PLUGIN_URL', plugin_dir_url(__FILE__));
define('PRIVFILEUP_VERSION', '1.2.2');

// Load classes
require_once __DIR__ . '/src/Utils.php';
require_once __DIR__ . '/src/Plugin.php';
require_once __DIR__ . '/src/Admin.php';

add_action('plugins_loaded', function () {
    \PRIVFILEUP\Plugin::init();
    \PRIVFILEUP\Admin::init();

    \PRIVFILEUP\Utils::log_info('Plugin initialized', [
        'version' => PRIVFILEUP_VERSION,
        'php_version' => PHP_VERSION,
        'wp_version' => get_bloginfo('version')
    ]);
});

add_filter('plugin_action_links_' . plugin_basename(__FILE__), function (array $links) {
    if (!\PRIVFILEUP\Admin::can_safe_deactivate()) {
        return $links;
    }
    $url = admin_url('admin.php?page=privfileup-safe-deactivate');
    array_unshift($links, '<a href="' . esc_url($url) . '">' . esc_html__('Safe Deactivate', 'private-file-uploader') . '</a>');
    return $links;
});

// Log plugin activation
register_activation_hook(__FILE__, function () {
    \PRIVFILEUP\Utils::log_info('Plugin activated');
});

// Log plugin deactivation
register_deactivation_hook(__FILE__, function () {
    \PRIVFILEUP\Utils::log_info('Plugin deactivated');
});
