<?php
/** WordPress integration checks for uploader assets, Nginx rules and uninstall. */
if (!defined('PRIVFILEUP_TEST_SANDBOX') || PRIVFILEUP_TEST_SANDBOX !== true || !defined('WP_CLI') || !WP_CLI) {
    throw new RuntimeException('A disposable WordPress CLI sandbox is required.');
}

use PRIVFILEUP\Admin;
use PRIVFILEUP\Plugin;

$checks = 0;
$expect = static function ($condition, string $message) use (&$checks): void {
    ++$checks;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $message);
    }
    WP_CLI::log('PASS: ' . $message);
};
$original_blog = get_current_blog_id();
$base = Plugin::get_user_base(wp_get_current_user());
$fixture = $base['path'] . '/p2-retained.pdf';
file_put_contents($fixture, 'Retained user content fixture');

// R5: Core actually prints the configuration before the external uploader.
Admin::enqueue_library_uploader('dashboard');
$expect(!wp_script_is('privfileup-library-uploader', 'enqueued'), 'uploader is not enqueued on unrelated admin pages');
Admin::enqueue_library_uploader('private-uploader_page_privfileup-library');
$expect(wp_script_is('privfileup-library-uploader', 'enqueued'), 'uploader is enqueued on Library');
ob_start();
wp_print_scripts('privfileup-library-uploader');
$scripts = ob_get_clean();
$configuration = strpos($scripts, 'window.PRIVFILEUP_UPLOADER');
$source = strpos($scripts, 'assets/js/library-uploader.js');
$expect($configuration !== false && $source !== false && $configuration < $source, 'Core prints uploader configuration before the script');
$expect(strpos($scripts, 'plupload') < $source && strpos($scripts, 'jquery') < $source, 'Core dependencies precede uploader');
ob_start();
Admin::render_library_page();
$library = ob_get_clean();
$expect(strpos($library, '<script') === false && strpos($library, 'onclick=') === false && strpos($library, 'onerror=') === false, 'Library markup has no directly embedded JavaScript');
$expect(strpos($library, 'privfileup-delete-file') !== false, 'delete buttons expose the external script binding');

// R6: URL routing is independent of the uploads filesystem location.
$rule = new ReflectionMethod(Admin::class, 'get_nginx_deny_rule');
$rule->setAccessible(true);
$locations = [
    'https://example.invalid/wp-content/uploads' => '/wp-content/uploads/media/private-file-uploader/',
    'https://example.invalid/wp1/wp-content/uploads' => '/wp1/wp-content/uploads/media/private-file-uploader/',
    'https://cdn.example.invalid/another/place' => '/another/place/media/private-file-uploader/',
    'https://cdn.example.invalid/space%20and%20%E6%9D%B1%E4%BA%AC' => '/space and 東京/media/private-file-uploader/',
];
foreach ($locations as $url => $expected) {
    $filter = static function ($dirs) use ($url) { $dirs['baseurl'] = $url; return $dirs; };
    add_filter('upload_dir', $filter);
    try {
        $actual = $rule->invoke(null);
        $expect($actual === 'location ^~ "' . $expected . '" {' . "\n    deny all;\n}", 'Nginx prefix matches storage URL ' . $url);
    } finally {
        remove_filter('upload_dir', $filter);
    }
}
foreach (['/uploads/%0a', '/uploads/%22', '/uploads/%5c', '/uploads/$uri', '/uploads/../'] as $unsafe_path) {
    $filter = static function ($dirs) use ($unsafe_path) { $dirs['baseurl'] = 'https://example.invalid' . $unsafe_path; return $dirs; };
    add_filter('upload_dir', $filter);
    try {
        $expect($rule->invoke(null) === '', 'do not emit an unsafe Nginx configuration for ' . $unsafe_path);
    } finally {
        remove_filter('upload_dir', $filter);
    }
}

// R7: uninstall removes configuration in every site, preserving content/context.
$sites = is_multisite() ? get_sites(['fields' => 'ids', 'number' => 0]) : [$original_blog];
foreach ($sites as $site_id) {
    if (is_multisite()) switch_to_blog((int) $site_id);
    update_option('privfileup_settings', ['fixture' => $site_id]);
    update_option('privfileup_sidecar_cleanup_121', 'fixture');
    update_option('privfileup_sidecar_cleanup_121_v2', 'fixture');
    set_transient('privfileup_notice_users', 'fixture', 60);
    if (is_multisite()) restore_current_blog();
}
define('WP_UNINSTALL_PLUGIN', plugin_basename(PRIVFILEUP_PLUGIN_FILE));
require PRIVFILEUP_PLUGIN_DIR . 'uninstall.php';
$expect(get_current_blog_id() === $original_blog, 'uninstall restores original site context');
foreach ($sites as $site_id) {
    if (is_multisite()) switch_to_blog((int) $site_id);
    $expect(
        get_option('privfileup_settings', false) === false &&
        get_option('privfileup_sidecar_cleanup_121', false) === false &&
        get_option('privfileup_sidecar_cleanup_121_v2', false) === false &&
        get_transient('privfileup_notice_users') === false,
        'uninstall cleans plugin options and notice on site ' . $site_id
    );
    if (is_multisite()) restore_current_blog();
}
$expect(is_file($fixture) && file_get_contents($fixture) === 'Retained user content fixture', 'uninstall preserves uploaded content');
WP_CLI::success($checks . ' P2 regression checks passed.');
