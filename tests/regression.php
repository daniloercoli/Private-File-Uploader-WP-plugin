<?php
/**
 * Integration regressions. Run only in a disposable WordPress installation.
 * See tests/README.md. This script creates users, files and (on Multisite) sites.
 */

if (!defined('PRIVFILEUP_TEST_SANDBOX') || PRIVFILEUP_TEST_SANDBOX !== true || !defined('WP_CLI') || !WP_CLI) {
    throw new RuntimeException('A disposable WordPress CLI sandbox is required.');
}

use PRIVFILEUP\Admin;
use PRIVFILEUP\Plugin;

require_once ABSPATH . 'wp-admin/includes/user.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
WP_Filesystem();

$run = 'pfu' . strtolower(wp_generate_password(8, false, false));
$checks = 0;
$expect = static function ($condition, string $message) use (&$checks): void {
    ++$checks;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $message);
    }
    WP_CLI::log('PASS: ' . $message);
};
$new_user = static function (string $login, string $role = 'author') use ($run): WP_User {
    $id = wp_insert_user([
        'user_login' => $login,
        'user_nicename' => $run . '-' . wp_generate_password(6, false, false),
        'user_pass' => wp_generate_password(),
        'user_email' => wp_generate_password(10, false, false) . '@example.invalid',
        'role' => $role,
    ]);
    if (is_wp_error($id)) {
        throw new RuntimeException($id->get_error_message());
    }
    return get_user_by('id', $id);
};
$request = static function (string $method, string $path, array $params = []): WP_REST_Response {
    $req = new WP_REST_Request($method, '/' . Plugin::REST_NS . $path);
    foreach ($params as $key => $value) {
        $req->set_param($key, $value);
    }
    return rest_do_request($req);
};
$upload = static function (string $name) use ($expect): string {
    $tmp = wp_tempnam('privfileup-regression');
    file_put_contents($tmp, "%PDF-1.4\nTemporary regression fixture\n%%EOF\n");
    $req = new WP_REST_Request('POST', '/' . Plugin::REST_NS . '/upload');
    $req->set_file_params(['file' => [
        'name' => $name, 'type' => 'application/pdf', 'tmp_name' => $tmp,
        'error' => UPLOAD_ERR_OK, 'size' => filesize($tmp),
    ]]);
    $response = rest_do_request($req);
    $expect($response->get_status() === 201, 'upload accepts ' . $name);
    return $response->get_data()['path'];
};
// Let tests inspect wp_die and redirects before the actual exit call.
add_filter('wp_die_handler', static function () {
    return static function ($message, $title = '', $args = []) {
        throw new RuntimeException('wp_die:' . ($args['response'] ?? 500) . ':' . wp_strip_all_tags($message));
    };
});
add_filter('wp_redirect', static function ($url) {
    throw new RuntimeException('redirect:' . $url);
}, -100);
$invoke_admin = static function (callable $callback): string {
    try {
        $callback();
    } catch (RuntimeException $e) {
        return $e->getMessage();
    }
    throw new RuntimeException('Expected an admin redirect or wp_die.');
};

$original_blog = get_current_blog_id();
$original_user = get_current_user_id();
$original_post = $_POST;
$original_get = $_GET;
$original_request = $_REQUEST;
$plugin = plugin_basename(PRIVFILEUP_PLUGIN_FILE);
$author = $new_user($run . '_author');
wp_set_current_user($author->ID);
$base = Plugin::get_user_base($author);
$expect(!is_wp_error($base), 'ordinary login has valid storage');
$expect($base['path'] === Plugin::storage_root_base() . '/' . $author->user_login, 'existing username path remains unchanged');
$expect(Plugin::get_user_base($author, false) === $base, 'read-only resolution matches writable resolution');

// R1: special logins, path aliases and symlinks cannot escape the storage root.
$outside = dirname(Plugin::storage_root_base()) . '/' . $run . '-outside.pdf';
file_put_contents($outside, 'outside fixture');
foreach (['.', '..', 'trailing.', 'trailing ', 'a/b', 'a\\b', 'alias:stream'] as $login) {
    $fake = clone $author;
    $fake->user_login = $login;
    $expect(is_wp_error(Plugin::get_user_base($fake)), 'reject unsafe storage login ' . $login);
}
$dot_user = get_user_by('login', '..');
if (!$dot_user) {
    $dot_user = $new_user('..');
}
wp_set_current_user($dot_user->ID);
$expect($request('GET', '/files')->get_status() === 403, 'dotdot login cannot list parent files');
$expect($request('DELETE', '/files/' . basename($outside))->get_status() === 403 && file_exists($outside), 'dotdot login cannot delete parent files');
$tmp_upload = wp_tempnam('privfileup-dotdot');
file_put_contents($tmp_upload, "%PDF-1.4\nFixture\n%%EOF\n");
$req = new WP_REST_Request('POST', '/' . Plugin::REST_NS . '/upload');
$req->set_file_params(['file' => ['name' => $run . '.pdf', 'type' => 'application/pdf', 'tmp_name' => $tmp_upload, 'size' => filesize($tmp_upload), 'error' => 0]]);
$expect(rest_do_request($req)->get_status() === 403, 'dotdot upload cannot write into parent directory');
wp_delete_file($tmp_upload);
wp_set_current_user($author->ID);
$link_user = $new_user($run . '_link');
$link_path = Plugin::storage_root_base() . '/' . $link_user->user_login;
$expect(symlink($base['path'], $link_path), 'create isolated symlink fixture');
$expect(is_wp_error(Plugin::get_user_base($link_user)), 'reject a user directory symlink to another user');
unlink($link_path);

// R2: exact filename identity across real upload, REST and admin handlers.
$ascii = $upload('report.pdf');
$unicode = $upload('report東京.pdf');
$head = $request('HEAD', '/files/report東京.pdf');
$expect($head->get_status() === 200 && $head->get_headers()['X-Private-File-Uploader-Name'] === 'report東京.pdf', 'HEAD preserves the Unicode filename');
$deleted = $request('DELETE', '/files/report東京.pdf');
$expect($deleted->get_status() === 200 && $deleted->get_data()['deleted'] === 'report東京.pdf', 'REST delete targets the exact Unicode filename');
$expect(file_exists($ascii) && !file_exists($unicode), 'REST delete preserves similarly named ASCII file');
$upload('report東京.pdf');
$rename = $request('POST', '/files/report東京.pdf/rename', ['new_name' => 'renamed東京.pdf']);
$expect($rename->get_status() === 200 && file_exists(dirname($ascii) . '/renamed東京.pdf') && file_exists($ascii), 'REST rename preserves Unicode and neighboring file');
foreach (['../report.pdf', 'folder/report.pdf', 'folder\\report.pdf', "report.pdf\0", 'file:stream', 'file.pdf.', "file.pdf\r\nX-Header:test"] as $name) {
    $expect(is_wp_error(Plugin::sanitize_user_filename($name)), 'reject unsafe basename ' . wp_json_encode($name));
}
foreach (['file.php', 'file.php.pdf', '.htaccess'] as $name) {
    $expect(is_wp_error(Plugin::validate_rename_target($ascii, 'report.pdf', $name)), 'reject unsafe rename ' . $name);
}
$_POST = ['file' => 'renamed東京.pdf', 'new_name' => 'admin東京.pdf'];
$_REQUEST['_wpnonce'] = wp_create_nonce('privfileup_rename_renamed東京.pdf');
$result = $invoke_admin([Admin::class, 'handle_rename_file']);
$expect(str_starts_with($result, 'redirect:') && file_exists(dirname($ascii) . '/admin東京.pdf') && file_exists($ascii), 'admin rename preserves exact Unicode filename');
$_GET = ['file' => 'admin東京.pdf'];
$_REQUEST['_wpnonce'] = wp_create_nonce('privfileup_del_admin東京.pdf');
$result = $invoke_admin([Admin::class, 'handle_delete_file']);
$expect(str_starts_with($result, 'redirect:') && !file_exists(dirname($ascii) . '/admin東京.pdf') && file_exists($ascii), 'admin delete preserves similarly named file');
$_POST = [];
$_GET = [];
$_REQUEST = [];

$subscriber = $new_user($run . '_subscriber', 'subscriber');
wp_set_current_user($subscriber->ID);
foreach ([['POST', '/upload'], ['DELETE', '/files/report.pdf'], ['POST', '/files/report.pdf/rename']] as [$method, $path]) {
    $expect($request($method, $path, ['new_name' => 'other.pdf'])->get_status() === 403, 'subscriber cannot ' . $method . ' ' . $path);
}
wp_set_current_user(0);
$expect($request('GET', '/files')->get_status() === 401, 'anonymous file listing is denied');

// R4: a failed move must stop user deletion, leaving their identity reserved.
wp_set_current_user($original_user);
$failure_user = $new_user($run . '_failure');
$failure_dir = Plugin::get_user_base($failure_user)['path'];
file_put_contents($failure_dir . '/retained.pdf', 'retained fixture');
$working_filesystem = $GLOBALS['wp_filesystem'];
$GLOBALS['wp_filesystem'] = new class extends WP_Filesystem_Direct {
    public function __construct() { parent::__construct(null); }
    public function move($source, $destination, $overwrite = false) { return false; }
};
$result = $invoke_admin(static function () use ($failure_user) { wp_delete_user($failure_user->ID); });
$expect(str_starts_with($result, 'wp_die:500:') && get_user_by('id', $failure_user->ID) && file_exists($failure_dir . '/retained.pdf'), 'failed quarantine stops user deletion and preserves files');
$GLOBALS['wp_filesystem'] = $working_filesystem;
$expect(wp_delete_user($failure_user->ID), 'user deletion succeeds after filesystem recovery');
$expect(!is_dir($failure_dir), 'successful quarantine removes the reusable login path');

if (is_multisite()) {
    require_once ABSPATH . 'wp-admin/includes/ms.php';
    $network_admin = get_user_by('login', get_super_admins()[0]);
    wp_set_current_user($network_admin->ID);
    activate_plugin($plugin, '', true);
    $site_id = wpmu_create_blog(DOMAIN_CURRENT_SITE, '/' . $run . '/', $run, $network_admin->ID);
    $expect(!is_wp_error($site_id), 'create isolated secondary site');
    $owner = $new_user($run . '_owner');
    add_user_to_blog($site_id, $owner->ID, 'author');
    switch_to_blog($site_id);
    $owner_path = Plugin::get_user_base($owner)['path'];
    file_put_contents($owner_path . '/old-owner.pdf', 'old owner fixture');
    restore_current_blog();
    remove_user_from_blog($owner->ID, $site_id);
    $expect(wpmu_delete_user($owner->ID), 'network deletion succeeds for former site member');
    $expect(get_current_blog_id() === $original_blog && !is_dir($owner_path), 'all former membership storage is quarantined and site context restored');
    $replacement = $new_user($owner->user_login);
    add_user_to_blog($site_id, $replacement->ID, 'author');
    switch_to_blog($site_id);
    wp_set_current_user($replacement->ID);
    $list = $request('GET', '/files');
    $expect($list->get_status() === 200 && empty($list->get_data()['items']), 'replacement login cannot see previous owner files');
    restore_current_blog();

    // Retry failure on a secondary site and verify the network user is retained.
    wp_set_current_user($network_admin->ID);
    $blocked = $new_user($run . '_blocked');
    switch_to_blog($site_id);
    $blocked_path = Plugin::get_user_base($blocked)['path'];
    file_put_contents($blocked_path . '/retained.pdf', 'retained network fixture');
    restore_current_blog();
    $GLOBALS['wp_filesystem'] = new class extends WP_Filesystem_Direct {
        public function __construct() { parent::__construct(null); }
        public function move($source, $destination, $overwrite = false) { return false; }
    };
    $result = $invoke_admin(static function () use ($blocked) { wpmu_delete_user($blocked->ID); });
    $expect(str_starts_with($result, 'wp_die:500:') && get_user_by('id', $blocked->ID), 'failed secondary-site quarantine prevents network user deletion');
    $expect(get_current_blog_id() === $original_blog && file_exists($blocked_path . '/retained.pdf'), 'failed network cleanup restores site context and preserves data');
    $GLOBALS['wp_filesystem'] = $working_filesystem;

    // R3: a valid nonce and manage_options do not grant network deactivation.
    $site_admin = $new_user($run . '_admin', 'administrator');
    wp_set_current_user($site_admin->ID);
    $expect(current_user_can('manage_options') && !current_user_can('manage_network_plugins'), 'site admin fixture has no network permissions');
    $_POST = ['privfileup_mode' => 'delete'];
    $_REQUEST['_wpnonce'] = wp_create_nonce('privfileup_safe_deactivate');
    $result = $invoke_admin([Admin::class, 'handle_safe_deactivate']);
    $expect(str_starts_with($result, 'wp_die:403:') && is_plugin_active_for_network($plugin) && file_exists($ascii), 'site admin cannot deactivate network plugin or delete storage');
    $expect(!Admin::can_safe_deactivate(), 'Safe Deactivate link is unavailable for network activation');
    wp_set_current_user($network_admin->ID);
    $expect(!Admin::can_safe_deactivate(), 'network administrators use Network Admin for network activation');
} else {
    // R3: custom site roles with manage_options alone are also denied.
    $settings_user = $new_user($run . '_settings', 'subscriber');
    $settings_user->add_cap('manage_options');
    wp_set_current_user($settings_user->ID);
    $_POST = ['privfileup_mode' => 'delete'];
    $_REQUEST['_wpnonce'] = wp_create_nonce('privfileup_safe_deactivate');
    $result = $invoke_admin([Admin::class, 'handle_safe_deactivate']);
    $expect(str_starts_with($result, 'wp_die:403:') && file_exists($ascii), 'manage_options alone cannot deactivate or delete storage');
    $site_admin = $new_user($run . '_admin', 'administrator');
    wp_set_current_user($site_admin->ID);
    $expect(Admin::can_safe_deactivate(), 'site administrator retains safe deactivation for site activation');
}

$_POST = $original_post;
$_GET = $original_get;
$_REQUEST = $original_request;
wp_set_current_user($original_user);
WP_CLI::success($checks . ' regression checks passed.');
