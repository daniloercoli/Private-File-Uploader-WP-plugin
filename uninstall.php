<?php
/**
 * Uninstall handler for Private File Uploader.
 *
 * Fired when the user deletes the plugin from the WordPress admin.
 * Removes plugin options and transients. User-uploaded files are NOT
 * deleted here: they are content, and the plugin provides a "Safe
 * Deactivate" screen to handle file removal explicitly.
 *
 * @package PrivateFileUploader
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$privfileup_cleanup_site = static function (): void {
    delete_option('privfileup_settings');
    delete_option('privfileup_sidecar_cleanup_121');
    delete_option('privfileup_sidecar_cleanup_121_v2');
    delete_transient('privfileup_notice_users');
};

if (is_multisite()) {
    // Plugin files are removed for the entire installation, so clean every
    // site's configuration, even if the plugin is currently inactive there.
    $privfileup_offset = 0;
    do {
        $privfileup_site_ids = get_sites(['fields' => 'ids', 'number' => 100, 'offset' => $privfileup_offset, 'orderby' => 'id', 'order' => 'ASC']);
        foreach ($privfileup_site_ids as $privfileup_site_id) {
            switch_to_blog((int) $privfileup_site_id);
            try {
                $privfileup_cleanup_site();
            } finally {
                restore_current_blog();
            }
        }
        $privfileup_offset += count($privfileup_site_ids);
    } while (count($privfileup_site_ids) === 100);
} else {
    $privfileup_cleanup_site();
}

// Per-user rate-limit transients expire automatically after one hour.
