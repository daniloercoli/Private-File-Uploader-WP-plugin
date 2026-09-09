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

// Delete the main settings option.
delete_option('privfileup_settings');
delete_option('privfileup_sidecar_cleanup_121');
delete_option('privfileup_sidecar_cleanup_121_v2');

// Delete the admin notice transient.
delete_transient('privfileup_notice_users');

// Per-user rate-limit transients expire automatically after one hour.
