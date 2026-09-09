=== Private File Uploader ===
Contributors: daniloercoli
Tags: upload, rest api, files, storage, application passwords
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 1.2.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Self-hosted per-user uploads with an authenticated REST API, admin library, limits, and image thumbnails.

== Description ==

Private File Uploader stores uploads in a separate directory for each WordPress user. It provides an authenticated REST API for mobile clients and an Admin Library with drag-and-drop upload, rename, and delete actions.

REST operations require a logged-in user or a WordPress Application Password. Files and thumbnails are delivered using direct URLs under the WordPress uploads directory. Those URLs are not automatically access-controlled: anyone who knows a file URL may be able to open it, depending on the web server configuration.

= Features =

* Per-user directories under `/wp-content/uploads/media/private-file-uploader/username/`
* Authenticated REST endpoints for upload, list, rename, delete, and file headers
* Admin Library with drag-and-drop upload, previews, rename, and delete actions
* Automatic thumbnails for image uploads
* Authentication via WordPress Application Passwords
* Configurable upload size limits and MIME type allowlists
* Safe deactivation with file preservation options
* User deletion handling with file reassignment or deletion

= REST API =

The REST API namespace is `/wp-json/private-file-uploader/v1`.

* `GET /ping` checks authentication.
* `POST /upload` accepts multipart field `file`.
* `GET /files` lists the current user's files.
* `HEAD /files/{filename}` returns file headers.
* `POST /files/{filename}/rename` accepts `new_name`.
* `DELETE /files/{filename}` deletes a file.

All routes require authentication. Upload, rename, and delete also require the `upload_files` capability.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`, or install it from the WordPress Plugins screen.
2. Activate the plugin through the Plugins screen.
3. Open Private Uploader in the admin menu.
4. Configure the upload limit and MIME allowlist if needed.
5. Create a WordPress Application Password for each external client that needs REST access.

== Frequently Asked Questions ==

= How do I authenticate with the REST API? =

Use WordPress Application Passwords. Users can create application passwords in their profile. Clients use Basic Authentication with the username and application password.

= Are uploaded files private? =

The REST management endpoints are authenticated, but the file and thumbnail URLs point directly into the uploads directory. The plugin prevents directory listing where possible, but it does not provide authenticated file delivery. Treat a direct URL as shareable and do not upload secrets unless your web server has suitable access controls that remain compatible with your client.

= Where are files stored? =

Files are stored in `/wp-content/uploads/media/private-file-uploader/username/`.

Existing paths for ordinary user logins remain unchanged. Logins that cannot safely identify a directory, including `.` and `..`, cannot use the upload area.

= Can I customize the allowed file types? =

Yes. Administrators can configure allowed MIME types in the plugin settings, or use the `privfileup_allowed_mime_types` filter.

= How do I change the maximum upload size? =

Use the Settings page in the plugin, or the `privfileup_max_upload_bytes` filter.

= What happens when a user or the plugin is deleted? =

When an administrator deletes a user through the WordPress Users screen, the plugin offers to delete, reassign, or quarantine that user's files outside the reusable login path. While the plugin is active, non-interactive deletions quarantine retained files, and network user deletion checks every site's storage, including former memberships. User deletion stops if the files cannot be safely removed or quarantined; fix storage permissions and retry. Files already quarantined remain preserved.

Deleting the plugin normally preserves uploaded files because they are user content. Safe Deactivate handles the current site's storage and requires plugin deactivation permissions. It is unavailable for network-active plugins: manage their activation from Network Admin and arrange file retention or removal for each site before deleting the plugin.

== Privacy ==

Uploaded files are stored on the same WordPress site, in a directory whose name is derived from the user's login. The plugin does not send files or personal data to external services, does not load remote code, and does not include telemetry.

New uploads do not create sidecar files containing IP addresses, user-agent strings, or user IDs. Recognized metadata sidecars from earlier versions are removed during admin maintenance. Administrators control retention: files can be deleted through the REST API or Admin Library, handled during user deletion, or removed with Safe Deactivate. A normal uninstall preserves uploaded files.

Direct file URLs may be accessible to anyone who knows the URL. Site owners should describe this access model in their privacy policy and apply web-server controls if their client workflow permits them.

== External Services ==

This plugin does not connect to external services. WordPress Application Password authentication is handled entirely by the WordPress site.

== Screenshots ==

1. Overview page showing upload policy and server limits
2. Library page with file list, thumbnails, and drag-and-drop uploader
3. Settings page for configuring upload size and MIME types

== Changelog ==

= 1.2.2 =

* Reject unsafe user storage paths and symbolic links without changing existing paths for ordinary logins.
* Preserve exact filenames, including Unicode, when inspecting, renaming, and deleting files.
* Require plugin deactivation permissions and prevent site-level actions from deactivating a network-active plugin.
* Quarantine deleted users' files across all sites and stop user deletion if storage cleanup fails.
* Load the Library uploader through WordPress script APIs.
* Generate Nginx access rules from the actual storage URL, including subdirectory and custom uploads locations.
* Remove plugin settings and notices from every site on Multisite uninstall while preserving uploaded files.

= 1.2.1 =

* Breaking change: moved the REST API to `/private-file-uploader/v1`. REST clients must update their base URL; the previous namespace is no longer registered.
* Standardized plugin-owned identifiers with the unique `privfileup` prefix.
* Added WordPress.org-compliant headers, cleanup, privacy guidance, and internationalization support.
* Prevented unsafe rename targets and public request-metadata sidecars.
* Fixed file deletion compatibility with WordPress 6.0 through 6.6.
* Hardened user-file and Safe Deactivate filesystem operations.

== Upgrade Notice ==

= 1.2.2 =

Fixes file isolation, Unicode filename handling, and Multisite permissions and retention. Keep the plugin active during user deletion so its storage safeguards can run.

= 1.2.1 =

REST clients must use the `/wp-json/private-file-uploader/v1` namespace. This release also includes security, privacy, and WordPress.org review improvements.
