=== Private File Uploader ===
Contributors: daniloercoli
Tags: upload, media, rest api, privacy, files
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 8.0
Stable tag: 1.2.1
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html

A complete, self-hosted file upload solution for WordPress.
Per-user storage, secure REST API, automatic thumbnails, and first-class mobile clients.

== Description ==

**Private File Uploader** adds per-user storage, a secure REST API, and an Admin **Library** with drag-and-drop uploads.

* Per-user directories under `uploads/media/private-file-uploader/<username>`
* REST endpoints for upload, list, rename, delete, and quick metadata (HEAD)
* Admin **Library** with drag & drop uploader, preview icons/thumbs, rename & delete
* Automatic **thumbnails** for image uploads (returned as `thumbUrl`)
* Works great with mobile apps via **Application Passwords** over HTTPS

> Learn more: https://filesuploader.ercoliconsulting.eu

**Example mobile clients**

* Flutter (primary): https://github.com/daniloercoli/Private-File-Uploader-Flutter-Apps  
* React Native (example): https://github.com/daniloercoli/Private-File-Uploader-ReactNative-Apps

= REST API overview =

Endpoints (all require authentication):

* `GET    /wp-json/fileuploader/v1/ping` – auth check
* `POST   /wp-json/fileuploader/v1/upload` – upload a single file (multipart field **`file`**)
* `GET    /wp-json/fileuploader/v1/files` – list user files (pagination & sort)
* `HEAD   /wp-json/fileuploader/v1/files/{filename}` – quick metadata via headers
* `DELETE /wp-json/fileuploader/v1/files/{filename}` – delete a file (+ metadata & thumb)
* `POST   /wp-json/fileuploader/v1/files/{filename}/rename` – rename a file (+ move metadata & thumb)

Files are stored in:
`wp-content/uploads/media/private-file-uploader/<username>/...`

== Installation ==

1. Upload the plugin folder to:
   `wp-content/plugins/wp-private-file-uploader/`
2. In **WP Admin → Plugins**, activate **Private File Uploader**.
3. Ensure REST is reachable:
   * Pretty: `https://example.com/wp-json/`
   * Fallback: `https://example.com/index.php?rest_route=/`
4. If `/wp-json` is 404 on local Apache, flush permalinks (Settings → Permalinks → Save) or use the fallback form.

== Frequently Asked Questions ==

= How do I authenticate? =

Use **Application Passwords** (core feature since WP 5.6).  
Each user creates one in **Users → Profile → Application Passwords**.  
Clients send Basic Auth:
`Authorization: Basic base64(username:application_password)`

On some stacks PHP doesn’t receive the header. Add to your site root `.htaccess`:

Pass HTTP Authorization to PHP (required for Application Passwords)
```
RewriteEngine On
RewriteCond %{HTTP:Authorization} .
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
```

= Can I upload from the Admin Library? =

Yes. The Library includes a **drag & drop** uploader that uses the **same REST endpoint** as the apps.

= Where are files stored? =

Under:
`wp-content/uploads/media/private-file-uploader/<username>/...`  
Each folder contains an `index.html` to discourage directory listing.

= How do I change max size or allowed MIME types? =

Use **Settings** in WP Admin → Private Uploader, or filters:
```
add_filter('pfu_max_upload_bytes', fn() => 200 * 1024 * 1024); // 200 MB
add_filter('pfu_allowed_mime_types', function ($m) {
$m[] = 'text/plain';
return array_values(array_unique($m));
});
```

> PHP/server limits must also allow it: `upload_max_filesize`, `post_max_size`, and any proxy/web server limits.

= Do image uploads generate thumbnails? =

Yes. A server-generated thumbnail is created and returned in API responses as `thumbUrl`. The Library also uses it, with fallback to the original image.

== Screenshots ==

1. Overview page with policy and server limit checks  
2. Library with thumbnails, rename, delete, and drag & drop uploader  
3. Settings for max size and allowed MIME types

== Changelog ==

= 1.2.0 =
* Admin Library: drag & drop uploader (uses REST)
* Thumbnails for images (returned as `thumbUrl`; excluded from listings)
* File rename (moves metadata & thumbnail)
* Per-user storage under `/uploads/media/private-file-uploader/<username>`
* REST: ping, upload, list (pagination & sort), head metadata, delete, rename
* Settings: max upload size, allowed MIME types (+ filters)
* Overview: shows PHP limits and warns if lower than policy
* Safe Deactivate: delete all or keep & block access (Apache/IIS helpers, Nginx snippet)
* User deletion helpers: delete/reassign/keep

== Upgrade Notice ==

= 1.2.0 =
Adds drag & drop uploader in Admin, thumbnails, and file rename. Review Settings and server PHP limits if you handle large files.

== Documentation ==

* Full overview & docs: https://filesuploader.ercoliconsulting.eu
* Flutter client (primary): https://github.com/daniloercoli/Private-File-Uploader-Flutter-Apps
* React Native client (example): https://github.com/daniloercoli/Private-File-Uploader-ReactNative-Apps

