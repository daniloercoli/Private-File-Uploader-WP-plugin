# Private File Uploader (WordPress Plugin)

A complete, self-hosted file upload solution for WordPress.  
Per-user storage, secure REST API, an admin **Library** with drag-and-drop uploads, automatic thumbnails, and first-class mobile clients.

> Learn more: **https://filesuploader.ercoliconsulting.eu**

### What is it
- **WordPress plugin (this repo):** per-user directories under `uploads/media/private-file-uploader/<username>`, REST endpoints, image thumbnails, admin pages (Overview, Library, Settings, Safe Deactivate).
- **Admin Library UI:** drag & drop uploader (uses the same REST endpoint as the apps), preview icons/thumbs, rename & delete.
- **Mobile apps:** Flutter (primary) and React Native (example) that authenticate via **Application Passwords** over HTTPS.

**Example clients**
- Flutter (primary): https://github.com/daniloercoli/Private-File-Uploader-Flutter-Apps  
- React Native (example): https://github.com/daniloercoli/Private-File-Uploader-ReactNative-Apps

---

## What it does

* REST API under `/wp-json/fileuploader/v1/...`:

  * `GET    /ping` – auth check
  * `POST   /upload` – upload a single file (multipart field **`file`**)
  * `GET    /files` – list user files (pagination & sort)
  * `HEAD   /files/{filename}` – quick metadata via headers
  * `DELETE /files/{filename}` – delete a file (+ its metadata & thumb)
  * `POST   /files/{filename}/rename` – rename a file (+ move metadata & thumb)
* Files are stored under
  `wp-content/uploads/media/private-file-uploader/<username>/...`
* Image uploads get a **server-generated thumbnail**, returned as `thumbUrl`
* Admin **Library** page includes a **drag & drop** uploader that uses the **same REST endpoint** as the mobile apps

---

## Requirements

* WordPress **5.6+** (Application Passwords in core)
* PHP **8.0+** (tested with 8.1/8.2/8.3)
* HTTPS strongly recommended in production

---

## Installation

1. Copy the plugin folder to:
   `wp-content/plugins/wp-private-file-uploader/`
2. In **WP Admin → Plugins**, activate **Private File Uploader**.
3. Ensure REST is reachable:

   * Pretty: `https://example.com/wp-json/`
   * Fallback: `https://example.com/index.php?rest_route=/`
4. If `/wp-json` is 404 on local Apache, flush permalinks (Settings → Permalinks → Save) or use the fallback.

---

## Authentication (Application Passwords)

Each user creates an **Application Password** in
**Users → Profile → Application Passwords**.

Clients authenticate with **Basic**:

```
Authorization: Basic base64(username:application_password)
```

> On some stacks PHP doesn’t receive the header. Add to your site root `.htaccess`:
>
> ```apache
> # Pass HTTP Authorization to PHP (required for Application Passwords)
> RewriteEngine On
> RewriteCond %{HTTP:Authorization} .
> RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
> ```

### MAMP note

Enable mod_rewrite and pass Authorization:

* Edit `/Applications/MAMP/conf/apache/httpd.conf` and ensure:

  ```apache
  LoadModule rewrite_module modules/mod_rewrite.so
  SetEnvIf Authorization .+ HTTP_AUTHORIZATION=$0
  ```
* Restart MAMP.

---

## Configuring limits & types

You can set limits in **Admin → Private Uploader → Settings** and/or override via filters.

### Max upload size (bytes)

Default: **50 MB**.

```php
// 200 MB
add_filter('pfu_max_upload_bytes', fn() => 200 * 1024 * 1024);

// 1 GB
add_filter('pfu_max_upload_bytes', fn() => 1024 * 1024 * 1024);
```

> **Note:** PHP/server limits must also allow it:
> `upload_max_filesize`, `post_max_size`, and any proxy/web server limits.

### Allowed MIME types

Default allowlist:

* `application/zip`
* `image/jpeg`
* `image/png`
* `application/pdf`

Override or extend:

```php
add_filter('pfu_allowed_mime_types', function ($mimes) {
  // Override completely:
  return ['application/zip','application/pdf','image/jpeg','image/png','text/plain','video/mp4'];
});

// or extend defaults:
add_filter('pfu_allowed_mime_types', function ($mimes) {
  $mimes[] = 'text/plain';
  return array_values(array_unique($mimes));
});
```

---

## Endpoints

All endpoints require authentication.

### 1) Ping

```
GET /wp-json/fileuploader/v1/ping
```

**cURL**

```bash
curl -s -u 'USERNAME:APP_PASSWORD' \
  'https://example.com/index.php?rest_route=/fileuploader/v1/ping'
```

---

### 2) Upload (single file)

```
POST /wp-json/fileuploader/v1/upload
```

* Multipart form field: **`file`**
* On images, the plugin generates a **thumbnail** and returns its URL.

**cURL**

```bash
curl -v -u 'USERNAME:APP_PASSWORD' \
  -X POST \
  -F 'file=@/path/to/file.jpg;type=image/jpeg' \
  'https://example.com/index.php?rest_route=/fileuploader/v1/upload'
```

**Response (201)**

```json
{
  "ok": true,
  "file": "photo.jpg",
  "path": "/var/www/.../uploads/media/private-file-uploader/alice/photo.jpg",
  "url": "https://example.com/wp-content/uploads/media/private-file-uploader/alice/photo.jpg",
  "thumbUrl": "https://example.com/wp-content/uploads/media/private-file-uploader/alice/photo-pfu-thumb.jpg",
  "mime": "image/jpeg",
  "owner": "alice",
  "location": "media/private-file-uploader/alice"
}
```

---

### 3) List files

```
GET /wp-json/fileuploader/v1/files
```

Query params:

* `page` (int, default: 1)
* `per_page` (int, default: **1000**, max: **1000**)
* `order` (`asc` | `desc`, default: `desc`)

**Response**

```json
{
  "ok": true,
  "items": [
    {
      "name": "photo.jpg",
      "url": "https://example.com/.../photo.jpg",
      "thumbUrl": "https://example.com/.../photo-pfu-thumb.jpg",
      "size": 123456,
      "mime": "image/jpeg",
      "modified": 1730000000
    }
  ],
  "owner": "alice",
  "count": 1,
  "page": 1,
  "per_page": 1000,
  "total": 1,
  "total_pages": 1,
  "order": "desc"
}
```

> Thumbnails are **not** listed as separate items and are excluded automatically.

---

### 4) File metadata (HEAD)

```
HEAD /wp-json/fileuploader/v1/files/{filename}
```

Returns metadata via headers:

```
X-PFU-Size, X-PFU-Mime, X-PFU-Name, X-PFU-Owner
```

---

### 5) Delete

```
DELETE /wp-json/fileuploader/v1/files/{filename}
```

Deletes the file **and** its sidecar metadata and **thumbnail** when present.

---

### 6) Rename

```
POST /wp-json/fileuploader/v1/files/{filename}/rename
Body: { "newName": "new-filename.ext" }
Content-Type: application/json
```

Renames the file and moves associated **metadata** and **thumbnail**.

**cURL**

```bash
curl -u 'USERNAME:APP_PASSWORD' \
  -H 'Content-Type: application/json' \
  -d '{"newName":"renamed.pdf"}' \
  'https://example.com/wp-json/fileuploader/v1/files/document.pdf/rename'
```

---

## Admin Interface

Accessible from **WP Admin → Private Uploader**.

### Overview

* Shows current upload policy (max size, allowed MIME)
* Displays PHP server limits (`upload_max_filesize`, `post_max_size`, `memory_limit`, …)
* Warns when PHP limits are below plugin policy
* Quick links to **Library** and **Settings**

### Library

* Your files (name, size, modified, MIME)
* **Image preview** (uses generated thumbnail, falls back to original)
* **Delete** & **Rename** actions
* **Drag & drop uploader** that uses the same **REST** endpoint as the mobile apps

### Settings (Admins)

* Configure **max upload size** and **allowed MIME types**
* Options can be overridden via filters for advanced setups

### Safe Deactivate

* Choose to **delete** all files or **keep & block** access (writes deny rules for Apache/IIS; Nginx snippet provided)

### On User Deletion

* **Delete** that user’s files
* **Reassign** to another user
* **Keep** (admin must block public access manually)

---

## Storage Layout

```
wp-content/uploads/
  media/private-file-uploader/
    <username>/
      index.html
      <file>.ext
      <file>.ext.meta.json
      <image>-pfu-thumb.<ext>        # generated thumbnail for images
```

* Directory created on first upload
* `index.html` discourages directory listing

---

## Troubleshooting

* **404 on `/wp-json`**: use `index.php?rest_route=/...` or fix permalinks/rewrites.
* **401 Unauthorized**: verify Application Password and that PHP receives `Authorization` (see `.htaccess`).
* **Missing parameter: file**: send multipart **`file`** field (don’t force `Content-Type` by hand).
* **413 Payload Too Large**: increase plugin limit **and** PHP/server limits (`upload_max_filesize`, `post_max_size`, proxy).
* **415 Unsupported Media Type**: add the MIME to the allowlist (Settings or filter).
* **Thumbnails**: only for images; URLs are returned as `thumbUrl`.

---

## Development

* Entry: `private-file-uploader.php`
* Core: `src/Plugin.php` (routes, upload/validation, per-user storage, thumbnails, rename/delete)
* Admin: `src/Admin.php` (overview, library + drag&drop uploader via REST, settings, safe deactivate, user deletion helpers)
* No DB schema changes; uses WP upload APIs (`wp_handle_sideload`) and filesystem.

Quick ping:

```bash
curl -s 'http://localhost/wp/index.php?rest_route=/fileuploader/v1/ping'
```

---

## License

MIT — see [LICENSE](./LICENSE).
