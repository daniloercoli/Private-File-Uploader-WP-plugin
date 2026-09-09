<?php

namespace PRIVFILEUP;

if (!defined('ABSPATH')) {
    exit;
}

class Plugin
{
    const REST_NS   = 'private-file-uploader/v1';
    const SLUG      = 'private-file-uploader';
    const SUB_BASE  = 'media/private-file-uploader'; // under uploads/

    // Default values; overridable via filters (see below)
    const DEFAULT_MAX_UPLOAD_BYTES = 50 * 1024 * 1024; // 50 MB
    const DEFAULT_ALLOWED_MIME = [
        'application/zip',
        'image/jpeg',
        'image/png',
        'application/pdf',
    ];

    /**
     * Get the storage root base directory
     *
     * @return string Absolute path to the storage root
     */
    public static function storage_root_base(): string
    {
        $up = \wp_get_upload_dir();
        return trailingslashit($up['basedir']) . self::SUB_BASE;
    }

    /**
     * Get the effective max upload size (defaults → options → filters)
     *
     * @return int Maximum upload size in bytes
     */
    public static function effective_max_upload_bytes(): int
    {
        return self::get_max_upload_bytes();
    }

    /**
     * Get the effective allowed MIME types (defaults → options → filters)
     *
     * @return array<string> List of allowed MIME types
     */
    public static function effective_allowed_mime_types(): array
    {
        return self::get_allowed_mime_types();
    }

    /**
     * Get the max upload size in bytes, configurable via 'privfileup_max_upload_bytes' filter
     *
     * @return int Maximum upload size in bytes
     */
    private static function get_max_upload_bytes(): int
    {
        // 1) defaults
        $max = self::DEFAULT_MAX_UPLOAD_BYTES;

        // 2) options (admin settings)
        if (class_exists(__NAMESPACE__ . '\\Admin')) {
            $opt = Admin::get_settings();
            if (!empty($opt['privfileup_max_upload_bytes']) && (int)$opt['privfileup_max_upload_bytes'] > 0) {
                $max = (int)$opt['privfileup_max_upload_bytes'];
            }
        }

        // 3) uniquely prefixed filter.
        $max = (int) apply_filters('privfileup_max_upload_bytes', $max);
        return $max > 0 ? $max : self::DEFAULT_MAX_UPLOAD_BYTES;
    }

    /**
     * Get the allowed MIME types, configurable via 'privfileup_allowed_mime_types' filter
     *
     * @return array<string> List of allowed MIME types
     */
    private static function get_allowed_mime_types(): array
    {
        // 1) defaults
        $allowed = self::DEFAULT_ALLOWED_MIME;

        // 2) options (admin settings)
        if (class_exists(__NAMESPACE__ . '\\Admin')) {
            $opt = Admin::get_settings();
            if (!empty($opt['privfileup_allowed_mime_types']) && is_array($opt['privfileup_allowed_mime_types'])) {
                $allowed = array_values(array_unique(array_filter(array_map('strval', $opt['privfileup_allowed_mime_types']))));
            }
        }

        // 3) uniquely prefixed filter.
        $m = apply_filters('privfileup_allowed_mime_types', $allowed);
        if (!is_array($m) || empty($m)) {
            return $allowed;
        }
        return array_values(array_unique(array_filter(array_map('strval', $m))));
    }

    /**
     * Initialize the plugin
     */
    public static function init(): void
    {
        add_action('rest_api_init', [__CLASS__, 'register_routes']);
        Utils::log_debug('REST routes initialization scheduled');
    }

    /**
     * Register REST API routes
     */
    public static function register_routes(): void
    {
        // GET /ping - Authentication check
        register_rest_route(self::REST_NS, '/ping', [
            [
                'methods'  => 'GET',
                'callback' => [__CLASS__, 'route_ping'],
                'permission_callback' => [__CLASS__, 'require_auth'],
            ],
        ]);

        // POST /upload - Upload a single file
        register_rest_route(self::REST_NS, '/upload', [
            [
                'methods'  => 'POST',
                'callback' => [__CLASS__, 'route_upload'],
                'permission_callback' => [__CLASS__, 'require_can_upload'],
            ],
        ]);

        // GET /files - List user's files
        register_rest_route(self::REST_NS, '/files', [
            [
                'methods'  => 'GET',
                'callback' => [__CLASS__, 'route_list_files'],
                'permission_callback' => [__CLASS__, 'require_auth'],
                'args' => [
                    'page' => [
                        'description' => __('Page number (1-based)', 'private-file-uploader'),
                        'type'        => 'integer',
                        'required'    => false,
                        'sanitize_callback' => 'absint',
                        'validate_callback' => static function ($value) {
                            return ($value === null) || (absint($value) >= 1);
                        },
                    ],
                    'per_page' => [
                        'description' => __('Items per page (1..1000)', 'private-file-uploader'),
                        'type'        => 'integer',
                        'required'    => false,
                        'sanitize_callback' => 'absint',
                        'validate_callback' => static function ($value) {
                            $v = absint($value);
                            return $v >= 1 && $v <= 1000;
                        },
                    ],
                    'order' => [
                        'description' => __('Sort by modified time: desc|asc', 'private-file-uploader'),
                        'type'        => 'string',
                        'required'    => false,
                        'sanitize_callback' => 'sanitize_text_field',
                        'validate_callback' => static function ($value) {
                            return in_array(strtolower((string)$value), ['asc', 'desc'], true);
                        },
                    ],
                ],
            ],
        ]);

        // DELETE /files/{filename} - Delete a user's file
        register_rest_route(self::REST_NS, '/files/(?P<filename>[^/]+)', [
            [
                'methods'  => 'DELETE',
                'callback' => [__CLASS__, 'route_delete_file'],
                'permission_callback' => [__CLASS__, 'require_can_upload'],
                'args' => [
                    'filename' => [
                        'description' => __('Base filename to delete (no slashes)', 'private-file-uploader'),
                        'required' => true,
                        'sanitize_callback' => [__CLASS__, 'sanitize_user_filename'],
                        'validate_callback' => static function ($value) {
                            return is_string($value) && strpos($value, '/') === false;
                        },
                    ],
                ],
            ],
        ]);

        // POST /files/{filename}/rename  - Rename a user's file
        register_rest_route(self::REST_NS, '/files/(?P<filename>[^/]+)/rename', [
            [
                'methods'  => 'POST',
                'callback' => [__CLASS__, 'route_rename_file'],
                'permission_callback' => [__CLASS__, 'require_can_upload'],
                'args' => [
                    'filename' => [
                        'description' => __('Current base filename (no slashes)', 'private-file-uploader'),
                        'required' => true,
                        'sanitize_callback' => [__CLASS__, 'sanitize_user_filename'],
                        'validate_callback' => static function ($value) {
                            return is_string($value) && strpos($value, '/') === false;
                        },
                    ],
                    'new_name' => [
                        'description' => __('New base filename (no slashes)', 'private-file-uploader'),
                        'type'        => 'string',
                        'required'    => true,
                        'sanitize_callback' => [__CLASS__, 'sanitize_user_filename'],
                        'validate_callback' => static function ($value) {
                            return is_string($value) && $value !== '' && strpos($value, '/') === false;
                        },
                    ],
                ],
            ],
        ]);

        // HEAD /files/{filename} - Get file metadata via headers (no body)
        register_rest_route(self::REST_NS, '/files/(?P<filename>[^/]+)', [
            [
                'methods'  => 'HEAD',
                'callback' => [__CLASS__, 'route_head_file'],
                'permission_callback' => [__CLASS__, 'require_auth'],
                'args' => [
                    'filename' => [
                        'description' => __('Base filename to inspect (no slashes)', 'private-file-uploader'),
                        'required' => true,
                        'sanitize_callback' => [__CLASS__, 'sanitize_user_filename'],
                        'validate_callback' => static function ($value) {
                            return is_string($value) && strpos($value, '/') === false;
                        },
                    ],
                ],
            ],
        ]);

        Utils::log_debug('REST routes registered', [
            'namespace' => self::REST_NS,
            'endpoints' => 5
        ]);
    }

    /**
     * Permission callback: require authentication (Application Password)
     *
     * @param \WP_REST_Request $req Current request
     * @return bool|\WP_Error True if authenticated, WP_Error otherwise
     */
    public static function require_auth(\WP_REST_Request $req)
    {
        if (is_user_logged_in()) {
            return true;
        }

        Utils::log_warning('Unauthorized access attempt', [
            'endpoint' => $req->get_route(),
            'ip' => Utils::get_client_ip()
        ]);

        return new \WP_Error('privfileup_auth', __('Authentication required', 'private-file-uploader'), ['status' => 401]);
    }

    /**
     * Permission callback: require authenticated user with upload capability
     *
     * @param \WP_REST_Request $req Current request
     * @return bool|\WP_Error True if authorized, WP_Error otherwise
     */
    public static function require_can_upload(\WP_REST_Request $req)
    {
        if (is_user_logged_in() && current_user_can('upload_files')) {
            return true;
        }

        Utils::log_warning('Forbidden access attempt - insufficient permissions', [
            'endpoint' => $req->get_route(),
            'user_id' => get_current_user_id(),
            'ip' => Utils::get_client_ip()
        ]);

        return new \WP_Error('privfileup_forbidden', __('Insufficient permissions', 'private-file-uploader'), ['status' => 403]);
    }

    /**
     * GET /ping - Useful for testing credentials via curl
     *
     * @param \WP_REST_Request $req Current request
     * @return \WP_REST_Response Response with user info
     */
    public static function route_ping(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = wp_get_current_user();

        Utils::log_info('Ping endpoint accessed', [
            'user' => $user ? $user->user_login : 'guest',
            'ip' => Utils::get_client_ip(),
            'mobile' => Utils::is_mobile_request()
        ]);

        return new \WP_REST_Response([
            'ok'      => true,
            'user'    => $user ? $user->user_login : null,
            'message' => __('Hello from Private File Uploader', 'private-file-uploader'),
        ]);
    }

    /**
     * POST /upload - Upload a single file (multipart field "file") to uploads/media/private-file-uploader/<username>/
     * Uses upload_dir filter (scoped) and wp_handle_sideload to move the file
     *
     * @param \WP_REST_Request $req Current request
     * @return \WP_REST_Response Upload result
     */
    public static function route_upload(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = wp_get_current_user();
        if (!$user || 0 === $user->ID) {
            Utils::log_error('Upload failed: user not authenticated');
            return new \WP_REST_Response(['ok' => false, 'error' => __('Not authenticated', 'private-file-uploader')], 401);
        }

        if (!self::check_rate_limit($user->ID)) {
            return new \WP_REST_Response([
                'ok' => false,
                'error' => __('Rate limit exceeded. Try again later.', 'private-file-uploader')
            ], 429);
        }
        // Get uploaded files from the request (WP maps them from $_FILES)
        $files = $req->get_file_params();

        // Expected field: "file" (as in curl -F 'file=@...')
        if (empty($files['file']) || !is_array($files['file'])) {
            // Fallback: first file if present
            if (is_array($files) && !empty($files)) {
                $first = reset($files);
                if (is_array($first)) {
                    $files['file'] = $first;
                }
            }
        }

        if (empty($files['file']) || !is_array($files['file'])) {
            Utils::log_warning('Upload rejected: no file provided');
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('No file provided (multipart field "file")', 'private-file-uploader')],
                400
            );
        }

        $original_filename = isset($files['file']['name']) && is_string($files['file']['name'])
            ? $files['file']['name']
            : '';
        $temporary_path = isset($files['file']['tmp_name']) && is_string($files['file']['tmp_name'])
            ? $files['file']['tmp_name']
            : '';
        $client_mime = isset($files['file']['type']) && is_string($files['file']['type'])
            ? sanitize_mime_type($files['file']['type'])
            : '';
        $upload_error = isset($files['file']['error']) ? (int) $files['file']['error'] : UPLOAD_ERR_NO_FILE;

        // Thumbnail and metadata names are plugin-owned artifacts. Accepting
        // one as an original upload would hide user content and could let a
        // later thumbnail generation overwrite it.
        $sanitized_upload_name = sanitize_file_name($original_filename);
        if (
            $sanitized_upload_name === '' ||
            Utils::is_thumb_filename($sanitized_upload_name) ||
            Utils::is_metadata_file($sanitized_upload_name)
        ) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Reserved filename', 'private-file-uploader')],
                400
            );
        }

        // Validations: max size + MIME allowlist
        $size = isset($files['file']['size']) ? (int)$files['file']['size'] : 0;
        $max  = self::get_max_upload_bytes();

        if ($size <= 0) {
            Utils::log_warning('Upload rejected: empty file', [
                'filename' => $original_filename
            ]);
            return new \WP_REST_Response(['ok' => false, 'error' => __('Empty upload or unknown size', 'private-file-uploader')], 400);
        }

        if ($size > $max) {
            Utils::log_warning('Upload rejected: file too large', [
                'filename' => $original_filename,
                'size' => $size,
                'limit' => $max,
                'size_human' => Utils::human_bytes($size),
                'limit_human' => Utils::human_bytes($max)
            ]);

            return new \WP_REST_Response([
                'ok'    => false,
                'error' => __('File too large', 'private-file-uploader'),
                'limit' => $max,
                'limitHuman' => Utils::human_bytes($max),
                'got'   => $size,
                'gotHuman' => Utils::human_bytes($size),
            ], 413);
        }

        // MIME detection using Utils
        $allowed = self::get_allowed_mime_types();
        $mime = $temporary_path !== ''
            ? Utils::detect_mime_type($temporary_path, $original_filename)
            : null;

        // Fallback to client header if detection failed
        if ($mime === null && $client_mime !== '') {
            $mime = $client_mime;
        }

        if ($mime === null || !in_array($mime, $allowed, true)) {
            Utils::log_warning('Upload rejected: unsupported MIME type', [
                'filename' => $original_filename,
                'mime' => $mime,
                'allowed' => $allowed
            ]);

            return new \WP_REST_Response([
                'ok'        => false,
                'error'     => __('Unsupported media type', 'private-file-uploader'),
                'mime'      => $mime,
                'allowed'   => $allowed,
                'hint'      => __('Allowed MIME types can be configured via the privfileup_allowed_mime_types filter.', 'private-file-uploader'),
            ], 415);
        }

        $paths = self::get_user_base($user);
        if (is_wp_error($paths)) {
            return self::storage_error_response($paths);
        }
        $username = $paths['username'];

        Utils::log_info('Upload started', [
            'user' => $username,
            'filename' => $original_filename,
            'size' => $size,
            'size_human' => Utils::human_bytes($size),
            'mime' => $mime,
            'ip' => Utils::get_client_ip(),
            'user_agent' => Utils::get_user_agent()
        ]);

        // Temporarily override upload directory
        $filter = function ($dirs) use ($paths) {
            $dirs['subdir'] = '/' . self::SUB_BASE . '/' . $paths['username'];
            $dirs['path']   = $paths['path'];
            $dirs['url']    = $paths['url'];
            return $dirs;
        };

        add_filter('upload_dir', $filter, 10, 1);

        $file_array = [
            'name'     => $original_filename,
            'type'     => $client_mime,
            'tmp_name' => $temporary_path,
            'error'    => $upload_error,
            'size'     => $size,
        ];

        $overrides = ['test_form' => false];

        // Ensure upload functions are loaded
        if (!function_exists('\wp_handle_sideload')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        try {
            $moved = \wp_handle_sideload($file_array, $overrides);
        } finally {
            remove_filter('upload_dir', $filter, 10);
        }

        if (isset($moved['error'])) {
            Utils::log_error('Upload failed during file handling', [
                'user' => $username,
                'filename' => $original_filename,
                'error' => $moved['error']
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => $moved['error']], 400);
        }

        $final_filename = wp_basename($moved['file']);

        // Do not write a predictable public sidecar containing request or user
        // data. Older sidecars remain supported by rename/delete cleanup.

        Utils::log_info('Upload completed successfully', [
            'user' => $username,
            'original_filename' => $original_filename,
            'final_filename' => $final_filename,
            'size' => $size,
            'mime' => $mime,
            'path' => $moved['file']
        ]);

        // If image: generate "medium" thumbnail
        $thumb = null;
        if (strpos((string)$moved['type'], 'image/') === 0) {
            $thumb = self::make_thumbnail($moved['file'], $moved['url']);
        }

        return new \WP_REST_Response([
            'ok'       => true,
            'file'     => $final_filename,
            'path'     => $moved['file'],
            'url'      => $moved['url'],
            'mime'     => $moved['type'],
            'owner'    => $username,
            'location' => self::SUB_BASE . '/' . $username,
            'thumb_url'    => $thumb['url']    ?? null,
            'thumb_width'  => $thumb['width']  ?? null,
            'thumb_height' => $thumb['height'] ?? null,
        ], 201);
    }

    /**
     * GET /files - List files for the current user
     *
     * @param \WP_REST_Request $req Current request
     * @return \WP_REST_Response List of files with pagination
     */
    public static function route_list_files(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = \wp_get_current_user();
        if (!$user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => __('Not authenticated', 'private-file-uploader')], 401);
        }

        $base = self::get_user_base($user);
        if (is_wp_error($base)) {
            return self::storage_error_response($base);
        }
        $dir  = $base['path'];
        $url  = $base['url'];

        // Parse parameters
        $page     = max(1, (int)($req->get_param('page') ?: 1));
        $per_page = (int)($req->get_param('per_page') ?: 1000);
        if ($per_page < 1) {
            $per_page = 1;
        }
        if ($per_page > 1000) {
            $per_page = 1000;
        }
        $order = strtolower((string)($req->get_param('order') ?: 'desc'));
        if ($order !== 'asc' && $order !== 'desc') {
            $order = 'desc';
        }

        Utils::log_debug('File list requested', [
            'user' => $base['username'],
            'page' => $page,
            'per_page' => $per_page,
            'order' => $order
        ]);

        if (!is_dir($dir)) {
            Utils::log_debug('User directory does not exist yet', [
                'user' => $base['username'],
                'dir' => $dir
            ]);

            return new \WP_REST_Response([
                'ok'          => true,
                'items'       => [],
                'owner'       => $base['username'],
                'count'       => 0,
                'page'        => $page,
                'per_page'    => $per_page,
                'total'       => 0,
                'total_pages' => 0,
                'order'       => $order,
            ]);
        }

        $items = [];
        $dh = @opendir($dir);
        if ($dh) {
            while (false !== ($entry = readdir($dh))) {
                if ($entry === '.' || $entry === '..' || $entry === 'index.html' || strpos($entry, "\0") !== false) {
                    continue;
                }

                // Skip metadata files using Utils helper
                if (Utils::is_metadata_file($entry)) {
                    continue;
                }
                if (Utils::is_system_file($entry)) {
                    continue;
                }

                // Skip auto-generated thumbnails
                if (Utils::is_thumb_filename($entry)) {
                    continue;
                }

                $abs = $dir . DIRECTORY_SEPARATOR . $entry;
                if (\is_link($abs) || !is_file($abs)) {
                    continue;
                }

                $size  = @filesize($abs);
                $mtime = @filemtime($abs);
                $ft    = \wp_check_filetype($entry);
                $mime  = $ft && isset($ft['type']) ? $ft['type'] : null;

                $thumb_url = null;
                $thumb_w = null;
                $thumb_h = null;

                if ($mime && strpos($mime, 'image/') === 0) {
                    $thumbAbs = Utils::append_suffix($abs, '-privfileup-thumb');
                    if (file_exists($thumbAbs) && is_file($thumbAbs)) {
                        // Build the URL by replacing the basename
                        $origUrl = $url . '/' . rawurlencode($entry);
                        $thumb_url = Utils::path_replace_basename($origUrl, basename($thumbAbs));
                        // Dimensions (best-effort)
                        $dim = @getimagesize($thumbAbs);
                        if (is_array($dim) && isset($dim[0], $dim[1])) {
                            $thumb_w = (int) $dim[0];
                            $thumb_h = (int) $dim[1];
                        }
                    }
                }

                $items[] = [
                    'name'     => $entry,
                    'url'      => $url . '/' . rawurlencode($entry),
                    'size'     => is_int($size) ? $size : null,
                    'mime'     => $mime,
                    'modified' => is_int($mtime) ? $mtime : null,
                    'thumb_url'    => $thumb_url,
                    'thumb_width'  => $thumb_w,
                    'thumb_height' => $thumb_h,
                ];
            }
            closedir($dh);
        }

        // Sort by mtime asc/desc; null goes last
        usort($items, function ($a, $b) use ($order) {
            $am = $a['modified'] ?? 0;
            $bm = $b['modified'] ?? 0;
            if ($am === $bm) return 0;
            return ($order === 'asc')
                ? (($am < $bm) ? -1 : 1)
                : (($am > $bm) ? -1 : 1);
        });

        $total = count($items);
        $total_pages = (int) ceil($total / $per_page);
        if ($page > $total_pages && $total_pages > 0) {
            $page = $total_pages;
        }
        $offset = ($page - 1) * $per_page;
        $paged_items = array_slice($items, $offset, $per_page);

        Utils::log_info('File list retrieved', [
            'user' => $base['username'],
            'total_files' => $total,
            'page' => $page,
            'returned' => count($paged_items)
        ]);

        $resp = new \WP_REST_Response([
            'ok'          => true,
            'items'       => $paged_items,
            'owner'       => $base['username'],
            'count'       => $total,
            'page'        => $page,
            'per_page'    => $per_page,
            'total'       => $total,
            'total_pages' => $total_pages,
            'order'       => $order,
        ]);

        // Optional: pagination-like headers
        $resp->header('X-Total-Count', (string)$total);
        $resp->header('X-Total-Pages', (string)$total_pages);

        return $resp;
    }

    /**
     * DELETE /files/{filename} - Delete a file in the user's folder
     *
     * @param \WP_REST_Request $req Current request
     * @return \WP_REST_Response Deletion result
     */
    public static function route_delete_file(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = \wp_get_current_user();
        if (!$user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => __('Not authenticated', 'private-file-uploader')], 401);
        }

        $param = $req->get_param('filename');
        $base  = self::sanitize_user_filename($param);

        if (is_wp_error($base)) {
            Utils::log_warning('Delete rejected: invalid filename', [
                'user' => $user->user_login,
                'filename' => $param,
                'error' => $base->get_error_message()
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => $base->get_error_message()], 400);
        }

        $paths = self::get_user_base($user);
        if (is_wp_error($paths)) {
            return self::storage_error_response($paths);
        }
        $abs   = $paths['path'] . DIRECTORY_SEPARATOR . $base;

        if (!Utils::is_path_within_base($paths['path'], $abs)) {
            Utils::log_error('Delete rejected: path traversal attempt', [
                'user' => $paths['username'],
                'filename' => $param,
                'attempted_path' => $abs
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => __('Invalid file path', 'private-file-uploader')], 400);
        }

        // Verify it's a file inside the user's folder
        if (!file_exists($abs) || !is_file($abs)) {
            Utils::log_warning('Delete failed: file not found', [
                'user' => $paths['username'],
                'filename' => $base
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => __('File not found', 'private-file-uploader')], 404);
        }

        if (\is_link($abs)) {
            Utils::log_error('Delete rejected: symbolic link', [
                'user' => $paths['username'],
                'filename' => $base
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => __('Symbolic links not allowed', 'private-file-uploader')], 400);
        }

        // Get file size before deletion for logging
        $file_size = @filesize($abs);

        // Delete a legacy metadata sidecar if it exists.
        $meta_file = $abs . '.meta.json';
        if (Utils::is_legacy_metadata_sidecar($meta_file)) {
            $meta_deleted = Utils::delete_legacy_metadata_sidecar($meta_file);
            Utils::log_debug('Metadata file deletion', [
                'user' => $paths['username'],
                'meta_file' => basename($meta_file),
                'success' => $meta_deleted
            ]);

            if (!$meta_deleted) {
                return new \WP_REST_Response(['ok' => false, 'error' => __('Unable to delete file', 'private-file-uploader')], 500);
            }
        }

        // Delete the associated thumbnail before the main file so a failed
        // auxiliary cleanup never reports a partial success.
        $thumb_abs = Utils::append_suffix($abs, '-privfileup-thumb');
        if (file_exists($thumb_abs)) {
            if (!is_file($thumb_abs) || is_link($thumb_abs)) {
                return new \WP_REST_Response(['ok' => false, 'error' => __('Unable to delete file', 'private-file-uploader')], 500);
            }

            wp_delete_file($thumb_abs);
            clearstatcache(true, $thumb_abs);
            if (file_exists($thumb_abs)) {
                return new \WP_REST_Response(['ok' => false, 'error' => __('Unable to delete file', 'private-file-uploader')], 500);
            }
        }

        // Delete the file
        wp_delete_file($abs);
        clearstatcache(true, $abs);
        $ok = !file_exists($abs);

        if (!$ok) {
            Utils::log_error('Delete failed: unable to remove file', [
                'user' => $paths['username'],
                'filename' => $base,
                'path' => $abs
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => __('Unable to delete file', 'private-file-uploader')], 500);
        }

        Utils::log_info('File deleted successfully', [
            'user' => $paths['username'],
            'filename' => $base
        ]);

        return new \WP_REST_Response([
            'ok'      => true,
            'deleted' => $base,
            'owner'   => $paths['username'],
        ]);
    }

    /**
     * HEAD /files/{filename} - Return metadata via headers, no body
     *
     * @param \WP_REST_Request $req Current request
     * @return \WP_REST_Response Response with metadata in headers
     */
    public static function route_head_file(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = \wp_get_current_user();
        if (!$user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => __('Not authenticated', 'private-file-uploader')], 401);
        }

        $param = $req->get_param('filename');
        $base  = self::sanitize_user_filename($param);

        if (\is_wp_error($base)) {
            return new \WP_REST_Response(['ok' => false, 'error' => $base->get_error_message()], 400);
        }

        $paths = self::get_user_base($user);
        if (is_wp_error($paths)) {
            return self::storage_error_response($paths);
        }
        $abs   = $paths['path'] . DIRECTORY_SEPARATOR . $base;

        if (!Utils::is_path_within_base($paths['path'], $abs)) {
            return new \WP_REST_Response(['ok' => false, 'error' => __('Invalid file path', 'private-file-uploader')], 400);
        }

        if (!\file_exists($abs) || !\is_file($abs)) {
            return new \WP_REST_Response(['ok' => false, 'error' => __('File not found', 'private-file-uploader')], 404);
        }

        // Get metadata
        $size  = @\filesize($abs);
        $mtime = @\filemtime($abs);
        $ft    = \wp_check_filetype($base);
        $mime  = ($ft && isset($ft['type'])) ? $ft['type'] : 'application/octet-stream';

        // Simple ETag based on user path + size + mtime
        $etag = '"' . \md5($paths['username'] . '/' . $base . ':' . (int)$size . ':' . (int)$mtime) . '"';

        Utils::log_debug('File metadata requested', [
            'user' => $paths['username'],
            'filename' => $base,
            'size' => $size,
            'mime' => $mime
        ]);

        // Response without body: metadata in headers
        $resp = new \WP_REST_Response(null, 200);
        $resp->header('Content-Length', '0');
        $resp->header('Cache-Control', 'private, max-age=60');
        if (\is_int($mtime)) {
            $resp->header('Last-Modified', \gmdate('D, d M Y H:i:s', $mtime) . ' GMT');
        }
        $resp->header('ETag', $etag);

        // Custom convenience headers for the client
        if (\is_int($size)) {
            $resp->header('X-Private-File-Uploader-Size', (string)$size);
        }
        $resp->header('X-Private-File-Uploader-Mime', $mime);
        $resp->header('X-Private-File-Uploader-Name', $base);
        $resp->header('X-Private-File-Uploader-Owner', $paths['username']);

        return $resp;
    }

    /**
     * POST /files/{filename}/rename
     * Body: new_name
     */
    public static function route_rename_file(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = \wp_get_current_user();
        if (!$user || 0 === $user->ID) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Not authenticated', 'private-file-uploader')],
                401
            );
        }

        $param   = $req->get_param('filename');
        $sanBase = self::sanitize_user_filename($param);
        if (\is_wp_error($sanBase)) {
            return new \WP_REST_Response(['ok' => false, 'error' => $sanBase->get_error_message()], 400);
        }

        $newParam = $req->get_param('new_name');
        $sanNew   = self::sanitize_user_filename($newParam);
        if (\is_wp_error($sanNew)) {
            return new \WP_REST_Response(['ok' => false, 'error' => $sanNew->get_error_message()], 400);
        }

        // Block direct rename of generated thumbnails.
        if (Utils::is_thumb_filename($sanBase)) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Cannot rename generated thumbnails directly', 'private-file-uploader')],
                400
            );
        }
        if (Utils::is_metadata_file($sanBase)) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Cannot rename metadata files directly', 'private-file-uploader')],
                400
            );
        }

        if ($sanBase === $sanNew) {
            return new \WP_REST_Response(['ok' => true, 'unchanged' => true], 200);
        }

        // Disallow renaming to a thumbnail name or metadata file name.
        if (Utils::is_thumb_filename($sanNew)) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Target name cannot be a generated thumbnail', 'private-file-uploader')],
                400
            );
        }

        $ends_with_meta = function_exists('str_ends_with')
            ? str_ends_with($sanNew, '.meta.json')
            : (substr($sanNew, -10) === '.meta.json');

        if ($ends_with_meta) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Target name cannot end with .meta.json', 'private-file-uploader')],
                400
            );
        }

        $paths = self::get_user_base($user);
        if (is_wp_error($paths)) {
            return self::storage_error_response($paths);
        }
        $dir   = $paths['path'];
        $url   = $paths['url'];

        // Ensure base dir exists.
        wp_mkdir_p($dir);

        $srcAbs = $dir . DIRECTORY_SEPARATOR . $sanBase;
        $dstAbs = $dir . DIRECTORY_SEPARATOR . $sanNew;

        // Normalize for robust comparisons.
        $normBase = untrailingslashit(wp_normalize_path($dir));
        $normSrc  = wp_normalize_path($srcAbs);
        $normDst  = wp_normalize_path($dstAbs);

        // Source must be within base and exist as a file.
        if (strpos($normSrc, $normBase . '/') !== 0 || !file_exists($srcAbs) || !is_file($srcAbs) || is_link($srcAbs)) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Invalid file path', 'private-file-uploader')],
                400
            );
        }

        // Destination must be within base.
        if (strpos($normDst, $normBase . '/') !== 0) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Invalid file path', 'private-file-uploader')],
                400
            );
        }

        // Destination directory must be exactly the user's base directory.
        $dstDir = wp_normalize_path(dirname($dstAbs));
        if ($dstDir !== $normBase) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Invalid file path', 'private-file-uploader')],
                400
            );
        }

        $rename_validation = self::validate_rename_target($srcAbs, $sanBase, $sanNew);
        if (is_wp_error($rename_validation)) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => $rename_validation->get_error_message()],
                400
            );
        }

        $oldMeta    = $srcAbs . '.meta.json';
        $newMeta    = $dstAbs . '.meta.json';
        $oldThumbAbs = Utils::append_suffix($srcAbs, '-privfileup-thumb');
        $newThumbAbs = Utils::append_suffix($dstAbs, '-privfileup-thumb');

        // Collision check, including auxiliary artifacts.
        if (file_exists($dstAbs) || file_exists($newMeta) || file_exists($newThumbAbs)) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Target filename already exists', 'private-file-uploader')],
                409
            );
        }

        // MIME/size for response/log (best-effort).
        $size  = filesize($srcAbs);
        $size  = (false === $size) ? null : (int) $size;

        $mtime = filemtime($srcAbs);
        $mtime = (false === $mtime) ? null : (int) $mtime;

        $ft   = wp_check_filetype($sanBase);
        $mime = (!empty($ft['type'])) ? $ft['type'] : 'application/octet-stream';

        // Init WP_Filesystem for move().
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        if (!WP_Filesystem()) {
            Utils::log_error('Rename failed: WP_Filesystem init failed', [
                'user' => $paths['username'],
            ]);

            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Filesystem not available', 'private-file-uploader')],
                500
            );
        }

        global $wp_filesystem;
        if (!isset($wp_filesystem) || !is_object($wp_filesystem)) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Filesystem not available', 'private-file-uploader')],
                500
            );
        }

        // Remove the no-longer-used legacy request metadata before renaming.
        if (!Utils::delete_legacy_metadata_sidecar($oldMeta)) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Unable to rename file', 'private-file-uploader')],
                500
            );
        }

        // Move the thumbnail first so it can be rolled back if the main move
        // fails. Never overwrite an orphaned destination artifact.
        $thumbRenamed = false;
        if (file_exists($oldThumbAbs)) {
            if (!is_file($oldThumbAbs) || is_link($oldThumbAbs)) {
                return new \WP_REST_Response(
                    ['ok' => false, 'error' => __('Unable to rename file', 'private-file-uploader')],
                    500
                );
            }

            $thumbRenamed = (bool) $wp_filesystem->move($oldThumbAbs, $newThumbAbs, false);
            if (!$thumbRenamed) {
                return new \WP_REST_Response(
                    ['ok' => false, 'error' => __('Unable to rename file', 'private-file-uploader')],
                    500
                );
            }
        }

        // Move original (do not overwrite).
        $moved = (bool) $wp_filesystem->move($srcAbs, $dstAbs, false);
        if (!$moved) {
            if ($thumbRenamed) {
                $wp_filesystem->move($newThumbAbs, $oldThumbAbs, false);
            }
            Utils::log_error('Rename failed: unable to move file', [
                'user' => $paths['username'],
                'src'  => $srcAbs,
                'dst'  => $dstAbs,
            ]);

            return new \WP_REST_Response(
                ['ok' => false, 'error' => __('Unable to rename file', 'private-file-uploader')],
                500
            );
        }

        // New URLs.
        $newUrl      = $url . '/' . rawurlencode($sanNew);
        $newThumbUrl = null;

        if ($thumbRenamed || (file_exists($newThumbAbs) && is_file($newThumbAbs))) {
            $newThumbUrl = Utils::path_replace_basename($newUrl, basename($newThumbAbs));
        }

        Utils::log_info('Rename completed', [
            'user'     => $paths['username'],
            'old_name' => $sanBase,
            'new_name' => $sanNew,
            'thumb'    => $newThumbUrl ? 'renamed' : 'none',
        ]);

        return new \WP_REST_Response([
            'ok'        => true,
            'old_name'  => $sanBase,
            'new_name'  => $sanNew,
            'url'       => $newUrl,
            'size'      => $size,
            'mime'      => $mime,
            'modified'  => $mtime,
            'thumb_url' => $newThumbUrl,
        ], 200);
    }


    /**
     * Create an empty index.html file in the directory to prevent directory listing (if enabled on server)
     *
     * @param string $dir Directory path
     */
    private static function ensure_index_html(string $dir): void
    {
        $index = trailingslashit($dir) . 'index.html';
        if (file_exists($index)) {
            return;
        }

        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        if (!WP_Filesystem()) {
            Utils::log_warning('Failed to init WP_Filesystem for index.html', ['dir' => $dir]);
            return;
        }

        global $wp_filesystem;
        if (!isset($wp_filesystem) || !is_object($wp_filesystem)) {
            Utils::log_warning('WP_Filesystem not available for index.html', ['dir' => $dir]);
            return;
        }

        $written = (bool) $wp_filesystem->put_contents($index, "<!-- silence is golden -->", FS_CHMOD_FILE);
        if (!$written) {
            Utils::log_warning('Failed to create index.html', ['dir' => $dir]);
        }
    }

    /**
     * Resolve storage beneath the fixed plugin root, preserving existing URLs.
     *
     * @param \WP_User $user User object
     * @param bool $create Whether to create missing directories.
     * @return array|\WP_Error Path, URL and username, or a storage error.
     */
    public static function get_user_base(\WP_User $user, bool $create = true)
    {
        $username = (string) $user->user_login;
        // sanitize_user() is not a filesystem boundary check. Reject aliases
        // instead of mapping two logins (or dot segments) to the same folder.
        if (
            $user->ID <= 0 ||
            $username === '' ||
            $username === '.' ||
            $username === '..' ||
            preg_match('/\A[A-Za-z0-9 _@.\-]+\z/', $username) !== 1 ||
            trim($username) !== $username ||
            rtrim($username, '.') !== $username
        ) {
            return new \WP_Error('privfileup_unsafe_username', __('This user login cannot be used as a storage directory.', 'private-file-uploader'));
        }

        $uploads = \wp_get_upload_dir();
        if (empty($uploads['basedir']) || empty($uploads['baseurl']) || !empty($uploads['error'])) {
            return new \WP_Error('privfileup_storage_unavailable', __('The uploads directory is not available.', 'private-file-uploader'));
        }

        $path = untrailingslashit($uploads['basedir']);
        if ($create && !wp_mkdir_p($path)) {
            return new \WP_Error('privfileup_storage_unavailable', __('The uploads directory could not be created.', 'private-file-uploader'));
        }

        // Check every component before following or creating it. The uploads
        // base itself may be a legitimate server-configured symlink, but no
        // child owned by this plugin may point outside it or into another user.
        foreach (array_merge(explode('/', self::SUB_BASE), [$username]) as $segment) {
            $parent = $path;
            $path   = trailingslashit($parent) . $segment;
            if (
                is_link($path) ||
                (file_exists($path) && (!is_dir($path) || !Utils::is_path_within_base($parent, $path)))
            ) {
                return new \WP_Error('privfileup_unsafe_storage', __('The storage directory is not a safe regular directory.', 'private-file-uploader'));
            }
            if ($create && !is_dir($path) && !wp_mkdir_p($path)) {
                return new \WP_Error('privfileup_storage_unavailable', __('The storage directory could not be created.', 'private-file-uploader'));
            }
        }

        if ($create) {
            self::ensure_index_html($path);
        }

        $url = trailingslashit($uploads['baseurl']) . self::SUB_BASE . '/' . rawurlencode($username);
        return ['path' => $path, 'url' => $url, 'username' => $username];
    }

    /** Convert storage failures into a consistent REST response. */
    private static function storage_error_response(\WP_Error $error): \WP_REST_Response
    {
        $status = $error->get_error_code() === 'privfileup_unsafe_username' ? 403 : 500;
        return new \WP_REST_Response(['ok' => false, 'error' => $error->get_error_message()], $status);
    }

    /**
     * Strong filename validation (no path traversal, no slashes)
     *
     * @param mixed $filename Input filename
     * @return string|\WP_Error Sanitized basename or WP_Error
     */
    public static function sanitize_user_filename($filename)
    {
        if (!is_string($filename) || $filename === '') {
            return new \WP_Error('privfileup_bad_filename', __('Invalid filename', 'private-file-uploader'));
        }

        // Use Utils sanitization
        $base = Utils::sanitize_filename($filename);

        // Additional validation
        if ($base === '' || $base === '.' || $base === '..' || strpos($base, "\0") !== false) {
            return new \WP_Error('privfileup_bad_filename', __('Invalid filename', 'private-file-uploader'));
        }

        if (strlen($base) > 255) {
            return new \WP_Error('privfileup_bad_filename', __('Filename too long', 'private-file-uploader'));
        }

        return $base;
    }

    /**
     * Validate that a rename cannot bypass the upload MIME allowlist.
     *
     * @param string $source_path     Absolute path to the existing file.
     * @param string $source_filename Existing base filename.
     * @param string $target_filename Requested base filename.
     * @return true|\WP_Error True when the target name is safe.
     */
    public static function validate_rename_target(string $source_path, string $source_filename, string $target_filename)
    {
        if (is_link($source_path) || !is_file($source_path)) {
            return new \WP_Error('privfileup_unsafe_rename', __('Invalid source file', 'private-file-uploader'));
        }

        if (
            $target_filename === '' ||
            $target_filename[0] === '.' ||
            Utils::is_metadata_file($target_filename) ||
            Utils::is_thumb_filename($target_filename) ||
            Utils::is_system_file($target_filename)
        ) {
            return new \WP_Error('privfileup_unsafe_rename', __('Target filename is reserved', 'private-file-uploader'));
        }

        // Reject executable/configuration extensions even when another plugin
        // broadens WordPress' MIME map. This also catches double extensions.
        if (preg_match('/(?:^|\.)(?:php[0-9]*|pht|phtml|phps|phar|shtml|fcgi|cgi|pl|py|sh|bash|asp|aspx|asa|jsp|jspx|war|htaccess|user\.ini|web\.config)(?:\.|$)/i', $target_filename)) {
            return new \WP_Error('privfileup_unsafe_rename', __('Target file type is not allowed', 'private-file-uploader'));
        }

        // Apply only Core's multi-extension hardening, without otherwise
        // normalizing names that the published mobile API already accepts.
        $name_parts = explode('.', $target_filename);
        if (count($name_parts) > 2) {
            array_shift($name_parts);
            array_pop($name_parts);
            $core_mime_map = \get_allowed_mime_types();

            foreach ($name_parts as $part) {
                if (!preg_match('/^[a-zA-Z]{2,5}\d?$/', $part)) {
                    continue;
                }

                $intermediate_allowed = false;
                foreach ($core_mime_map as $extension_pattern => $unused_mime) {
                    if (preg_match('!^(' . $extension_pattern . ')$!i', $part)) {
                        $intermediate_allowed = true;
                        break;
                    }
                }

                if (!$intermediate_allowed) {
                    return new \WP_Error('privfileup_unsafe_rename', __('Target file type is not allowed', 'private-file-uploader'));
                }
            }
        }

        $allowed_mimes = self::get_allowed_mime_types();
        $target_type   = wp_check_filetype($target_filename);
        $target_ext    = isset($target_type['ext']) ? (string) $target_type['ext'] : '';
        $target_mime   = isset($target_type['type']) ? (string) $target_type['type'] : '';

        // Preserve the published ability to use an extensionless name. Such a
        // name cannot be mapped to an executable extension, so validate the
        // existing content against the plugin allowlist instead.
        if ($target_ext === '' && pathinfo($target_filename, PATHINFO_EXTENSION) === '') {
            $detected_mime = Utils::detect_mime_type($source_path, $source_filename);
            if ($detected_mime !== null && in_array($detected_mime, $allowed_mimes, true)) {
                return true;
            }

            return new \WP_Error('privfileup_unsafe_rename', __('Target file type is not allowed', 'private-file-uploader'));
        }

        if ($target_mime === '' || !in_array($target_mime, $allowed_mimes, true)) {
            return new \WP_Error('privfileup_unsafe_rename', __('Target file type is not allowed', 'private-file-uploader'));
        }

        // Core verifies the real content, extension, global MIME policy, and
        // image type. A suggested proper filename means the requested
        // extension does not match the file content.
        $checked = wp_check_filetype_and_ext($source_path, $target_filename);
        if (
            empty($checked['ext']) ||
            empty($checked['type']) ||
            $checked['type'] !== $target_mime ||
            !empty($checked['proper_filename'])
        ) {
            return new \WP_Error('privfileup_unsafe_rename', __('Target extension does not match the file content', 'private-file-uploader'));
        }

        return true;
    }

    private static function check_rate_limit(int $user_id): bool
    {
        $transient_key = "privfileup_v1_rate_" . $user_id;
        $attempts = get_transient($transient_key) ?: 0;

        if ($attempts >= 50) { // 50 uploads per hour
            return false;
        }

        set_transient($transient_key, $attempts + 1, HOUR_IN_SECONDS);
        return true;
    }

    /** Reads the "medium" image size dimensions from WordPress (no crop). Minimum 300x300. */
    private static function wp_thumb_dims(): array
    {
        $w = (int) get_option('medium_size_w', 300);
        $h = (int) get_option('medium_size_h', 300);
        if ($w <= 0) $w = 300;
        if ($h <= 0) $h = 300;
        $crop = false; // medium size does not crop
        return [$w, $h, $crop];
    }

    /**
     * Create a "medium" preview next to the original using WP_Image_Editor.
     * Returns [url, path, width, height] or null if not created.
     */
    private static function make_thumbnail(string $origPath, string $origUrl): ?array
    {
        if (!file_exists($origPath) || !is_file($origPath) || is_link($origPath)) return null;

        $ft   = \wp_check_filetype(basename($origPath));
        $mime = $ft['type'] ?? 'application/octet-stream';
        // Limit to formats commonly handled by the core editor
        if (!preg_match('#^image/(jpeg|png|gif|webp)$#i', $mime)) return null;

        $destPath = Utils::append_suffix($origPath, '-privfileup-thumb');
        if (
            wp_normalize_path(dirname($destPath)) !== wp_normalize_path(dirname($origPath)) ||
            file_exists($destPath) ||
            is_link($destPath)
        ) {
            return null;
        }

        if (!function_exists('wp_get_image_editor')) {
            require_once ABSPATH . 'wp-admin/includes/image.php';
        }

        $editor = \wp_get_image_editor($origPath);
        if (\is_wp_error($editor)) return null;

        list($tw, $th, $crop) = self::wp_thumb_dims();

        // If the image is smaller than the requested preview, save a copy as-is
        $size = $editor->get_size();
        if (is_array($size) && isset($size['width'], $size['height'])) {
            if ($size['width'] <= $tw && $size['height'] <= $th) {
                $saved = $editor->save($destPath);
                if (\is_wp_error($saved) || empty($saved['path'])) return null;

                $url = Utils::path_replace_basename($origUrl, basename($saved['path']));
                return [
                    'url'    => $url,
                    'path'   => $saved['path'],
                    'width'  => (int) ($saved['width'] ?? $size['width']),
                    'height' => (int) ($saved['height'] ?? $size['height']),
                ];
            }
        }

        // Proportional resize (no crop for "medium")
        $res = $editor->resize($tw, $th, $crop);
        if (\is_wp_error($res)) return null;

        // Quality: allow override (default 82).
        $quality = (int) apply_filters('privfileup_thumb_quality', 82);
        if (method_exists($editor, 'set_quality')) {
            $editor->set_quality($quality);
        }

        $saved = $editor->save($destPath);
        if (\is_wp_error($saved) || empty($saved['path'])) return null;

        $thumbPath = (string) $saved['path'];
        $thumbUrl  = Utils::path_replace_basename($origUrl, basename($thumbPath));

        return [
            'url'    => $thumbUrl,
            'path'   => $thumbPath,
            'width'  => (int) ($saved['width'] ?? 0),
            'height' => (int) ($saved['height'] ?? 0),
        ];
    }
}
