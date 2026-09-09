<?php

namespace PRIVFILEUP;

if (!defined('ABSPATH')) {
    exit;
}

class Utils
{
    /**
     * Emit an opt-in debug action when WordPress debugging is enabled.
     *
     * @param string $message Message to log
     * @param string $level Log level: info, warning, error, debug
     * @param array $context Additional context data
     */
    public static function log(string $message, string $level = 'info', array $context = []): void
    {
        if (!defined('WP_DEBUG') || !WP_DEBUG || !defined('WP_DEBUG_LOG') || !WP_DEBUG_LOG) {
            return;
        }

        /**
         * Fires when the plugin emits opt-in diagnostic information.
         *
         * Nothing is persisted by default. Site owners may attach a listener
         * while debugging and are responsible for its retention policy.
         *
         * @param string $message Diagnostic message.
         * @param string $level   Diagnostic level.
         * @param array  $context Additional context.
         */
        do_action('privfileup_debug_log', $message, strtolower($level), $context);
    }

    /**
     * Log info message
     *
     * @param string $message Message to log
     * @param array $context Additional context
     */
    public static function log_info(string $message, array $context = []): void
    {
        self::log($message, 'info', $context);
    }

    /**
     * Log warning message
     *
     * @param string $message Message to log
     * @param array $context Additional context
     */
    public static function log_warning(string $message, array $context = []): void
    {
        self::log($message, 'warning', $context);
    }

    /**
     * Log error message
     *
     * @param string $message Message to log
     * @param array $context Additional context
     */
    public static function log_error(string $message, array $context = []): void
    {
        self::log($message, 'error', $context);
    }

    /**
     * Log debug message
     *
     * @param string $message Message to log
     * @param array $context Additional context
     */
    public static function log_debug(string $message, array $context = []): void
    {
        self::log($message, 'debug', $context);
    }

    /**
     * Convert bytes to human-readable format
     *
     * @param int $bytes Number of bytes
     * @param int $precision Decimal precision
     * @return string Human-readable size
     */
    public static function human_bytes(int $bytes, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        $i = 0;
        $n = $bytes;

        while ($n >= 1024 && $i < count($units) - 1) {
            $n /= 1024;
            $i++;
        }

        if ($i === 0) {
            return "{$n} {$units[$i]}";
        }

        return number_format($n, $precision) . " {$units[$i]}";
    }

    /**
     * Convert shorthand INI notation (e.g. "128M", "2G") to bytes
     *
     * @param mixed $val INI value
     * @return int Bytes
     */
    public static function ini_to_bytes($val): int
    {
        if ($val === null || $val === '') {
            return 0;
        }

        $v = trim((string)$val);

        if ($v === '-1') {
            return PHP_INT_MAX; // unlimited
        }

        if (preg_match('/^\d+$/', $v)) {
            return (int)$v;
        }

        if (!preg_match('/^\s*([0-9\.]+)\s*([KMGkmg])\s*$/i', $v, $m)) {
            return (int)$v;
        }

        $n = (float)$m[1];
        $u = strtoupper($m[2]);

        switch ($u) {
            case 'G':
                $n *= 1024;
                // no break
            case 'M':
                $n *= 1024;
                // no break
            case 'K':
                $n *= 1024;
        }

        return (int)round($n);
    }

    /**
     * Get INI value as [human_readable, bytes, raw_value] tuple
     *
     * @param string $key INI key
     * @return array [human_readable, bytes, raw_value]
     */
    public static function get_ini_pair(string $key): array
    {
        $raw = @ini_get($key);
        $bytes = self::ini_to_bytes($raw);

        if ($raw === false || $raw === '') {
            $human = __('N/A', 'private-file-uploader');
        } elseif ($raw === '-1') {
            $human = __('Unlimited', 'private-file-uploader');
        } else {
            $human = self::human_bytes($bytes);
        }

        return [$human, $bytes, (string)$raw];
    }

    /**
     * Validate a basename without changing which file it identifies.
     *
     * @param string $filename Original filename
     * @return string Exact filename, or an empty string when unsafe.
     */
    public static function sanitize_filename(string $filename): string
    {
        // Reject separators, control characters, Windows stream syntax, and
        // names that Windows would resolve to a different basename. Never
        // transliterate or truncate a lookup: that could target another file.
        if (
            $filename === '' ||
            $filename === '.' ||
            $filename === '..' ||
            strlen($filename) > 255 ||
            preg_match('/[<>:"\/\\\\|?*\x00-\x1F\x7F]/', $filename) ||
            rtrim($filename, ". ") !== $filename ||
            wp_check_invalid_utf8($filename) !== $filename
        ) {
            return '';
        }

        return $filename;
    }

    /**
     * Get unique filename to avoid overwriting existing files
     *
     * @param string $dir Directory path
     * @param string $filename Desired filename
     * @return string Unique filename
     */
    public static function get_unique_filename(string $dir, string $filename): string
    {
        $path = trailingslashit($dir) . $filename;

        if (!file_exists($path)) {
            return $filename;
        }

        $info = pathinfo($filename);
        $name = $info['filename'];
        $ext = isset($info['extension']) ? '.' . $info['extension'] : '';
        $counter = 1;

        while (file_exists(trailingslashit($dir) . "{$name}_{$counter}{$ext}")) {
            $counter++;
            if ($counter > 9999) {
                // Safety limit reached, use unique ID
                return $name . '_' . uniqid() . $ext;
            }
        }

        return "{$name}_{$counter}{$ext}";
    }

    /**
     * Calculate total size of a directory
     *
     * @param string $dir Directory path
     * @return int Total size in bytes
     */
    public static function get_directory_size(string $dir): int
    {
        if (!is_dir($dir)) {
            return 0;
        }

        $total = 0;

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file) {
                if ($file->isFile() && !$file->isLink()) {
                    $total += $file->getSize();
                }
            }
        } catch (\Exception $e) {
            self::log_error('Error calculating directory size', [
                'dir' => $dir,
                'error' => $e->getMessage()
            ]);
        }

        return $total;
    }

    /**
     * Count files in a directory
     *
     * @param string $dir Directory path
     * @param bool $recursive Count recursively
     * @return int Number of files
     */
    public static function count_directory_files(string $dir, bool $recursive = false): int
    {
        if (!is_dir($dir)) {
            return 0;
        }

        $count = 0;

        try {
            if ($recursive) {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::LEAVES_ONLY
                );
            } else {
                $iterator = new \DirectoryIterator($dir);
            }

            foreach ($iterator as $file) {
                if ($file->isFile() && !$file->isLink()) {
                    $count++;
                }
            }
        } catch (\Exception $e) {
            self::log_error('Error counting directory files', [
                'dir' => $dir,
                'error' => $e->getMessage()
            ]);
        }

        return $count;
    }

    /**
     * Check if file extension is allowed
     *
     * @param string $filename Filename to check
     * @param array $allowed_extensions List of allowed extensions
     * @return bool True if allowed
     */
    public static function is_extension_allowed(string $filename, array $allowed_extensions): bool
    {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        return in_array($ext, array_map('strtolower', $allowed_extensions), true);
    }

    /**
     * Validate file MIME type using multiple methods
     *
     * @param string $filepath Path to file
     * @param string $filename Original filename
     * @return string|null Detected MIME type or null
     */
    public static function detect_mime_type(string $filepath, string $filename = ''): ?string
    {
        $mime = null;

        // Method 1: Using finfo (most reliable)
        if (function_exists('finfo_open') && is_readable($filepath)) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo) {
                $detected = finfo_file($finfo, $filepath);
                if ($detected !== false) {
                    $mime = $detected;
                }
                finfo_close($finfo);
            }
        }

        // Method 2: Using file extension as fallback
        if ($mime === null && !empty($filename)) {
            $filetype = wp_check_filetype($filename);
            if ($filetype && !empty($filetype['type'])) {
                $mime = $filetype['type'];
            }
        }

        // Method 3: Using mime_content_type (if available)
        if ($mime === null && function_exists('mime_content_type')) {
            $detected = @mime_content_type($filepath);
            if ($detected !== false) {
                $mime = $detected;
            }
        }

        return $mime;
    }

    /**
     * Check if a filename is a metadata file
     *
     * @param string $filename Filename to check
     * @return bool True if it's a metadata file
     */
    public static function is_metadata_file(string $filename): bool
    {
        $filename = strtolower($filename);
        return strlen($filename) > 10 && substr($filename, -10) === '.meta.json';
    }

    /**
     * Check whether a file matches the complete sidecar schema written by
     * plugin versions prior to 1.2.1.
     *
     * A suffix check alone is deliberately insufficient: users may upload a
     * legitimate JSON document whose name happens to end in `.meta.json`.
     *
     * @param string $filepath Absolute path to the possible sidecar.
     * @return bool True only for a recognized legacy sidecar.
     */
    public static function is_legacy_metadata_sidecar(string $filepath): bool
    {
        if (
            !self::is_metadata_file(basename($filepath)) ||
            !is_file($filepath) ||
            is_link($filepath)
        ) {
            return false;
        }

        $size = filesize($filepath);
        if ($size === false || $size > 65536) {
            return false;
        }

        $data = wp_json_file_decode($filepath, ['associative' => true]);
        if (!is_array($data)) {
            return false;
        }

        $required_keys = [
            'uploaded_at',
            'user_id',
            'plugin_version',
            'original_name',
            'mime',
            'size',
            'ip',
            'user_agent',
            'mobile',
        ];
        $actual_keys = array_keys($data);
        sort($required_keys);
        sort($actual_keys);

        if ($actual_keys !== $required_keys) {
            return false;
        }

        return is_string($data['uploaded_at']) &&
            preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $data['uploaded_at']) === 1 &&
            is_int($data['user_id']) &&
            $data['user_id'] >= 0 &&
            is_string($data['plugin_version']) &&
            $data['plugin_version'] !== '' &&
            is_string($data['original_name']) &&
            $data['original_name'] !== '' &&
            is_string($data['mime']) &&
            $data['mime'] !== '' &&
            is_int($data['size']) &&
            $data['size'] >= 0 &&
            is_string($data['ip']) &&
            filter_var($data['ip'], FILTER_VALIDATE_IP) !== false &&
            is_string($data['user_agent']) &&
            $data['user_agent'] !== '' &&
            is_bool($data['mobile']);
    }

    /**
     * Delete a recognized legacy metadata sidecar and verify the result.
     * Unrecognized files are intentionally left untouched.
     *
     * @param string $filepath Absolute path to the possible sidecar.
     * @return bool True when no recognized legacy sidecar remains.
     */
    public static function delete_legacy_metadata_sidecar(string $filepath): bool
    {
        if (!self::is_legacy_metadata_sidecar($filepath)) {
            return true;
        }

        wp_delete_file($filepath);
        clearstatcache(true, $filepath);
        return !file_exists($filepath);
    }

    public static function is_system_file(string $filename): bool
    {
        $system_files = ['.DS_Store', 'Thumbs.db', 'desktop.ini', '._.DS_Store'];
        return in_array($filename, $system_files, true);
    }

    /** Thumbnail helpers */

    /** True if the filename is a generated thumbnail (-privfileup-thumb before the extension). */
    public static function is_thumb_filename(string $filename): bool
    {
        $filename = strtolower($filename);

        // photo.jpg => photo-privfileup-thumb.jpg.
        $dot = strrpos($filename, '.');
        if ($dot === false) {
            return str_ends_with($filename, '-privfileup-thumb');
        }
        $name = substr($filename, 0, $dot);
        return str_ends_with($name, '-privfileup-thumb');
    }

    /** Adds a suffix before the extension (e.g. photo.jpg + '-privfileup-thumb'). */
    public static function append_suffix(string $path, string $suffix): string
    {
        $dot             = strrpos($path, '.');
        $forward_slash   = strrpos($path, '/');
        $backward_slash  = strrpos($path, '\\');
        $last_separator  = max(
            false === $forward_slash ? -1 : $forward_slash,
            false === $backward_slash ? -1 : $backward_slash
        );

        // A dot in a parent directory is not a filename extension.
        if ($dot === false || $dot <= $last_separator) {
            return $path . $suffix;
        }
        $name = substr($path, 0, $dot);
        $ext  = substr($path, $dot);
        return $name . $suffix . $ext;
    }

    /** Given the original URL, replaces the basename with a new filename (preserves query string) */
    public static function path_replace_basename(string $origUrl, string $newBase): string
    {
        $qpos = strpos($origUrl, '?');
        $urlNoQ = ($qpos === false) ? $origUrl : substr($origUrl, 0, $qpos);
        $query  = ($qpos === false) ? '' : substr($origUrl, $qpos);

        $slash = strrpos($urlNoQ, '/');
        if ($slash === false) {
            return $newBase . $query;
        }
        return substr($urlNoQ, 0, $slash + 1) . rawurlencode($newBase) . $query;
    }

    /** End thumbnail helpers */

    /**
     * Get metadata filename for a given file
     *
     * @param string $filepath Path to the file
     * @return string Metadata file path
     */
    public static function get_metadata_filepath(string $filepath): string
    {
        return $filepath . '.meta.json';
    }

    /**
     * Delete file and its metadata
     *
     * @param string $filepath Path to the file
     * @return bool True if file was deleted successfully
     */
    public static function delete_file_with_metadata(string $filepath): bool
    {
        $meta_file = self::get_metadata_filepath($filepath);
        if (!self::delete_legacy_metadata_sidecar($meta_file)) {
            return false;
        }

        $thumb_file = self::append_suffix($filepath, '-privfileup-thumb');
        if (file_exists($thumb_file) && is_file($thumb_file)) {
            wp_delete_file($thumb_file);
            clearstatcache(true, $thumb_file);
            if (file_exists($thumb_file)) {
                return false;
            }
        }

        if (file_exists($filepath) && is_file($filepath) && !is_link($filepath)) {
            wp_delete_file($filepath);
            clearstatcache(true, $filepath);
            return !file_exists($filepath);
        }

        return false;
    }

    /**
     * Recursively delete a directory
     *
     * @param string $dir Directory path
     * @return bool True on success
     */
    public static function recursive_rmdir(string $dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }

        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        if (!WP_Filesystem()) {
            return false;
        }

        global $wp_filesystem;
        if (!isset($wp_filesystem) || !is_object($wp_filesystem)) {
            return false;
        }

        // delete( $file, $recursive, $type )
        return (bool) $wp_filesystem->delete($dir, true, 'd');
    }


    /**
     * Get client IP address
     *
     * @return string IP address
     */
    public static function get_client_ip(): string
    {
        $candidates = [];

        if (isset($_SERVER['HTTP_CF_CONNECTING_IP']) && is_string($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $candidates[] = sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']));
        }
        if (isset($_SERVER['HTTP_X_REAL_IP']) && is_string($_SERVER['HTTP_X_REAL_IP'])) {
            $candidates[] = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_REAL_IP']));
        }
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && is_string($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $candidates[] = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']));
        }
        if (isset($_SERVER['HTTP_CLIENT_IP']) && is_string($_SERVER['HTTP_CLIENT_IP'])) {
            $candidates[] = sanitize_text_field(wp_unslash($_SERVER['HTTP_CLIENT_IP']));
        }
        if (isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])) {
            $candidates[] = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        foreach ($candidates as $candidate) {
            $ip = sanitize_text_field($candidate);

            // Handle comma-separated IPs (proxies).
            if (strpos($ip, ',') !== false) {
                $parts = explode(',', $ip);
                $ip = trim($parts[0]);
            }

            $ip = trim($ip);

            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        return '0.0.0.0';
    }

    /**
     * Get user agent string
     *
     * @return string User agent
     */
    public static function get_user_agent(): string
    {
        if (!empty($_SERVER['HTTP_USER_AGENT'])) {
            return sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT']));
        }
        return 'Unknown';
    }

    /**
     * Check if request is from mobile device
     *
     * @return bool True if mobile
     */
    public static function is_mobile_request(): bool
    {
        $user_agent = self::get_user_agent();

        $mobile_agents = [
            'Android',
            'iPhone',
            'iPad',
            'iPod',
            'BlackBerry',
            'Windows Phone',
            'Mobile',
            'Tablet'
        ];

        foreach ($mobile_agents as $agent) {
            if (stripos($user_agent, $agent) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate a secure random token
     *
     * @param int $length Token length
     * @return string Random token
     */
    public static function generate_token(int $length = 32): string
    {
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes($length / 2));
        }

        return wp_generate_password($length, false);
    }

    /**
     * Verify that a path is within a base directory (security check)
     *
     * @param string $base Base directory
     * @param string $candidate Candidate path
     * @return bool True if safe
     */
    public static function is_path_within_base(string $base, string $candidate): bool
    {
        $base_real = realpath($base);
        $cand_real = realpath($candidate);

        if ($base_real === false || $cand_real === false) {
            return false;
        }

        $base_real = rtrim($base_real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

        return strncmp($cand_real, $base_real, strlen($base_real)) === 0;
    }

    /**
     * Format timestamp as relative time (e.g., "2 hours ago")
     *
     * @param int $timestamp Unix timestamp
     * @return string Relative time string
     */
    public static function time_ago(int $timestamp): string
    {
        $diff = time() - $timestamp;

        if ($diff < 60) {
            /* translators: %s: number of seconds */
            return sprintf(_n('%s second ago', '%s seconds ago', $diff, 'private-file-uploader'), $diff);
        }

        $diff = round($diff / 60);
        if ($diff < 60) {
            /* translators: %s: number of minutes */
            return sprintf(_n('%s minute ago', '%s minutes ago', $diff, 'private-file-uploader'), $diff);
        }

        $diff = round($diff / 60);
        if ($diff < 24) {
            /* translators: %s: number of hours */
            return sprintf(_n('%s hour ago', '%s hours ago', $diff, 'private-file-uploader'), $diff);
        }

        $diff = round($diff / 24);
        if ($diff < 30) {
            /* translators: %s: number of days */
            return sprintf(_n('%s day ago', '%s days ago', $diff, 'private-file-uploader'), $diff);
        }

        $diff = round($diff / 30);
        if ($diff < 12) {
            /* translators: %s: number of months */
            return sprintf(_n('%s month ago', '%s months ago', $diff, 'private-file-uploader'), $diff);
        }

        $diff = round($diff / 12);
        /* translators: %s: number of years */
        return sprintf(_n('%s year ago', '%s years ago', $diff, 'private-file-uploader'), $diff);
    }
}
