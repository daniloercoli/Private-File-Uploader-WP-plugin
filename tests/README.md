# Integration regressions

Use a **disposable WordPress installation** with this plugin active, an administrator, and a writable uploads directory. The script creates test users, files and, on Multisite, an extra site. It deliberately invokes deletion handlers and simulates filesystem failures; never run it against production data.

Set `define('PRIVFILEUP_TEST_SANDBOX', true);` in that installation's `wp-config.php`. Run with an administrator (a super administrator for Multisite):

```sh
wp --path=/path/to/disposable-wordpress --user=admin eval-file /path/to/private-file-uploader/tests/regression.php
```

Run once in single-site and once in Multisite. Each run uses new fixture names. PHP 8.0+ is required. This script is excluded from release archives by `.distignore`.

The tests exercise real WordPress REST dispatch, capabilities, nonce-checked admin handlers and user lifecycle hooks. Uploads use local fixtures with the plugin's sideload handler; they do not replace HTTP multipart/Application Password tests or browser checks.
