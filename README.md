# Asenka Guard

[![Version](https://img.shields.io/badge/version-0.1.4-315664)](https://github.com/Asenka-Dev-Team/Asenka-Guard/releases/latest) [![Latest release](https://img.shields.io/badge/Download-Latest%20Release-1f8c9b?logo=github)](https://github.com/Asenka-Dev-Team/Asenka-Guard/releases/latest) [![License](https://img.shields.io/badge/license-GPL--2.0%2B-60747e)](LICENSE)

A narrowly scoped, **manual WordPress security review tool** for investigating possible compromise related to YOOtheme Pro's image handler. Built by [Asenka Interactive](https://asenka.com).

> [!IMPORTANT]
> **First update affected YOOtheme Pro installations.** The known affected range is **5.0.0–5.0.52**, patched in **5.0.53**. Scanning does not close the vulnerability, and updating does not remove existing malware.

## Download and install

**[Download the latest GitHub Release](https://github.com/Asenka-Dev-Team/Asenka-Guard/releases/latest)**

1. Open the **Latest Release** link above.
2. Download the installable plugin ZIP listed in the release assets, **if available**. Otherwise download **Source code (zip)**; the GitHub updater can normalize the GitHub-generated source folder for automatic updates, but manual installation of GitHub source archives may need repackaging so the ZIP contains an `asenka-yootheme-image-guard/` root folder.
3. In WordPress go to **Plugins → Add New Plugin → Upload Plugin**, select the ZIP and activate it.
4. Go to **Tools → Asenka Guard** and select **Scan Results → Scan now**.

> [!NOTE]
> New versions are discovered from **public GitHub Releases**. Use the **Updates** tab to check the latest published version. Maintainers should publish a GitHub release tagged `v0.1.4` after committing matching versioned files.

## Features

- **Manual scanning:** uploads and nested YOOtheme cache, with all PHP-family extensions in uploads plus filename and code heuristics.
- **Last-scan status:** shows the date/time, files examined, active findings, and scan-limit warning; clearly identifies never-scanned sites.
- **YOOtheme version audit:** warns about known 5.0.0–5.0.52 exposure.
- **Reviewable findings:** severity colors, last-modified timestamps, flagged-path highlighting, readable snippets, file types, copy-path buttons, signal explanations, and secure read-only text/image previews.
- **Selection tools:** select individual files, all visible files, or filename/full-path substring matches, then apply bulk actions (up to 200 per request).
- **Quarantine tab:** view, restore or permanently delete quarantined files, with deletion confirmation.
- **CSV exports:** save findings for follow-up.
- **GitHub release updates:** WordPress-native updates, manual refresh, status diagnostics, and Update Now link in the Updates tab.
- **WP-CLI:** `wp ayig scan`, `wp ayig versions`, `wp ayig findings --format=csv`, `wp ayig quarantine <id>`, `wp ayig restore <id>`, `wp ayig delete <id> --yes`.

## Critical operational limitations

> [!CAUTION]
> **Not a full malware scanner.** Only the uploads directory is scanned. Theme modifications, injected header templates, database entries, cron tasks, rogue users, persistence mechanisms and files outside uploads are not comprehensively analyzed.
>
> **Heuristics are not proof.** PHP inside uploads and `tmp_123.php` patterns can be highly concerning, but *do not automatically delete findings*. Snippets and previews expose untrusted code as inert, escaped text only.
>
> **Quarantine storage must be private.** The default path (`dirname(ABSPATH)/asenka-yootheme-image-guard-quarantine`) is outside the WordPress installation directory but **might still be within a web-served parent directory**. Verify its protection on your GridPane server, or set a custom private location outside every served webroot:
>
> ```php
> add_filter('ayig_quarantine_path', function () {
>     return '/secure/private/asenka-image-guard';
> });
> ```
>
> **Back up production first.** Quarantine uses filesystem renames, which may fail across mounts. A deleted quarantined file cannot be restored by this plugin. A rescan after restoring a file will identify it again.

The scanning overlay is an activity indicator **not** a percentage progress bar. Scans currently run as a regular server request and large sites may encounter server/PHP timeouts. Text previews show the first 128 KiB of an unchanged file; image previews are limited to 2 MiB and is unavailable after permanent deletion.

## Security reference

- [YOOtheme changelog](https://yootheme.com/changelog)
- [CVE-2026-102785 at NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102785)

The underlying issue relates to abuse of YOOtheme Pro's image handler and may be associated with server-side code being written to accessible file paths. The scanner looks for suspicious PHP placement, injected PHP markers in image files, request-to-execution patterns and obfuscation. These are **indicators**, not attribution or forensic proof of the entry point.

## Release process (maintainers)

Change the main plugin header version, `AYIG_VERSION`, README badge, and changelog. Push files to the public repository root, tag `vX.Y.Z`, then publish a non-prerelease GitHub Release. The updater uses GitHub's `releases/latest` API and source-code ZIP with folder normalization; no manual binary asset is required for automatic updates.

## License

GPL-2.0-or-later.

### Severity classification (v0.1.4)
Severity is heuristic and is **not proof of compromise**. PHP files in uploads and PHP tags inside images trigger review; stronger combinations (request-driven execution, obfuscation, and known suspicious `tmp_*.php` patterns) raise priority. Common harmless `index.php` directory placeholders remain low priority. Review evidence before quarantining.


## v0.1.5: Security hardening and diagnostics

- Quarantine location checks validate the real parent directory, reject link-based storage paths, enforce owner-only directory permissions, and verify quarantined file hashes and permissions before reporting success.
- Restores reject existing destination paths and verify the hash again after moving. Any failed verification requires administrator inspection; do **not** automatically retry or delete evidence.
- Findings now include confidence (heuristic, suspicious, strong indicators, informational) independently of severity, along with permissions and additional manifest metadata. Existing quarantined files and their saved records are retained.
- The Quarantine and YOOtheme Versions tabs display filesystem isolation checks and a manual PHP-execution configuration reminder. **The plugin cannot prove that a server alias does not expose the quarantine folder or that uploads PHP is disabled.** No executable test file is generated.
- Before deployment: back up the site, confirm the private quarantine path, test restore with harmless fixtures, and check server PHP execution rules manually.

> [!CAUTION]
> A passing local quarantine diagnostic does not prove isolation from all server HTTP aliases. PHP execution protection requires server-specific verification. Do not use bulk delete without reviewing findings.

## Name and repository migration (v0.1.5)

The public name is **Asenka Guard**. Its focus is still the YOOtheme Pro 5 image-handler vulnerability and suspicious files in uploads. The GitHub repository is expected at [`Asenka-Dev-Team/Asenka-Guard`](https://github.com/Asenka-Dev-Team/Asenka-Guard). Rename the existing GitHub repository before distributing this build.

**Compatibility:** The installed directory remains `asenka-yootheme-image-guard` intentionally. **Do not delete the existing plugin directory or quarantine files** simply to change its display name: doing so can interrupt activation and file restoration. Existing saved scan history and WP-CLI command (`wp ayig`) are retained.
