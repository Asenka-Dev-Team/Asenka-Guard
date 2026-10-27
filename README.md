# Asenka Guard

[![Version](https://img.shields.io/badge/version-0.1.7-315664)](https://github.com/Asenka-Dev-Team/Asenka-Guard/releases/latest) [![Latest release](https://img.shields.io/badge/Download-Latest%20Release-1f8c9b?logo=github)](https://github.com/Asenka-Dev-Team/Asenka-Guard/releases/latest) [![License](https://img.shields.io/badge/license-GPL--2.0%2B-60747e)](LICENSE)

A WordPress security review and monitoring plugin focused on suspicious files, YOOtheme Pro image-handler exposure, and local file integrity changes. Built by [Asenka Interactive](https://asenka.com).

> [!IMPORTANT]
> **First update affected YOOtheme Pro installations.** The known affected range is **5.0.0–5.0.52**, patched in **5.0.53**. Scanning does not close the vulnerability, and updating does not remove existing malware.

## Download and install

**[Download the latest GitHub Release](https://github.com/Asenka-Dev-Team/Asenka-Guard/releases/latest)**

1. Open the **Latest Release** link above.
2. Download the installable plugin ZIP listed in the release assets, **if available**. Otherwise download **Source code (zip)**; the GitHub updater can normalize the GitHub-generated source folder for automatic updates, but manual installation of GitHub source archives may need repackaging so the ZIP contains an `asenka-yootheme-image-guard/` root folder.
3. In WordPress go to **Plugins → Add New Plugin → Upload Plugin**, select the ZIP and activate it.
4. Open **Asenka Guard → Scan Uploads** to run a manual uploads scan, or use **Scan Site** for broader read-only inspection. Review the Dashboard before enabling monitoring.

> [!NOTE]
> New versions are discovered from **public GitHub Releases**. Use the **Updates** tab to check the latest published version. Maintainers should publish a GitHub release tagged `v0.1.7` after committing matching versioned files.

## Features

- **Security dashboard:** summarizes active and high-priority findings, quarantined files, YOOtheme components, recent scans, and monitoring status.
- **Scan Uploads:** investigates unusual PHP files, disguised image payloads, and suspicious content in WordPress uploads and YOOtheme cache paths.
- **Scan Site:** performs read-only inspection outside uploads for suspicious PHP/backdoor patterns; site/root findings are review-only.
- **YOOtheme version and integrity checks:** audits potentially vulnerable versions and compares selected YOOtheme PHP, template and JavaScript files against a *locally captured* SHA-256 baseline.
- **Optional scheduled monitoring:** daily or weekly WP-Cron scans, selected scope (Uploads or Site), email notifications for new/changed findings and incomplete scans, and last/next-run status. **Off by default.**
- **Reviewable findings:** severity and confidence badges, timestamps, evidence snippets, signals, secure read-only previews, and Copy Path.
- **Fast selection:** single-row, Select All, filename/full-path matching, and **Shift+click range selection**; bulk actions support up to 200 findings per request.
- **File management:** private quarantine, verified restore, confirmed permanent deletion, and hash-aware Ignore/Unignore tools.
- **Exports and tracking:** CSV, bounded evidence ZIPs with SHA-256 manifest, scan-history summaries, and New/Changed file lists.
- **GitHub updates:** WordPress update integration, an Updates tab, and optional per-plugin automatic updates from the Plugins page.
- **WP-CLI:** `wp ayig scan --scope=uploads`, `wp ayig scan --scope=site`, `wp ayig monitor`, `wp ayig integrity`, `wp ayig versions`, and findings/quarantine/restore/ignore commands.

## Critical operational limitations

> [!CAUTION]
> **Not a complete malware scanner.** Uploads and Site scans use heuristics, not comprehensive or vendor-authenticated integrity verification. Database payloads, persistence mechanisms, rogue users and all possible infection paths are not exhaustively checked.
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

The scanning overlay is an activity indicator, **not** a percentage progress bar. Manual and scheduled scans are synchronous and large sites may encounter PHP timeouts. WP-Cron only runs when triggered by visits or an external cron mechanism; it does not guarantee exact scan times. The monitoring interface should not be relied upon as a substitute for server-level security monitoring. Text previews show the first 128 KiB of an unchanged file; image previews are limited to 2 MiB and is unavailable after permanent deletion.

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


## v0.1.7 — YOOtheme integrity and monitoring

- **Dashboard:** overview of active findings, high/critical findings, quarantined files, detected YOOtheme components, last Uploads/Site scans, and scheduled monitoring status.
- **Integrity:** capture a SHA-256 baseline for selected YOOtheme source files and compare subsequent scans for **added, modified, or removed** files. Capture only after verifying that the installation is clean. Normal YOOtheme updates also change hashes; this is **not** comparison against official vendor checksums.
- **Scheduled monitoring:** optionally enable daily or weekly scans via WP-Cron. Choose Uploads or Site, set the recipient email, and enable notifications for new/changed findings or incomplete scans. The dashboard reports the next scheduled run and latest outcome.
- **Result selection:** Shift+click across visible findings to select or deselect a contiguous range for bulk actions.
- **Plugins page:** native enable/disable auto-updates control; author name links to [Asenka Interactive](https://asenka.com) and the redundant Asenka row-action link is removed.

> [!CAUTION]
> Scheduled scans remain synchronous and can time out on large sites. WP-Cron is traffic-dependent. **Monitoring and automatic updates are opt-in.** Inspect and approve any YOOtheme baseline before trusting change reports.

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


## Scan scopes and ignore rules (v0.1.5)

- **Scan Uploads:** checks suspicious files within `wp-content/uploads` as before.
- **Scan Site:** read-only filesystem examination of the WordPress installation, excluding symlinks and common dependency/cache folders. Outside uploads, it reports stronger executable-code or image-polyglot indicators rather than every PHP file. This is heuristic and can produce false positives; scans may time out on large sites.
- **Ignored Files:** an administrator can hide an active finding. Ignore rules persist across scans while the file SHA-256 remains unchanged. When the content changes, the file may reappear. Undo an ignore from the Ignored Files tab and scan again.
- **Quarantine:** shared storage and management for all scan scopes. File actions retain hash verification and safety checks.
- **WP-CLI:** `wp ayig scan --scope=site` or `wp ayig scan --scope=uploads`; `wp ayig ignore <finding-id>` / `wp ayig unignore <finding-id>`.

> [!CAUTION]
> Scan Site is an additional heuristic scan, not a WordPress core integrity check or guarantee of compromise detection. Verify findings against trusted originals. Perform server-level backups before quarantine or deletion.


## v0.1.6 scanning improvements

- Image magic-byte checks distinguish file extensions from actual signatures. A `.jpg` containing `BZh` bytes is flagged for review.
- Bounded, in-process bzip2/gzip/zlib inspection (when PHP extensions are available) and heuristic inspection of decompressed PHP. Content is **never executed**.
- `wp-blog.php` and request-driven command execution are specifically considered during site scans. The Sucuri name `php.backdoor.fakeJPG.001` is **not** claimed as an exact proprietary signature match.
- UI: row selection highlighting, more compact actions and signal labels, color-coded confidence, filters and new/changed tracking.
- Evidence ZIP: 50 unchanged findings maximum, 2 MiB per file, 12 MiB total, with JSON manifest and SHA-256 hashes. It contains potentially malicious content; store offline and never execute. Requires PHP ZipArchive.

### Operational limits

- Scans are still synchronous, bounded by the current PHP execution environment and a 150,000-entry cap. **Chunked AJAX scanning and a trustworthy progress percentage are not yet implemented.**
- Compressed samples over 256 KiB and expanded payloads over 4 MiB are not fully decoded; `compressed_uninspected` marks this limitation. `bzdecompress` requires PHP bzip2.
- Image header mismatch is evidence for investigation, not proof of maliciousness. AVIF, ICO and BMP support is limited.
- Site-scan findings are **review-only**, including theme/plugin files. Quarantine should be limited to thoroughly reviewed uploads findings.
- New/changed labels compare against the preceding saved scan, not an immutable trusted baseline.
