## 0.2.0 — 2026-10-29
- Detect observed `rawheaderdecodes` injected redirect loaders inside PHP theme/plugin files, including multiple blocks per file (read-only detection).
- Flag the `space_active` cookie when accompanied by browser-redirect or decoding signals; do not flag generic `eval` / `String.fromCharCode` alone as confirmed malware.
- Ensure these targeted indicators survive the site scanner's legitimate-PHP noise filter.
- Normalize both single and bulk WordPress GitHub release upgrades, with plugin entry-point validation and support for a single nested plugin folder.
- Site findings remain review-only outside uploads: no automatic alteration of legitimate theme/plugin files.

## 0.1.9 — 2026-10-27 — JPEG-aware analysis and reliability

- Ignore coincidental `<?` and `<?=` sequences in JPEG compressed pixel data without assuming valid JPEG files are automatically safe.
- Scan JPEG APP/COM metadata separately for recognizable PHP; flag PHP appended after the JPEG end-of-image marker for high-priority review.
- Keep detecting image-type mismatches and disguised compressed payloads; do not scan a partial read as a malformed complete JPEG.
- Preserve previous saved findings and ignore rules if scans are incomplete because of file limits, inaccessible roots or unreadable files; report incomplete state in the dashboard, scan summary and WP-CLI.
- Keep scheduled monitoring from treating partial discoveries as new findings; report partial status and alert when configured.
- Retain the verified native WordPress Automatic Updates column fallback from the unreleased v0.1.8 hotfix. Full GitHub installation still requires a live, newer-release integration test.
- No automatic deletion or quarantine of suspicious JPEGs.

## 0.1.8 — 2026-10-27 — Verification, exports and downloads

- Fix WordPress native Automatic Updates column integration by supplying GitHub release metadata even when already up to date; remove redundant custom auto-update row action.
- Reduce Scan Site false positives by excluding checksum-verified WordPress core and WordPress.org plugin files where official matching checksums are available; do not automatically trust commercial plugins or BlogVault connectors.
- Omit empty and recognized harmless directory-browsing `index.php` placeholders from default findings.
- Add report-style CSV exports with site/domain, scan scope, timestamp, WordPress, active theme, YOOtheme and Asenka Guard versions, alongside findings-only CSV for spreadsheet imports.
- Add nonce-protected, permission-checked direct downloads of active/quarantined evidence as inert `.bin` attachments with SHA-256 verification and an 8 MiB limit.
- Name evidence ZIPs by site, scan scope and export timestamp, with expanded software metadata in `manifest.json`.
- Keep scanning heuristic; unverified files are not safe by default. No automatic deletion.

## 0.1.7 — pre-release

- Dashboard metrics for scans and quarantine.
- Opt-in WP-Cron monitoring and notification settings.
- Local YOOtheme change-baseline inventory and comparison.
- Shift+click range selection on scan results.
- Linked author credit to Asenka Interactive.

## v0.1.6.1 — Pre-release fixes
- Tightened scan table column widths and improved action visibility.
- Lock document scrolling during the scanning overlay.
- Prevent false positives from isolated PHP-like bytes in JPEG image entropy; maintain review for meaningful PHP payloads and mismatched/compressed image files.

## 0.1.6 — Scan intelligence and workflow
- Magic-byte media checks and bounded compressed-content inspection.
- Targeted detection of unexpected `wp-blog.php` and request-driven command execution.
- Reduced noisy media alerts; stronger confidence and severity signals.
- Selected-row highlighting, compact one-line action controls, filter dropdowns, new/changed labels.
- Selected finding evidence ZIP with SHA-256 manifest and hard size/count limits.
- Expanded hash-aware bulk Ignore and per-scope scan history.
- Site findings are review-only; no site-scope quarantine.
- Known limitation: chunked AJAX scans are not yet provided.

## 0.1.5 — Pre-release branding and responsive results
- Renamed the displayed plugin to **Asenka Guard**; focus remains YOOtheme Pro image-handler exposure and suspicious uploads.
- Updated the GitHub Releases updater to `Asenka-Dev-Team/Asenka-Guard`.
- Scan result rows display as labeled cards at narrower widths while retaining table display on desktop.
- Preserved the existing plugin directory, PHP class names, WP-CLI alias (`wp ayig`), saved options, and quarantine paths for backwards compatibility.
- Rename the GitHub repository before installing this package or expecting automatic update checks.

## 0.1.5 — Security Hardening
- Verify quarantine storage boundaries, directory/file permissions and post-move hashes.
- Harden restore target checks, collision handling and evidence manifests.
- Add independent confidence categorization and file permission metadata.
- Show local quarantine diagnostics and manual uploads-PHP execution verification guidance.
- Preserve stored quarantine history and existing administrator workflows.

# Changelog

## Unreleased patch (0.1.8)
- Preserve WordPress native Automatic Updates column support even when GitHub metadata is unavailable; add site-wide auto-update diagnostics.


## 0.1.4 — Scan triage and native updates
- Fixed GitHub updater hook to use WordPress `update_plugins_github.com` dynamic filter; adds native forced checks, diagnostics, and Update Now navigation.
- Added filename substring selection and optional full-path matching with select/unselect matching controls.
- Highlights all executable PHP-family files in uploads; recognizes harmless `index.php` placeholders as low severity.
- Added file type column and Copy Path controls.
- Improved suspect-code snippet readability and read-only viewer for text, images, and embedded PHP evidence; avoids displaying binary gibberish.
- Corrected bulk form markup and updated documentation.
- Final pre-release: evidence-weighted severity classification, bottom bulk action bar, and notification-safe faux heading.

# Changelog

## 0.1.3 — 2026-10-26
- Add last-scan status with WordPress-local timestamp, examined-file count, and active findings count.
- Make never-scanned sites distinguishable from scans with zero findings.
- Warn when the scan file limit is reached.
- Carry forward the v0.1.2 admin UI asset-loading, badge, and markup corrections.


## 0.1.2 — 2026-10-26
- Pre-release polish: remove decorative emoji from documentation and add a custom SVG security badge to the admin page header and sidebar menu.
- New gunmetal-styled four-tab admin dashboard: Scan Results, Quarantine, YOOtheme Versions, Updates.
- Read-only escaped source viewer in a separate tab with content security controls; snippet disclosure.
- Select-all and multi-select bulk quarantine, restore, and permanent deletion.
- Confidence-path highlighting toggle, clickable signal definitions, severity chips, and file modified timestamps.
- Scan activity spinner, Asenka admin footer, and standard plugin action links.
- Updated public-download instructions and prominent critical safety documentation.


## 0.1.1 — 2026-10-26
- Rebrand to Asenka Guard to isolate CVE-related scanning from future Asenka security tools.
- Standard Asenka public GitHub Releases updater (no manually uploaded ZIP asset needed).
- Proper plugin directory structure and Tools > Image Guard Updates status page.
- Preserve quarantined/deleted finding entries between rescans.
- Scope writable upload files, including YOOtheme 5 image cache; add observed tmp PHP filename signal.
- Require out-of-ABSPATH quarantine location and fail closed if it is inside ABSPATH.
- Rename WP-CLI command to `wp ayig`.

## 0.1.0 — 2026-10-26
- Initial prototype: manual scan, version audit, CSV, review, quarantine, restore, delete, WP-CLI.

- Corrected asset loading for the top-level WordPress admin menu; both entry points now load the security-themed styling and behavior.
- Removed duplicate dashboard shield, corrected results form markup, and standardized tab URLs.

### v0.1.5 pre-release final refinements
- Numbered result rows; responsive row-number layout.
- Hash-aware Ignore File action with an Ignored Files management tab.
- Separate Scan Uploads and Scan Site views and action labels; shared quarantine.
- WP-CLI scan scope and ignore/unignore commands.

- Pre-release v0.1.6.1: Clickable New/Changed scan summary counts open a read-only file list dialog.
