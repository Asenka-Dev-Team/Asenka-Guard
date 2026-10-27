## 0.1.5 — Security Hardening
- Verify quarantine storage boundaries, directory/file permissions and post-move hashes.
- Harden restore target checks, collision handling and evidence manifests.
- Add independent confidence categorization and file permission metadata.
- Show local quarantine diagnostics and manual uploads-PHP execution verification guidance.
- Preserve stored quarantine history and existing administrator workflows.

# Changelog

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
- Rebrand to Asenka YOOtheme Image Guard to isolate CVE-related scanning from future Asenka security tools.
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
