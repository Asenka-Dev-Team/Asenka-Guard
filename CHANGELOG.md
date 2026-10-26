# Changelog

## 0.1.2 — 2026-10-26
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
