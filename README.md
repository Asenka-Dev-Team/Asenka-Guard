# Asenka YOOtheme Image Guard

A purpose-built WordPress scanner and manual quarantine tool for investigating YOOtheme Pro image-handler exposure. Maintained by Asenka Interactive.

## Security advisory
YOOtheme's published changelog identifies **CVE-2026-102785** as an unauthenticated remote code execution vulnerability in its image handler, patched in **YOOtheme Pro 5.0.53 (October 21, 2026)**. Versions 5.0.0–5.0.52 require immediate updates. The WordPress YOOtheme image cache resides at `wp-content/uploads/yootheme/cache` as of 5.0.0.

Sources:
- https://yootheme.com/changelog
- https://nvd.nist.gov/vuln/detail/CVE-2026-102785

## Installation and releases
1. Create **public** repository `Asenka-Dev-Team/Asenka-YOOtheme-Image-Guard`.
2. Put the plugin files **directly at repository root**, not within an additional wrapper folder.
3. In WordPress upload `asenka-yootheme-image-guard-v0.1.1.zip`, then activate.
4. Publish a **GitHub Release** with stable tag `v0.1.1`. The GitHub-generated **Source code (zip)** is sufficient. No manual ZIP asset is needed.
5. For each new release update `Version` in the plugin header, `AYIG_VERSION`, and this changelog, then tag/release `vX.Y.Z`.

WordPress checks GitHub through its `Update URI` mechanism. The updater checks the releases/latest endpoint (cached one hour), integrates with Plugins > Updates, and normalizes GitHub's source-code wrapper folder during updates. A check/status interface appears at Tools > Image Guard Updates.

## Features
- Manual uploads-directory inspection including `uploads/yootheme/cache`.
- YOOtheme theme/plugin version identification, with vulnerable 5.0.0–5.0.52 warnings.
- Heuristic signals for PHP in writable uploads, image/PHP polyglots, PHP execution/obfuscation patterns and previously observed `tmp_123456.php` files.
- Review, CSV export, quarantine, restore, permanent deletion of **already quarantined** files.
- WP-CLI: `wp ayig scan`, `wp ayig versions`, `wp ayig findings --format=csv`, `wp ayig quarantine <id>`, `wp ayig restore <id>`, `wp ayig delete <id> --yes`.
- Existing quarantined/deleted finding records persist through rescans.

## Critical operational limitations
- Manual scans only; not a guarantee of a clean site. The scanner does **not** comprehensively inspect theme/plugin/header modifications, database injection, user accounts, scheduled tasks or other backdoors.
- PHP in uploads is suspicious but not by itself proof of compromise. Review before changing production files.
- Before enabling quarantine, ensure a writable directory **physically outside all served webroots**, with appropriate server permissions. The default is `dirname(ABSPATH)/asenka-yootheme-image-guard-quarantine` and the plugin blocks paths physically inside ABSPATH. On nested installations, confirm that the parent is not separately web-served. To set the location, add this to a small must-use plugin:
  `add_filter('ayig_quarantine_path', function () { return '/secure/private/asenka-image-guard'; });`
- Back up and snapshot the site before quarantining. Quarantine uses filesystem rename, so it may require the source and destination to reside on compatible mounted volumes.
- Findings are heuristic and need human review. Do not run bulk deletion without investigating scope and persistence.
- GitHub repository/release must exist before updater will show a latest version. This package does **not** publish GitHub automatically.

## License
GPL-2.0-or-later.
