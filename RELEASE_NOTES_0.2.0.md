# Asenka Guard 0.2.0 — deployment notes

This build adds detection for observed YOOtheme-related redirect infections and repairs the GitHub release ZIP normalization for single/bulk upgrades. **It does not automatically strip injected PHP/JS from existing legitimate files**. Those files should be reviewed, backed up, and cleaned with validated server-side remediation.

## Important update caveat
The currently deployed 0.1.9 updater must perform the upgrade to 0.2.0, so an existing broken bulk/native upgrade path may still fail on that first hop. Install 0.2.0 manually on one staging site (or use the working plugin Updates button) and test normal single, bulk, and automatic update channels with a subsequent release.

## Test checklist
1. Backup files and database and test on a staging clone.
2. Scan Site and confirm a synthetic PHP file containing `rawheaderdecodes` is reported as critical.
3. Confirm legitimate plugin JS and a PHP file containing `String.fromCharCode` alone are not marked as confirmed redirect loaders.
4. Confirm Scan Uploads and quarantine/restore still function.
5. Test native, bulk and automatic upgrades to a later test tag and verify the folder remains `asenka-yootheme-image-guard`.
6. Purge page, Redis and PHP OPcache externally after manual malware cleanup.
