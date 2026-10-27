# Asenka YOOtheme Image Guard — Why We Built It

## How this started

In October 2026, we began finding suspicious files on WordPress websites using YOOtheme Pro. Around the same time, a serious security issue was disclosed in YOOtheme Pro's image-handling feature. The concern was that attackers could use that weakness to place harmful files on a website.

Updating YOOtheme was an important first step, but it did not answer another question: **Had anything already been left behind on our sites?**

With many client websites to look after, checking every uploads folder by hand would take a lot of time. We needed a repeatable way to look for problems, keep a record of what we found, and deal with suspicious files carefully.

## What I built

**Asenka YOOtheme Image Guard** is a WordPress plugin that helps us check a site's uploaded files for signs of suspicious or potentially harmful code.

Think of it as a security inspection tool: it looks through areas where uploaded images and documents normally live and points out files that deserve a closer look.

Instead of requiring us to dig through server folders manually, it gives us a place inside WordPress to review findings and decide what to do next.

## What it helps us do

- **Scan uploaded files:** Look for warning signs that code may be hidden where it doesn't belong.
- **Review findings:** See which files were flagged and why, without automatically assuming every flagged file is dangerous.
- **Reduce unnecessary alerts:** Filter out known, legitimate files and patterns that would otherwise create noise.
- **Investigate individual files:** Download a flagged file for closer examination when needed.
- **Keep evidence:** Export a CSV report or an evidence ZIP to document what was found. Exports include identifying site and software-version information, making them easier to track later.
- **Handle suspicious files carefully:** Support a review-first approach to quarantine or removal rather than deleting everything that looks unusual.
- **Stay maintainable:** Use versioned plugin releases and WordPress update controls so improvements can be rolled out to client sites.

## Why this matters

A security update closes a known opening, but it does not necessarily remove files that may have been uploaded before the fix.

This plugin helps us cover that second part of the job. It also makes the process more consistent across client sites and gives us useful documentation if we need to revisit a finding or explain what was checked.

The goal is to save time **without sacrificing caution**. A flagged file is a reason to investigate, not automatic proof of an infection. Likewise, a clean scan is not a guarantee that a website has no security problems.

## Where the project stands

The plugin has been developed through several rounds of testing and refinement, including improvements to scan results, false-positive handling, file review, report exports, and update controls. The current release discussed during development is **v0.1.8**.

This is an internal security and maintenance tool, not a replacement for website backups, regular updates, server security, or a full malware investigation when one is needed.

## The bigger picture

What started as a response to a specific YOOtheme security issue has become a reusable tool for protecting and maintaining Asenka's WordPress client websites.

The main idea is simple: **find potential problems sooner, make them easier to review, and keep a clear record of the work.**
