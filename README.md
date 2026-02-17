# Fastmail Phishing Link Detector

I'm sick of receiving emails from company that adds tracking links everywhere.
This userscript helps me make it very visible on fastmail.

## What it does

This script automatically scans all links in your Fastmail emails and identifies suspicious ones:

- **🔴 Obvious phishing** (red underline): When a link's displayed text shows one URL but actually points to a completely different domain
- **🟡 Tracking links** (yellow underline): When a link redirects through a tracking subdomain of the same organization
- **🟡 Suspected phishing/tracking** (yellow underline): Links with suspicious characteristics like:
  - Redirect subdomains (go.*, click.*, track.*, etc.)
  - Known email tracking services (SendGrid, Mailgun, etc.)
  - High-entropy obfuscated tokens
  - Suspicious redirect path patterns

Hover over any marked link to see detailed information about why it was flagged.

## Installation

1. Install a userscript manager in your browser:
   - Chrome/Edge: [Tampermonkey](https://chrome.google.com/webstore/detail/tampermonkey/)
   - Firefox: [Greasemonkey](https://addons.mozilla.org/en-US/firefox/addon/greasemonkey/) or Tampermonkey
   - Safari: [Userscripts](https://apps.apple.com/app/userscripts/id1463298887)

2. Click on `fastmail_tracking_link_detector.user.js` and install it through your userscript manager

3. Open Fastmail - the script will automatically start scanning emails

## How it works

The script uses multiple detection methods:
- Text vs. href URL comparison to catch obvious mismatches
- Heuristic scoring based on common phishing/tracking patterns
- Shannon entropy analysis to detect obfuscated URLs
- Pattern matching for known redirect services and suspicious subdomains

It runs continuously using a MutationObserver to catch dynamically loaded email content.
