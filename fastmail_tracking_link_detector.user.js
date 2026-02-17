// ==UserScript==
// @name         Fastmail Phishing Link Detector
// @namespace    http://tampermonkey.net/
// @version      0.3
// @description  Detect and highlight potential phishing links in Fastmail emails (obvious and suspected)
// @author       You
// @icon         https://www.google.com/s2/favicons?sz=64&domain=fastmail.com
// @match        https://app.fastmail.com/*
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    // Styles for different phishing risk levels
    const OBVIOUS_PHISHING_STYLE = `
        text-decoration: underline wavy #ff4444 !important;
        text-decoration-thickness: 2px !important;
        text-underline-offset: 2px !important;
    `;

    const SUSPECTED_PHISHING_STYLE = `
        text-decoration: underline wavy #ffcc00 !important;
        text-decoration-thickness: 2px !important;
        text-underline-offset: 2px !important;
    `;

    // Regular expression to detect if text looks like a URL
    const URL_PATTERN = /^https?:\/\/[^\s]+$/i;

    // Suspicious redirect subdomains (often used in phishing)
    const REDIRECT_SUBDOMAINS = [
        'go', 'click', 'link', 'track', 'redirect', 'email', 'mail',
        't', 'r', 'links', 'tracking', 'trk', 'em', 'newsletter'
    ];

    // Suspicious redirect path patterns (often used in phishing)
    const REDIRECT_PATH_PATTERNS = [
        /^\/tr\//i,
        /^\/cl\//i,
        /^\/click\//i,
        /^\/track\//i,
        /^\/r\//i,
        /^\/redirect\//i,
        /^\/f\/a\//i,
        /^\/l\//i,
        /^\/e\//i,
        /^\/lnk\//i,
        /^\/ctc\//i,
    ];

    // Known email redirect services (can be abused for phishing)
    const REDIRECT_SERVICES = [
        'sendgrid.net',
        'mailgun.org',
        'mandrillapp.com',
        'amazonses.com',
        'sparkpostmail.com',
        'mailchimp.com',
        'list-manage.com',
        'campaignmonitor.com',
        'createsend.com',
        'constantcontact.com',
        'hubspotlinks.com',
        'hubspot.com',
        'hs-sites.com',
        'click.email',
        'link.mail',
        'url.mail',
    ];

    // Legitimate path patterns (negative indicators)
    const LEGITIMATE_PATH_PATTERNS = [
        /\/(order|invoice|ticket|confirmation|receipt|booking|reservation)[-_]?(id|token|number)?/i,
        /\/my[-_]?(account|orders|bookings|tickets)/i,
    ];

    /**
     * Calculate Shannon entropy of a string (0-1 scale)
     * Higher entropy = more random/encoded
     */
    function calculateEntropy(str) {
        if (!str || str.length === 0) return 0;

        const freq = {};
        for (let char of str) {
            freq[char] = (freq[char] || 0) + 1;
        }

        let entropy = 0;
        const len = str.length;
        for (let char in freq) {
            const p = freq[char] / len;
            entropy -= p * Math.log2(p);
        }

        // Normalize to 0-1 range (max entropy for ASCII is ~6.6 bits)
        return Math.min(entropy / 6.6, 1);
    }

    /**
     * Check if a string contains readable words (not just encoded gibberish)
     */
    function hasReadableWords(str) {
        // Check if there are sequences of 4+ lowercase letters (common in readable text)
        const readablePattern = /[a-z]{4,}/i;
        return readablePattern.test(str);
    }

    /**
     * Extract base domain from a hostname (e.g., "example.com" from "sub.example.com")
     * Handles common TLDs like .co.uk, .com.au, etc.
     */
    function getBaseDomain(hostname) {
        if (!hostname) return null;

        const parts = hostname.toLowerCase().split('.');

        // Handle special two-part TLDs (co.uk, com.au, etc.)
        const twoPartTlds = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'com.ar', 'co.za', 'gouv.fr'];

        if (parts.length >= 3) {
            const lastTwo = parts.slice(-2).join('.');
            if (twoPartTlds.includes(lastTwo)) {
                // Return domain.co.uk style
                return parts.slice(-3).join('.');
            }
        }

        // For regular TLDs, return last two parts (domain.com)
        if (parts.length >= 2) {
            return parts.slice(-2).join('.');
        }

        return hostname;
    }

    /**
     * Check if two URLs share the same base domain
     */
    function haveSameBaseDomain(url1, url2) {
        try {
            const domain1 = getBaseDomain(new URL(url1).hostname);
            const domain2 = getBaseDomain(new URL(url2).hostname);
            return domain1 && domain2 && domain1 === domain2;
        } catch (e) {
            return false;
        }
    }

    /**
     * Normalize a URL for comparison by:
     * - Converting to lowercase
     * - Removing trailing slashes
     * - Ensuring it has a protocol
     */
    function normalizeUrl(url) {
        try {
            let normalized = url.trim().toLowerCase();

            // Add https:// if no protocol is present
            if (!normalized.match(/^https?:\/\//i)) {
                normalized = 'https://' + normalized;
            }

            // Parse and reconstruct to normalize
            const urlObj = new URL(normalized);

            // Remove trailing slash from pathname
            let path = urlObj.pathname;
            if (path.endsWith('/') && path.length > 1) {
                path = path.slice(0, -1);
            }

            // Reconstruct URL without trailing slash
            return urlObj.protocol + '//' + urlObj.host + path + urlObj.search + urlObj.hash;
        } catch (e) {
            return null;
        }
    }

    /**
     * Check if textUrl is a valid prefix of hrefUrl
     * e.g., "https://example.com" is a valid prefix of "https://example.com/path/to/page"
     */
    function isValidPrefix(textUrl, hrefUrl) {
        const normalizedText = normalizeUrl(textUrl);
        const normalizedHref = normalizeUrl(hrefUrl);

        if (!normalizedText || !normalizedHref) {
            return false;
        }

        // Check if the href starts with the text URL
        // Also need to ensure it's a proper prefix (not partial match in middle of path)
        if (normalizedHref.startsWith(normalizedText)) {
            // Make sure the next character (if any) is a path separator or query/hash
            const nextChar = normalizedHref[normalizedText.length];
            return !nextChar || nextChar === '/' || nextChar === '?' || nextChar === '#';
        }

        return false;
    }

    /**
     * Analyze a URL for phishing characteristics using heuristic scoring
     * Returns: { isSuspicious: boolean, score: number, reasons: string[] }
     */
    function analyzeUrlForPhishing(url) {
        let score = 0;
        const reasons = [];

        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname.toLowerCase();
            const pathname = urlObj.pathname;
            const fullPath = pathname + urlObj.search + urlObj.hash;

            // Check for redirect subdomain (+3 points)
            const subdomain = hostname.split('.')[0];
            // Check for exact match or if subdomain starts with a redirect pattern
            const hasRedirectSubdomain = REDIRECT_SUBDOMAINS.some(pattern =>
                subdomain === pattern || subdomain.startsWith(pattern)
            );
            if (hasRedirectSubdomain) {
                score += 3;
                reasons.push(`Redirect subdomain: ${subdomain}`);
            }

            // Check for known redirect service (+3 points)
            const domain = hostname.split('.').slice(-2).join('.');
            if (REDIRECT_SERVICES.some(td => hostname.includes(td))) {
                score += 3;
                reasons.push(`Redirect service: ${domain}`);
            }

            // Check for redirect path patterns (+2 points)
            for (const pattern of REDIRECT_PATH_PATTERNS) {
                if (pattern.test(pathname)) {
                    score += 2;
                    reasons.push(`Redirect path pattern: ${pathname.substring(0, 20)}...`);
                    break;
                }
            }

            // Analyze entropy and length of path/query/hash
            if (fullPath.length > 80) {
                const entropy = calculateEntropy(fullPath);
                if (entropy > 0.7) {
                    // Very long paths with high entropy get more points
                    const points = fullPath.length > 200 ? 3 : 2;
                    score += points;
                    reasons.push(`Obfuscated token (${(entropy * 100).toFixed(0)}% entropy, ${fullPath.length} chars)`);
                }
            }

            // Check for lack of readable words (+1 point)
            if (fullPath.length > 40 && !hasReadableWords(fullPath)) {
                score += 1;
                reasons.push('No readable words in path');
            }

            // Check for legitimate patterns (-2 points)
            for (const pattern of LEGITIMATE_PATH_PATTERNS) {
                if (pattern.test(pathname)) {
                    score -= 2;
                    reasons.push('Matches legitimate pattern (order/ticket/etc)');
                    break;
                }
            }

            return {
                isSuspicious: score >= 4,
                score: score,
                reasons: reasons
            };
        } catch (e) {
            return { isSuspicious: false, score: 0, reasons: [] };
        }
    }

    /**
     * Check if a link is potentially phishing or tracking
     * Returns: { type: 'phishing'|'tracking'|'suspected', analysis?: object } or null
     */
    function detectPhishingType(link) {
        const href = link.getAttribute('href');
        const text = link.textContent.trim();

        // Skip if no href
        if (!href) {
            return null;
        }

        // First check: Text is URL but doesn't match href
        if (text && URL_PATTERN.test(text)) {
            const normalizedText = normalizeUrl(text);
            const normalizedHref = normalizeUrl(href);

            if (normalizedText && normalizedHref) {
                // If they match exactly or text is prefix, not suspicious
                if (normalizedText !== normalizedHref && !isValidPrefix(text, href)) {
                    // Check if same base domain (tracking) or different (phishing)
                    if (haveSameBaseDomain(normalizedText, normalizedHref)) {
                        return { type: 'tracking' };
                    } else {
                        return { type: 'phishing' };
                    }
                }
            }
        }

        // Second check: Heuristic analysis for suspected phishing/tracking
        const analysis = analyzeUrlForPhishing(href);
        if (analysis.isSuspicious) {
            return { type: 'suspected', analysis };
        }

        return null;
    }

    /**
     * Mark a link as potentially phishing or tracking
     */
    function markSuspiciousLink(link) {
        if (link.hasAttribute('data-phishing-checked')) {
            return;
        }

        link.setAttribute('data-phishing-checked', 'true');

        const detection = detectPhishingType(link);

        if (!detection) {
            return;
        }

        if (detection.type === 'phishing') {
            // Cross-domain phishing: text URL shows different domain than href
            link.style.cssText += OBVIOUS_PHISHING_STYLE;
            link.setAttribute('title',
                `🔴 POSSIBLE PHISHING\n\n` +
                `Shown URL: ${link.textContent.trim()}\n` +
                `Actual URL: ${link.href}\n\n` +
                `WARNING: The displayed URL domain does not match the actual destination. This may be a phishing attempt.`
            );

            // Add red circle emoji before the link
            const indicator = document.createElement('span');
            indicator.textContent = '🔴 ';
            indicator.style.cssText = 'font-weight: bold;';
            link.insertAdjacentElement('beforebegin', indicator);

            console.log('🔴 Possible phishing link detected:', {
                text: link.textContent.trim(),
                href: link.href
            });
        } else if (detection.type === 'tracking') {
            // Same-domain tracking: text URL shows same domain, just different subdomain
            link.style.cssText += SUSPECTED_PHISHING_STYLE;
            link.setAttribute('title',
                `🟡 TRACKING LINK\n\n` +
                `Shown URL: ${link.textContent.trim()}\n` +
                `Actual URL: ${link.href}\n\n` +
                `This link redirects through a tracking subdomain of the same organization.`
            );

            // Add yellow circle emoji before the link
            const indicator = document.createElement('span');
            indicator.textContent = '🟡 ';
            indicator.style.cssText = 'font-weight: bold;';
            link.insertAdjacentElement('beforebegin', indicator);

            console.log('🟡 Tracking link detected:', {
                text: link.textContent.trim(),
                href: link.href
            });
        } else if (detection.type === 'suspected') {
            // Suspected based on heuristics
            link.style.cssText += SUSPECTED_PHISHING_STYLE;

            const reasonsText = detection.analysis.reasons.join('\n• ');
            link.setAttribute('title',
                `🟡 SUSPICIOUS LINK\n\n` +
                `URL: ${link.href}\n\n` +
                `Risk Score: ${detection.analysis.score}/10\n\n` +
                `Reasons:\n• ${reasonsText}\n\n` +
                `This link shows characteristics commonly used in tracking or phishing.`
            );

            // Add yellow circle emoji before the link
            const indicator = document.createElement('span');
            indicator.textContent = '🟡 ';
            indicator.style.cssText = 'font-weight: bold;';
            link.insertAdjacentElement('beforebegin', indicator);

            console.log('🟡 Suspicious link detected:', {
                href: link.href,
                score: detection.analysis.score,
                reasons: detection.analysis.reasons
            });
        }
    }

    /**
     * Scan all links in the email content area
     */
    function scanLinks() {
        // Fastmail email content is typically in iframes or specific containers
        // We need to scan both the main document and any iframes
        const links = document.querySelectorAll('a[href]');

        links.forEach(link => {
            markSuspiciousLink(link);
        });

        // Also check iframes (email content is often in iframes)
        document.querySelectorAll('iframe').forEach(iframe => {
            try {
                const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
                const iframeLinks = iframeDoc.querySelectorAll('a[href]');
                iframeLinks.forEach(link => {
                    markSuspiciousLink(link);
                });
            } catch (e) {
                // Cross-origin iframe, can't access
                console.log('Cannot access iframe content (cross-origin):', e);
            }
        });
    }

    /**
     * Set up mutation observer to detect when email content changes
     */
    function setupObserver() {
        const observer = new MutationObserver((mutations) => {
            let shouldScan = false;

            for (const mutation of mutations) {
                // Check if any new nodes were added
                if (mutation.addedNodes.length > 0) {
                    for (const node of mutation.addedNodes) {
                        // If a link was added, or an element containing links
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            if (node.tagName === 'A' || node.querySelector('a[href]')) {
                                shouldScan = true;
                                break;
                            }
                        }
                    }
                }

                if (shouldScan) break;
            }

            if (shouldScan) {
                scanLinks();
            }
        });

        // Observe the entire document for changes
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });

        console.log('Fastmail Phishing Link Detector: Observer set up');
    }

    // Initial scan
    console.log('Fastmail Phishing Link Detector: Starting initial scan');
    scanLinks();

    // Set up observer for dynamic content
    if (document.body) {
        setupObserver();
    } else {
        document.addEventListener('DOMContentLoaded', setupObserver);
    }

    // Periodic scan as backup (every 2 seconds)
    setInterval(scanLinks, 2000);
})();
