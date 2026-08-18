/**
 * Browser smoke test: loads the UI, exercises the language toggle (en/he +
 * RTL) and the theme toggle, and renders a fake analysis result through the
 * results renderer (summary, conclusion, factors, tabs).
 *
 * Run:
 *   cd frontend/src && python3 -m http.server 8765 &
 *   npm i --no-save playwright   # once; browsers via `npx playwright install chromium`
 *   node ../tests/smoke.mjs
 *
 * Set CHROMIUM_PATH to use a pre-installed Chromium binary.
 */

import { chromium } from 'playwright';

const launchOptions = process.env.CHROMIUM_PATH
    ? { executablePath: process.env.CHROMIUM_PATH }
    : {};
const baseUrl = process.env.SMOKE_BASE_URL || 'http://localhost:8765';

const browser = await chromium.launch(launchOptions);
const page = await browser.newPage();
const errors = [];
page.on('pageerror', e => errors.push('pageerror: ' + e.message));
page.on('console', m => {
    const text = m.text();
    // The backend isn't running in this test — its health check failing is expected.
    if (m.type() === 'error' && !text.includes('Failed to load resource') && !text.includes('Health check failed')) {
        errors.push('console: ' + text);
    }
});

const expect = (condition, label) => {
    if (!condition) {
        errors.push('assert failed: ' + label);
    }
    console.log((condition ? 'ok' : 'FAIL') + ' - ' + label);
};

await page.goto(`${baseUrl}/index.html`, { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(300);

expect(await page.evaluate(() => document.documentElement.lang) === 'en', 'default language is en');
expect((await page.locator('.upload-header h2').textContent()).trim() === 'Analyze Email', 'english heading');

// Theme toggle flips the explicit data-theme attribute.
const themeBefore = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
await page.click('#themeToggle');
await page.waitForTimeout(150);
const themeAfter = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
expect((themeAfter === 'dark' || themeAfter === 'light') && themeAfter !== themeBefore, 'theme toggle switches theme');

await page.click('#langToggle');
await page.waitForTimeout(200);
expect(await page.evaluate(() => document.documentElement.dir) === 'rtl', 'hebrew switches to rtl');
expect((await page.locator('.upload-header h2').textContent()).trim() === 'ניתוח מייל', 'hebrew heading');

const render = await page.evaluate(() => {
    window.lastAnalysisResult = {
        risk_assessment: {
            level: 'high', score: 62, verdict: 'SUSPICIOUS - Exercise extreme caution', whitelist_applied: false,
            factors: [
                { label: 'Sender IP reputation', points: 20, severity: 'critical', detail: 'AbuseIPDB confidence 80%' },
                { label: 'Suspicious URLs', points: 10, severity: 'high', detail: '2 flagged link(s)' },
            ],
        },
        conclusion: {
            sender_address: 'a@b.com', subject: 'test', recipients: 'c@d.com',
            date: 'Mon, 09 Mar 2026 09:00:00 +0000',
            sending_server_ip: '8.8.8.8', reverse_dns: 'dns.google', reply_to: 'r@b.com',
        },
        suspicions: [{ category: 'authentication', severity: 'high', message: 'SPF check failed: fail' }],
        headers: { sender: 'a@b.com', subject: 'test' },
        authentication: { auth_analysis: { spf: 'fail' } },
        sender_info: { domain: 'b.com', ip: '8.8.8.8', reverse_dns: 'dns.google' },
        content: { urgent_phrases: ['urgent'] },
        urls: { total_count: 0 },
        attachments: { total_count: 0 },
        routing: { hops: ['hop1'], hop_count: 1 },
        routing_forensics: { hop_count: 1, public_ips: [], originating_ip: null, timezone_offset: null },
        artifacts: {
            schema_version: 1,
            checklist: {
                sender_address: 'a@b.com', subject: 'test', recipients: 'c@d.com',
                date_utc: '2026-03-09T09:00:00+00:00',
                sending_server_ip: '8.8.8.8', reverse_dns: 'dns.google', reply_to: 'r@b.com',
            },
            sender: { trust: 'header_claim', address: 'a@b.com', display_name: 'A',
                      registered_domain: 'b.com', flags: [] },
            subject: { trust: 'header_claim', value: 'test', charsets: [], flags: [] },
            recipients: { trust: 'header_claim', to: [{ name: '', address: 'c@d.com' }],
                          cc: [], bcc_inferred: ['hidden@d.com'], undisclosed: false, flags: [] },
            date: { trust: 'header_claim', utc: '2026-03-09T09:00:00+00:00',
                    offset_minutes: 0, skew_vs_oldest_received_seconds: -42, flags: [] },
            sending_server: {
                trust: 'header_claim', ip: '8.8.8.8', helo_claimed: 'mail.evil.example', flags: [],
                enrichment: {
                    reverse_dns: { trust: 'observed', ptr_name: 'dns.google',
                                   fcrdns: 'fail', ptr_matches_helo: false },
                    ip_intel: { trust: 'observed', asn: '15169', as_name: 'GOOGLE - Google LLC, US',
                                bgp_prefix: '8.8.8.0/24', country: 'US', registry: 'arin',
                                rdap: { name: 'GOGL', abuse_email: 'abuse@google.com' } },
                },
            },
            reverse_dns: { trust: 'observed', value: 'dns.google', flags: [] },
            reply_to: { trust: 'header_claim', address: 'r@b.com', flags: [] },
            authentication_advisory: { spf: { result: 'softfail', advisory: true, trusted: false } },
            flags: [{ code: 'fcrdns_fail', severity: 'medium', trust: 'observed', scope: 'sending_server' }],
            enrichment_status: { reverse_dns: 'ok', ip_intel: 'ok', spf_advisory: 'ok' },
        },
        metadata: { filename: 'sample.eml' },
    };
    window.resultsRenderer.render(window.lastAnalysisResult);
    const conclusionCard = document.querySelector('.conclusion-card');
    return {
        cardTitles: Array.from(document.querySelectorAll('.result-card-title')).map(e => e.textContent.trim()),
        conclusionText: conclusionCard ? conclusionCard.textContent : '',
        hasVerdict: !!document.querySelector('.verdict-card'),
        scoreText: (document.querySelector('.score-num') || {}).textContent || '',
        factorCount: document.querySelectorAll('.factor-item').length,
        tabCount: document.querySelectorAll('.tab-btn').length,
        tabLabels: Array.from(document.querySelectorAll('.tab-btn')).map(e => e.textContent.trim()),
    };
});
expect(render.cardTitles.includes('כותרות המייל'), 'results render in hebrew');
expect(render.cardTitles.includes('סיכום'), 'conclusion card renders in hebrew');
expect(render.conclusionText.includes('8.8.8.8'), 'conclusion shows sending server IP');
expect(render.conclusionText.includes('dns.google'), 'conclusion shows reverse DNS');
expect(render.hasVerdict, 'verdict summary card renders');
expect(render.scoreText === '62', 'score ring shows the score');
expect(render.factorCount === 2, 'risk factors render');
expect(render.tabCount >= 5, 'detail tabs render');
expect(render.conclusionText.includes('נצפה'), 'conclusion marks observed values');
expect(render.conclusionText.includes('טענה מהכותרות'), 'conclusion marks forgeable header claims');
expect(render.conclusionText.includes('AS15169'), 'conclusion shows the ASN');
expect(render.tabLabels.includes('ארטיפקטים'), 'artifacts tab renders in hebrew');

// Switching tabs reveals a previously hidden panel.
const tabSwitch = await page.evaluate(() => {
    const btns = document.querySelectorAll('.tab-btn');
    const last = btns[btns.length - 1];
    last.click();
    const idx = last.getAttribute('data-tab');
    const panel = document.querySelector(`.tab-panel[data-tab="${idx}"]`);
    return panel && panel.classList.contains('active') && last.classList.contains('active');
});
expect(tabSwitch, 'clicking a tab activates its panel');

// The artifact block must survive a round-trip into pasteable text, and must
// keep saying which values are forgeable once the badges are gone.
const artifactText = await page.evaluate(
    () => window.resultsRenderer.buildArtifactText(window.lastAnalysisResult)
);
expect(artifactText.includes('8.8.8.8'), 'export carries the sending IP');
expect(artifactText.includes('dns.google'), 'export carries reverse DNS');
expect(artifactText.includes('FCrDNS: fail'), 'export carries the FCrDNS verdict');
expect(artifactText.includes('AS15169'), 'export carries the ASN');
expect(artifactText.includes('fcrdns_fail'), 'export carries flags');
expect(/forgeable|לזיוף/.test(artifactText), 'export states which fields are forgeable');

// Missing enrichment must explain itself rather than render blank.
const missingReason = await page.evaluate(() => {
    const r = JSON.parse(JSON.stringify(window.lastAnalysisResult));
    r.conclusion.reverse_dns = null;
    r.artifacts.reverse_dns = { trust: 'observed', value: null, flags: [] };
    r.artifacts.enrichment_status.reverse_dns = 'disabled';
    window.resultsRenderer.render(r);
    const card = document.querySelector('.conclusion-card');
    return card ? card.textContent : '';
});
expect(missingReason.includes('הבדיקה מושבתת'), 'disabled lookup explains itself');
await page.evaluate(() => window.resultsRenderer.render(window.lastAnalysisResult));

await page.click('#langToggle');
await page.waitForTimeout(200);

expect(await page.evaluate(() => document.documentElement.dir) === 'ltr', 'toggle back to ltr');

await browser.close();

if (errors.length) {
    console.error('FAILURES:', errors);
    process.exit(1);
}
console.log('smoke test passed');
