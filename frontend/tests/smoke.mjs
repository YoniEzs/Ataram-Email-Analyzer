/**
 * Browser smoke test: loads the UI, exercises the language toggle (en/he +
 * RTL), and renders a fake analysis result through the results renderer.
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

await page.click('#langToggle');
await page.waitForTimeout(200);
expect(await page.evaluate(() => document.documentElement.dir) === 'rtl', 'hebrew switches to rtl');
expect((await page.locator('.upload-header h2').textContent()).trim() === 'ניתוח מייל', 'hebrew heading');

const cardTitles = await page.evaluate(() => {
    window.lastAnalysisResult = {
        risk_assessment: { level: 'high', score: 62, verdict: 'SUSPICIOUS - Exercise extreme caution', whitelist_applied: false },
        suspicions: [{ category: 'authentication', severity: 'high', message: 'SPF check failed: fail' }],
        headers: { sender: 'a@b.com', subject: 'test' },
        authentication: { auth_analysis: { spf: 'fail' } },
        sender_info: { domain: 'b.com' },
        content: { urgent_phrases: ['urgent'] },
        urls: { total_count: 0 },
        attachments: { total_count: 0 },
        routing: { hops: ['hop1'], hop_count: 1 },
        routing_forensics: { hop_count: 1, public_ips: [], originating_ip: null, timezone_offset: null },
        artifacts: {
            schema_version: 1,
            checklist: {
                sender_address: 'a@b.com',
                subject: 'test',
                recipients: 'victim@company.example',
                date_utc: '2026-07-06T09:00:00+00:00',
                sending_server_ip: '93.184.216.34',
                reverse_dns: 'mail.b.com',
                reply_to: 'r@b.com',
            },
            sender: { trust: 'header_claim', address: 'a@b.com', flags: [] },
            subject: { trust: 'header_claim', value: 'test', flags: [] },
            recipients: {
                trust: 'header_claim',
                to: [{ name: '', address: 'victim@company.example' }],
                cc: [], bcc_inferred: [], undisclosed: false, flags: [],
            },
            date: { trust: 'header_claim', utc: '2026-07-06T09:00:00+00:00', offset_minutes: 0, flags: [] },
            sending_server: {
                trust: 'header_claim', ip: '93.184.216.34', flags: [],
                enrichment: {
                    reverse_dns: { trust: 'observed', ptr_name: 'mail.b.com', fcrdns: 'fail', ptr_matches_helo: false },
                    ip_intel: { trust: 'observed', asn: '64500', as_name: 'EXAMPLE-AS', bgp_prefix: '93.184.216.0/24', country: 'US', registry: 'arin', rdap: { name: 'EXAMPLE-NET', abuse_email: 'abuse@b.com' } },
                },
            },
            reverse_dns: { trust: 'observed', value: 'mail.b.com', flags: [] },
            reply_to: { trust: 'header_claim', address: 'r@b.com', flags: [] },
            authentication_advisory: { spf: { result: 'fail', advisory: true, trusted: false } },
            flags: [{ code: 'fcrdns_fail', severity: 'medium', trust: 'observed', scope: 'sending_server' }],
            enrichment_status: { reverse_dns: 'ok', ip_intel: 'ok', spf_advisory: 'ok' },
        },
        metadata: { filename: 'sample.eml' },
    };
    window.resultsRenderer.render(window.lastAnalysisResult);
    return Array.from(document.querySelectorAll('.result-card-title')).map(e => e.textContent.trim());
});
expect(cardTitles.includes('כותרות המייל'), 'results render in hebrew');
expect(cardTitles.includes('ארטיפקטים'), 'artifacts card renders in hebrew');

// The artifact block must survive a round-trip into pasteable text, and must
// keep saying which values are forgeable once the badges are gone.
const artifactText = await page.evaluate(
    () => window.resultsRenderer.buildArtifactText(window.lastAnalysisResult)
);
expect(artifactText.includes('93.184.216.34'), 'export carries the sending IP');
expect(artifactText.includes('mail.b.com'), 'export carries reverse DNS');
expect(artifactText.includes('FCrDNS: fail'), 'export carries the FCrDNS verdict');
expect(artifactText.includes('AS64500'), 'export carries the ASN');
expect(artifactText.includes('fcrdns_fail'), 'export carries flags');
expect(/forgeable|לזיוף/.test(artifactText), 'export states which fields are forgeable');

// Missing enrichment must explain itself rather than render blank.
const missingReason = await page.evaluate(() => {
    const r = JSON.parse(JSON.stringify(window.lastAnalysisResult));
    r.artifacts.reverse_dns = { trust: 'observed', value: null, flags: [] };
    r.artifacts.checklist.reverse_dns = null;
    r.artifacts.enrichment_status.reverse_dns = 'disabled';
    window.resultsRenderer.render(r);
    // Scope to the artifacts card: the suspicions card also uses .result-card.
    const card = Array.from(document.querySelectorAll('.result-card')).find(
        el => el.querySelector('.result-card-title')?.textContent.trim() === 'ארטיפקטים'
    );
    return card ? card.textContent : '';
});
expect(missingReason.includes('הבדיקה מושבתת'), 'disabled lookup explains itself');

// Restore the full result for any later assertions.
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
