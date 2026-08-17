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

const render = await page.evaluate(() => {
    window.lastAnalysisResult = {
        risk_assessment: { level: 'high', score: 62, verdict: 'SUSPICIOUS - Exercise extreme caution', whitelist_applied: false },
        conclusion: {
            sender_address: 'a@b.com',
            subject: 'test',
            recipients: 'c@d.com',
            date: 'Mon, 09 Mar 2026 09:00:00 +0000',
            sending_server_ip: '8.8.8.8',
            reverse_dns: 'dns.google',
            reply_to: 'r@b.com',
        },
        suspicions: [{ category: 'authentication', severity: 'high', message: 'SPF check failed: fail' }],
        headers: { sender: 'a@b.com', subject: 'test' },
        authentication: { auth_analysis: { spf: 'fail' } },
        sender_info: { domain: 'b.com' },
        content: { urgent_phrases: ['urgent'] },
        urls: { total_count: 0 },
        attachments: { total_count: 0 },
        routing: { hops: ['hop1'], hop_count: 1 },
        routing_forensics: { hop_count: 1, public_ips: [], originating_ip: null, timezone_offset: null },
    };
    window.resultsRenderer.render(window.lastAnalysisResult);
    const conclusionCard = document.querySelector('.conclusion-card');
    return {
        cardTitles: Array.from(document.querySelectorAll('.result-card-title')).map(e => e.textContent.trim()),
        conclusionText: conclusionCard ? conclusionCard.textContent : '',
    };
});
expect(render.cardTitles.includes('כותרות המייל'), 'results render in hebrew');
expect(render.cardTitles.includes('סיכום'), 'conclusion card renders in hebrew');
expect(render.conclusionText.includes('8.8.8.8'), 'conclusion shows sending server IP');
expect(render.conclusionText.includes('dns.google'), 'conclusion shows reverse DNS');

await page.click('#langToggle');
await page.waitForTimeout(200);
expect(await page.evaluate(() => document.documentElement.dir) === 'ltr', 'toggle back to ltr');

await browser.close();

if (errors.length) {
    console.error('FAILURES:', errors);
    process.exit(1);
}
console.log('smoke test passed');
