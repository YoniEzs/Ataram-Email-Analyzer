/**
 * Results Renderer
 *
 * Layout: a summary-first verdict header, the key "official artifacts"
 * conclusion, a "why this score" breakdown, severity-ordered findings, and
 * the full detail split across tabs.
 *
 * Attachments and URLs deliberately carry no outbound lookup links: files and
 * URLs are checked with open-source tooling only, and the tool never hands a
 * hash or a URL to a third party on the analyst's behalf. Copy the value and
 * pivot deliberately if you want that. Sender-IP and domain reputation links
 * remain, since those describe infrastructure rather than the message payload.
 */

class ResultsRenderer {
    constructor(containerSelector) {
        this.container = document.querySelector(containerSelector);
    }

    /**
     * Render analysis results
     * @param {Object} data - Analysis results
     */
    render(data) {
        if (!data || data.error) {
            this.renderError(data?.error || 'Unknown error');
            return;
        }

        this.container.innerHTML = `
            ${this.renderSummary(data)}
            ${this.renderConclusion(data.conclusion, data.artifacts)}
            ${this.renderRiskFactors(data.risk_assessment)}
            ${this.renderSuspicions(data.suspicions)}
            ${this.renderTabs(data)}
        `;

        this.attachHandlers();
    }

    /**
     * Verdict summary header: score ring + verdict + quick stats.
     */
    renderSummary(data) {
        const risk = data.risk_assessment || {};
        const level = risk.level || 'unknown';
        const score = Number.isFinite(risk.score) ? risk.score : 0;
        const verdict = risk.verdict || 'Unable to determine risk level';
        const fileName = (data.metadata && data.metadata.filename) || '';

        const urls = data.urls || {};
        const att = data.attachments || {};
        const routing = data.routing || {};
        const findings = (data.suspicions || []).length;

        const stat = (value, label, flag) => `
            <div class="stat">
                <span class="stat-value ${flag ? 'flag' : ''}">${this.escapeHtml(String(value))}</span>
                <span class="stat-label">${this.escapeHtml(label)}</span>
            </div>
        `;

        return `
            <div class="verdict-card ${this.escapeHtml(level)}">
                <div class="score-ring" style="--val:${score}">
                    <div class="score-ring-inner">
                        <span class="score-num">${score}</span>
                        <span class="score-den">/100</span>
                    </div>
                </div>
                <div class="verdict-body">
                    <span class="verdict-level">${this.escapeHtml(t(level))} ${this.escapeHtml(t('Risk'))}</span>
                    <div class="verdict-text">${this.escapeHtml(t(verdict))}</div>
                    ${fileName ? `<div class="verdict-file">${this.escapeHtml(fileName)}</div>` : ''}
                    <div class="quick-stats">
                        ${stat(`${urls.suspicious_count || 0}/${urls.total_count || 0}`, t('URLs'), (urls.suspicious_count || 0) > 0)}
                        ${stat(`${att.suspicious_count || 0}/${att.total_count || 0}`, t('Attachments'), (att.suspicious_count || 0) > 0)}
                        ${stat(findings, t('Findings'), findings > 0)}
                        ${stat(routing.hop_count || 0, t('Hops'), false)}
                    </div>
                    <div class="verdict-actions">
                        <button type="button" class="btn btn-secondary btn-sm analyze-another">${this.escapeHtml(t('Analyze another email'))}</button>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Conclusion card — the key "official artifacts", with copy + pivots.
     */
    renderConclusion(conclusion, artifacts) {
        if (!conclusion) return '';

        const a = artifacts || {};
        const server = a.sending_server || {};
        const enrichment = server.enrichment || {};
        const rdns = enrichment.reverse_dns || {};
        const intel = enrichment.ip_intel || {};
        const status = a.enrichment_status || {};

        // Each row says where its value came from. Without this the card reads
        // as seven equally solid facts, when most of them are attacker-controlled.
        const rows = [
            [t('Sender Address'), this.valueCell(conclusion.sender_address, { copy: true }), a.sender],
            [t('Subject Line'), this.valueCell(conclusion.subject, {}), a.subject],
            [t('Recipients'), this.valueCell(conclusion.recipients, {}), a.recipients],
            [t('Date + Time'), this.valueCell(conclusion.date, {}), a.date],
            [t('Sending Server IP'), this.valueCell(conclusion.sending_server_ip, { code: true, copy: true, ip: true }), server],
            [
                t('Reverse DNS of Sending Server'),
                this.valueCell(conclusion.reverse_dns, {
                    code: true, copy: true,
                    empty: this.missingReason(status.reverse_dns),
                }),
                a.reverse_dns,
            ],
            [t('Reply-To Address'), this.valueCell(conclusion.reply_to, { copy: true }), a.reply_to],
        ];

        const rowsHtml = rows.map(([label, cell, artifact]) => {
            const badge = artifact && artifact.trust ? ' ' + this.trustBadge(artifact.trust) : '';
            return `<tr><th>${this.escapeHtml(label)}</th><td>${cell}${badge}</td></tr>`;
        }).join('') + this.renderConclusionEnrichment(rdns, intel);

        return `
            <div class="result-card conclusion-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M9 11l3 3L22 4"/>
                        <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
                    </svg>
                    <h3 class="result-card-title">${t('Conclusion')}</h3>
                </div>
                <p class="conclusion-subtitle">${t('Official artifacts extracted from this email')}</p>
                <table class="data-table">${rowsHtml}</table>
            </div>
        `;
    }

    /**
     * FCrDNS and ASN sub-rows appended to the Conclusion table.
     */
    renderConclusionEnrichment(rdns, intel) {
        const rows = [];
        if (rdns.fcrdns) {
            const tone = rdns.fcrdns === 'pass' ? 'success'
                : rdns.fcrdns === 'fail' ? 'danger' : 'warning';
            rows.push(`<tr><th>${t('Forward-Confirmed rDNS')}</th><td>
                <span class="pill ${tone}">${this.escapeHtml(t(rdns.fcrdns))}</span>
                ${this.trustBadge('observed')}</td></tr>`);
        }
        if (rdns.ptr_matches_helo === false && rdns.ptr_name) {
            // Half observed, half claimed — shown, never scored.
            rows.push(`<tr><th>${t('HELO vs Reverse DNS')}</th><td>
                <span class="pill warning">${t('Mismatch')}</span>
                ${this.trustBadge('header_claim')}</td></tr>`);
        }
        if (intel.asn) {
            const name = intel.as_name ? ' ' + this.escapeHtml(intel.as_name) : '';
            rows.push(`<tr><th>${t('ASN')}</th><td><code>AS${this.escapeHtml(intel.asn)}</code>${name}
                ${this.trustBadge('observed')}</td></tr>`);
        }
        return rows.join('');
    }

    trustBadge(trust) {
        if (trust === 'observed') return `<span class="pill success">${t('Observed')}</span>`;
        if (trust === 'computed') return `<span class="pill info">${t('Computed')}</span>`;
        return `<span class="pill warning">${t('Header claim')}</span>`;
    }

    /**
     * Explain an empty enrichment value instead of leaving the analyst guessing.
     */
    missingReason(status) {
        switch (status) {
            case 'disabled': return t('Lookup disabled');
            case 'skipped_no_public_ip': return t('No public sending IP');
            case 'unavailable': return t('No data returned');
            case 'error': return t('Lookup failed');
            case 'timeout': return t('Lookup timed out');
            default: return t('N/A');
        }
    }

    /**
     * "Why this score" — the backend's ordered factor breakdown.
     */
    renderRiskFactors(risk) {
        const factors = (risk && Array.isArray(risk.factors)) ? risk.factors : [];

        let body;
        if (factors.length === 0) {
            body = `<div class="empty-state">${t('No scoring factors — no strong signals detected')}</div>`;
        } else {
            body = factors.map(f => {
                const pts = Number(f.points) || 0;
                const sign = pts < 0 ? 'sub' : 'add';
                const ptsLabel = `${pts > 0 ? '+' : ''}${pts} ${t('pts')}`;
                const severity = f.severity || 'info';
                return `
                    <div class="factor-item">
                        <span class="factor-dot ${this.escapeHtml(severity)}"></span>
                        <div class="factor-main">
                            <div class="factor-label">${this.escapeHtml(f.label || '')}</div>
                            ${f.detail ? `<div class="factor-detail">${this.escapeHtml(f.detail)}</div>` : ''}
                        </div>
                        <span class="factor-points ${sign}">${this.escapeHtml(ptsLabel)}</span>
                    </div>
                `;
            }).join('');
        }

        return `
            <div class="result-card factors-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="20" x2="18" y2="10"/>
                        <line x1="12" y1="20" x2="12" y2="4"/>
                        <line x1="6" y1="20" x2="6" y2="14"/>
                    </svg>
                    <h3 class="result-card-title">${t('Why this score')}</h3>
                </div>
                ${body}
            </div>
        `;
    }

    /**
     * Render suspicions list (severity-ordered)
     */
    renderSuspicions(suspicions) {
        if (!suspicions || suspicions.length === 0) {
            return '';
        }

        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        const sorted = [...suspicions].sort(
            (a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9)
        );

        const items = sorted.map(s => `
            <li class="suspicion-item ${this.escapeHtml(s.severity)}">
                <div class="suspicion-category">${this.escapeHtml(s.category)} <span class="pill ${this.escapeHtml(s.severity)}">${this.escapeHtml(t(s.severity))}</span></div>
                <div>${this.escapeHtml(s.message)}</div>
            </li>
        `).join('');

        return `
            <div class="result-card suspicions-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                    <h3 class="result-card-title">${t('Suspicious Indicators')} (${suspicions.length})</h3>
                </div>
                <ul class="suspicions-list">${items}</ul>
            </div>
        `;
    }

    /**
     * Artifacts tab — the parsed detail behind the Conclusion card.
     *
     * The Conclusion card shows each field as received; this shows what the
     * analyzer made of it, and which parts were checked against live DNS.
     */
    renderArtifacts(artifacts) {
        if (!artifacts || !artifacts.checklist) return '';

        const sender = artifacts.sender || {};
        const subject = artifacts.subject || {};
        const recipients = artifacts.recipients || {};
        const date = artifacts.date || {};
        const server = artifacts.sending_server || {};
        const intel = (server.enrichment || {}).ip_intel || {};
        const rdap = intel.rdap || {};
        const status = artifacts.enrichment_status || {};

        const rows = [];
        const row = (label, cell) => rows.push(
            `<tr><th>${this.escapeHtml(label)}</th><td>${cell}</td></tr>`
        );

        row(t('Sender Address'), this.valueCell(sender.address, { copy: true }));
        if (sender.display_name) {
            row(t('Display Name'), this.valueCell(sender.display_name, {}));
        }
        row(t('Sender Domain'), this.valueCell(sender.registered_domain, { copy: true, domain: true }));
        if (subject.charsets && subject.charsets.length) {
            row(t('Subject Charsets'), this.valueCell(subject.charsets.join(', '), { code: true }));
        }
        row(t('To'), this.valueCell(
            (recipients.to || []).map(r => r.address).filter(Boolean).join(', '), {}
        ));
        row(t('Cc'), this.valueCell(
            (recipients.cc || []).map(r => r.address).filter(Boolean).join(', '), {}
        ));
        if ((recipients.bcc_inferred || []).length) {
            row(t('Delivered via BCC'), this.valueCell(recipients.bcc_inferred.join(', '), {}));
        }
        row(t('Date (UTC)'), this.valueCell(date.utc, { code: true }));
        if (typeof date.skew_vs_oldest_received_seconds === 'number') {
            row(t('Skew vs First Hop'), this.valueCell(
                `${date.skew_vs_oldest_received_seconds}s`, { code: true }
            ));
        }
        row(t('Sending Server IP'), this.valueCell(server.ip, { code: true, copy: true, ip: true }));
        if (server.helo_claimed) {
            row(t('HELO Claimed'), this.valueCell(server.helo_claimed, { code: true }));
        }
        if (intel.bgp_prefix) {
            row(t('BGP Prefix'), this.valueCell(intel.bgp_prefix, { code: true }));
        }
        const country = intel.country || rdap.country;
        if (country) {
            row(t('Allocated To'), this.valueCell(
                intel.registry ? `${country} / ${intel.registry}` : country, {}
            ));
        }
        if (rdap.name) row(t('Network'), this.valueCell(rdap.name, {}));
        if (rdap.abuse_email) {
            // Plain text, never a mailto: link.
            row(t('Abuse Contact'), this.valueCell(rdap.abuse_email, { code: true, copy: true }));
        }

        const spf = (artifacts.authentication_advisory || {}).spf;
        const advisoryHtml = spf && spf.result ? `
            <table class="data-table" style="margin-top:0.75rem;">
                <tr><th>${t('Advisory SPF')}</th><td>
                    <span class="pill warning">${this.escapeHtml(t(spf.result))}</span>
                    <div class="muted" style="font-size:0.85em; margin-top:0.25rem;">
                        ${t('Advisory only - never trusted')}
                    </div>
                </td></tr>
            </table>` : '';

        const flags = artifacts.flags || [];
        const flagsHtml = flags.length ? `<div style="margin-top:0.75rem;">${
            flags.map(f => {
                const tone = f.severity === 'high' || f.severity === 'critical' ? 'danger'
                    : f.severity === 'medium' ? 'warning' : 'info';
                return `<span class="pill ${tone}">${this.escapeHtml(t(f.code))}</span>`;
            }).join(' ')
        }</div>` : '';

        const statusHtml = Object.keys(status).length ? `
            <p class="muted" style="margin-top:0.75rem; font-size:0.85em;">
                ${Object.entries(status).map(
                    ([k, v]) => `${this.escapeHtml(t(k))}: ${this.escapeHtml(t(v))}`
                ).join(' · ')}
            </p>` : '';

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                    <h3 class="result-card-title">${t('Artifacts')}</h3>
                </div>
                <table class="data-table">${rows.join('')}</table>
                ${advisoryHtml}
                ${flagsHtml}
                ${statusHtml}
                <p class="muted" style="margin-top:0.75rem; font-size:0.85em;">
                    ${t('Observed = checked live at analysis time. Header claim = read from the file and forgeable.')}
                </p>
            </div>
        `;
    }

    recipientSummary(recipients) {
        if (!recipients) return '';
        const parts = [];
        const to = (recipients.to || []).map(r => r.address).filter(Boolean);
        const cc = (recipients.cc || []).map(r => r.address).filter(Boolean);
        if (to.length) parts.push(to.join(', '));
        if (cc.length) parts.push(`${cc.length} ${t('in Cc')}`);
        if (recipients.undisclosed) parts.push(t('undisclosed'));
        if ((recipients.bcc_inferred || []).length) {
            parts.push(`${recipients.bcc_inferred.length} ${t('via BCC')}`);
        }
        return parts.join(' \u00b7 ');
    }

    /**
     * Plain-text artifact block for pasting into a ticket.
     */
    buildArtifactText(result) {
        const artifacts = (result || {}).artifacts;
        if (!artifacts || !artifacts.checklist) return '';

        const checklist = artifacts.checklist;
        const server = artifacts.sending_server || {};
        const intel = (server.enrichment || {}).ip_intel || {};
        const rdns = (server.enrichment || {}).reverse_dns || {};
        const risk = result.risk_assessment || {};
        const filename = (result.metadata || {}).filename || '';

        let reverse = checklist.reverse_dns || t('N/A');
        if (rdns.fcrdns) reverse += ` (FCrDNS: ${rdns.fcrdns})`;

        let asn = t('N/A');
        if (intel.asn) {
            asn = `AS${intel.asn}${intel.as_name ? ' ' + intel.as_name : ''}`;
            if (intel.bgp_prefix) asn += ` (${intel.bgp_prefix})`;
        }

        // Any value may itself contain a pipe - a subject line, or the
        // recipient summary - which would otherwise split the table row.
        const cell = (value) => String(value ?? '').replace(/\|/g, '\\|');

        const lines = [
            `## ${t('Artifacts')}${filename ? ' - ' + filename : ''}`,
            '',
            `| ${t('Field')} | ${t('Value')} |`,
            '|---|---|',
            `| ${t('Sender Address')} | ${cell(checklist.sender_address || t('N/A'))} |`,
            `| ${t('Subject Line')} | ${cell(checklist.subject || t('N/A'))} |`,
            `| ${t('Recipients')} | ${cell(this.recipientSummary(artifacts.recipients) || t('N/A'))} |`,
            `| ${t('Date + Time')} | ${cell(checklist.date_utc || t('N/A'))} |`,
            `| ${t('Sending Server IP')} | ${cell(checklist.sending_server_ip || t('N/A'))} |`,
            `| ${t('Reverse DNS')} | ${cell(reverse)} |`,
            `| ${t('Reply-To')} | ${cell(checklist.reply_to || t('N/A'))} |`,
            `| ${t('ASN')} | ${cell(asn)} |`,
            `| ${t('Risk')} | ${risk.level || '?'} ${risk.score !== undefined ? risk.score + '/100' : ''} |`,
        ];

        const flags = artifacts.flags || [];
        if (flags.length) {
            lines.push('', `${t('Flags')}: ` + flags.map(f => `${f.code} (${f.severity})`).join(', '));
        }

        const advisory = (artifacts.authentication_advisory || {}).spf;
        if (advisory && advisory.result) {
            lines.push(`${t('Advisory SPF')}: ${advisory.result} - ${t('Advisory only - never trusted')}`);
        }

        // The two artifacts the analyst still has to verify by hand. Without
        // them the exported block names the message but not the things the
        // next person has to act on.
        const attachmentList = ((result.attachments || {}).attachments) || [];
        if (attachmentList.length) {
            lines.push('', `### ${t('Attachments')}`);
            attachmentList.forEach(att => {
                const parts = [att.filename || t('N/A')];
                const size = att.size_formatted
                    || (att.size !== undefined ? `${att.size} bytes` : '');
                if (size) parts.push(size);
                parts.push(att.sha256 ? `SHA-256: ${att.sha256}` : t('N/A'));
                lines.push(`- ${parts.join(' | ')}`);
            });
        }

        // Defanged here, unlike the per-URL copy button. This block is pasted
        // into tickets and mail, which auto-link a raw URL and hand a live
        // phishing link to whoever reads it next.
        const urlList = ((result.urls || {}).urls) || [];
        if (urlList.length) {
            lines.push('', `### ${t('URLs')}`);
            urlList.forEach(url => {
                const issues = (url.issues || []).length
                    ? ` (${url.issues.join(', ')})`
                    : '';
                lines.push(`- ${this.defang(url.url)}${issues}`);
            });
            lines.push(t('URLs above are defanged - restore hxxp to http before use.'));
        }

        // Spell the trust split out: this text gets pasted somewhere the badges
        // and colours do not survive.
        lines.push(
            '',
            `${t('Header claims (forgeable, read from the uploaded file)')}: ` +
                'From, Subject, To/Cc, Date, Received IP, HELO, Reply-To',
            `${t('Observed (checked live at analysis time)')}: ` +
                'PTR, FCrDNS, ASN, RDAP'
        );
        return lines.join('\n');
    }

    /**
     * Detail tabs. Every panel is rendered into the DOM (hidden unless active)
     * so printing shows everything and nothing is lost on tab switch.
     */
    renderTabs(data) {
        const routingContent = `${this.renderRouting(data.routing)}${this.renderHeaderForensics(data.routing_forensics)}`;

        const tabs = [
            { label: t('Artifacts'), content: this.renderArtifacts(data.artifacts) },
            { label: t('Authentication'), content: this.renderAuthentication(data.authentication) },
            { label: t('Sender & IP'), content: this.renderSenderInfo(data.sender_info) },
            { label: t('Content Analysis'), content: this.renderContent(data.content) },
            { label: t('URLs'), count: (data.urls || {}).total_count, content: this.renderURLs(data.urls) },
            { label: t('Attachments'), count: (data.attachments || {}).total_count, content: this.renderAttachments(data.attachments) },
            { label: t('Routing'), content: routingContent },
            { label: t('Headers'), content: this.renderHeaders(data.headers) },
        ];

        const nav = tabs.map((tb, i) => `
            <button type="button" class="tab-btn ${i === 0 ? 'active' : ''}" data-tab="${i}">
                ${this.escapeHtml(tb.label)}
                ${typeof tb.count === 'number' ? `<span class="tab-count">${tb.count}</span>` : ''}
            </button>
        `).join('');

        const panels = tabs.map((tb, i) => {
            const content = (tb.content || '').trim() || `<div class="empty-state">${t('Nothing to show here')}</div>`;
            return `<div class="tab-panel ${i === 0 ? 'active' : ''}" data-tab="${i}">${content}</div>`;
        }).join('');

        return `<div class="tabs"><div class="tabs-nav">${nav}</div>${panels}</div>`;
    }

    /**
     * Render email headers
     */
    renderHeaders(headers) {
        if (!headers) return '';

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
                        <polyline points="22,6 12,13 2,6"/>
                    </svg>
                    <h3 class="result-card-title">${t('Email Headers')}</h3>
                </div>
                <table class="data-table">
                    <tr><th>${t('From')}</th><td>${this.escapeHtml(headers.sender || t('N/A'))}</td></tr>
                    <tr><th>${t('To / Cc')}</th><td>${this.escapeHtml(headers.recipients || t('N/A'))}</td></tr>
                    <tr><th>${t('Subject')}</th><td>${this.escapeHtml(headers.subject || t('N/A'))}</td></tr>
                    <tr><th>${t('Date')}</th><td>${this.escapeHtml(headers.date || t('N/A'))}</td></tr>
                    <tr><th>${t('Reply-To')}</th><td>${this.escapeHtml(headers.reply_to || t('N/A'))}</td></tr>
                    <tr><th>${t('Return-Path')}</th><td>${this.escapeHtml(headers.return_path || t('N/A'))}</td></tr>
                    <tr><th>${t('Message-ID')}</th><td><code>${this.escapeHtml(headers.message_id || t('N/A'))}</code></td></tr>
                </table>
            </div>
        `;
    }

    /**
     * Render authentication info
     */
    renderAuthentication(auth) {
        if (!auth) return '';

        const claims = auth.header_claims || auth.auth_analysis || {};
        const verification = auth.verification || {};
        const spfClaim = this.renderAuthPill('SPF', claims.spf, false);
        const dkimClaim = this.renderAuthPill('DKIM', claims.dkim, false);
        const dmarcClaim = this.renderAuthPill('DMARC', claims.dmarc, false);
        const verifiedDkim = this.renderAuthPill('DKIM', verification.dkim, true);
        // "not checked" reads like a gap in the tool. Alignment is a
        // comparison between the signing domain and the From domain, and it
        // is only meaningful once the signature itself validates -- so when
        // DKIM fails there is nothing to align, and saying so is the honest
        // answer rather than implying a step was skipped.
        const alignment = verification.dkim_alignment_relaxed
            || (verification.dkim === 'fail'
                ? t('not applicable - the signature did not validate')
                : t('not checked'));

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0110 0v4"/>
                    </svg>
                    <h3 class="result-card-title">${t('Authentication')}</h3>
                </div>
                <table class="data-table">
                    <tr><th>${t('Untrusted header claims')}</th><td>${spfClaim} ${dkimClaim} ${dmarcClaim}</td></tr>
                    <tr><th>${t('Independent verification')}</th><td>${verifiedDkim}</td></tr>
                    <tr><th>${t('DKIM alignment')}</th><td>${this.escapeHtml(alignment)}</td></tr>
                    <tr><th>SPF / DMARC</th><td class="muted">${t('SPF and DMARC cannot be verified from an uploaded file alone')}</td></tr>
                    <tr><th>${t('SPF Record')}</th><td>${auth.spf ? `<code>${this.escapeHtml(auth.spf)}</code>` : `<span class="muted">${t('Not found')}</span>`}</td></tr>
                    <tr><th>${t('DMARC Record')}</th><td>${auth.dmarc ? `<code>${this.escapeHtml(auth.dmarc)}</code>` : `<span class="muted">${t('Not found')}</span>`}</td></tr>
                    <tr><th>${t('DKIM Record')}</th><td>${auth.dkim ? `<code>${this.escapeHtml(auth.dkim)}</code>` : `<span class="muted">${t('Not found')}</span>`}</td></tr>
                </table>
            </div>
        `;
    }

    /**
     * Render authentication pill
     */
    renderAuthPill(name, result, trusted = false) {
        if (!result) {
            return `<span class="pill warning">${name}: none</span>`;
        }

        const passResults = ['pass', 'ok'];
        const failResults = ['fail', 'softfail', 'permerror'];

        let className = trusted ? 'warning' : 'info';
        if (trusted && passResults.includes(result)) className = 'success';
        else if (trusted && failResults.includes(result)) className = 'danger';

        return `<span class="pill ${className}">${name}: ${result}</span>`;
    }

    /**
     * Render sender info (with reverse DNS + investigation pivots)
     */
    renderSenderInfo(sender) {
        if (!sender) return '';

        const abuseScore = sender.abuse_report?.abuseConfidenceScore;
        let abusePill =
            `<span class="muted">${t('Requires an AbuseIPDB API key')}</span>`;

        if (abuseScore !== undefined) {
            const className = abuseScore >= 70 ? 'danger' : abuseScore > 0 ? 'warning' : 'success';
            abusePill = `<span class="pill ${className}">Score: ${abuseScore}%</span>`;
            if (sender.abuse_report) {
                abusePill += ` <span class="pill info">Reports: ${sender.abuse_report.totalReports || 0}</span>`;
            }
        }

        const whoisInfo = sender.whois ? `
            <span class="pill info">${this.escapeHtml(sender.whois.registrar || t('Unknown'))}</span>
            <span class="pill">Created: ${this.escapeHtml(sender.whois.creation_date || t('Unknown'))}</span>
        ` : `<span class="muted">${t('Not available')}</span>`;

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="2" y1="12" x2="22" y2="12"/>
                        <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>
                    </svg>
                    <h3 class="result-card-title">${t('Sender Information')}</h3>
                </div>
                <table class="data-table">
                    <tr><th>${t('Domain')}</th><td>${this.valueCell(sender.domain, { copy: true, domain: true })}</td></tr>
                    <tr><th>${t('Sender IP')}</th><td>${this.valueCell(sender.ip, { code: true, copy: true, ip: true, empty: t('Not found') })}</td></tr>
                    <tr><th>${t('Reverse DNS')}</th><td>${this.valueCell(sender.reverse_dns, { code: true, copy: true, empty: t('Not found') })}</td></tr>
                    <tr><th>${t('IP Reputation')}</th><td>${abusePill}</td></tr>
                    <tr><th>${t('WHOIS')}</th><td>${whoisInfo}</td></tr>
                </table>
            </div>
        `;
    }

    /**
     * Render content analysis
     */
    renderContent(content) {
        if (!content) return '';

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                        <polyline points="14,2 14,8 20,8"/>
                        <line x1="16" y1="13" x2="8" y2="13"/>
                        <line x1="16" y1="17" x2="8" y2="17"/>
                    </svg>
                    <h3 class="result-card-title">${t('Content Analysis')}</h3>
                </div>
                <table class="data-table">
                    <tr><th>${t('Urgent Phrases')}</th><td>${this.renderList(content.urgent_phrases)}</td></tr>
                    <tr><th>${t('Generic Greetings')}</th><td>${this.renderList(content.generic_greetings)}</td></tr>
                    <tr><th>${t('Credential Requests')}</th><td>${this.renderList(content.credential_requests)}</td></tr>
                    <tr><th>${t('HTML Forms')}</th><td>${content.forms || 0}</td></tr>
                    <tr><th>${t('Scripts')}</th><td>${content.scripts || 0}</td></tr>
                    <tr><th>${t('Hidden Elements')}</th><td>${content.hidden_elements || 0}</td></tr>
                    <tr><th>${t('YARA Matches')}</th><td>${this.renderList(content.yara_matches)}</td></tr>
                </table>
            </div>
        `;
    }

    /**
     * Render URLs
     */
    renderURLs(urls) {
        if (!urls || urls.total_count === 0) {
            return `
                <div class="result-card">
                    <div class="result-card-header">
                        <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/>
                            <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>
                        </svg>
                        <h3 class="result-card-title">${t('URLs')} (0)</h3>
                    </div>
                    <div class="empty-state">${t('No URLs found in email')}</div>
                </div>
            `;
        }

        const urlItems = urls.urls.map(url => `
            <div class="url-item ${url.is_suspicious ? 'suspicious' : ''}">
                <div class="url-link">${this.escapeHtml(this.defang(url.url))}</div>
                <div class="url-domain">${t('Domain')}: ${this.escapeHtml(this.defang(url.domain))}</div>
                ${url.issues && url.issues.length > 0 ? `
                    <div class="url-issues">
                        ${url.issues.map(issue => `<span class="pill danger">${this.escapeHtml(issue)}</span>`).join('')}
                    </div>` : ''}
                <div class="value-actions">${this.copyBtn(url.url)}</div>
            </div>
        `).join('');

        // One click to take every URL into a sandbox queue. Raw, not defanged:
        // this is the clipboard, and the destination is a tool that needs the
        // real thing.
        const allUrls = urls.urls.map(u => u.url).filter(Boolean).join('\n');

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/>
                        <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>
                    </svg>
                    <h3 class="result-card-title">${t('URLs')} (${urls.total_count} ${t('found')}, ${urls.suspicious_count} ${t('suspicious')})</h3>
                    ${allUrls ? `<div class="card-actions">${this.copyBtn(allUrls, t('Copy all URLs'))}</div>` : ''}
                </div>
                <div class="defang-note">${t('Shown defanged so nobody clicks one by accident. Copy gives the real URL.')}</div>
                <div class="url-list">${urlItems}</div>
            </div>
        `;
    }

    /**
     * Render attachments (hash copy only - see the module note on pivots)
     */
    renderAttachments(attachments) {
        if (!attachments || attachments.total_count === 0) {
            return `
                <div class="result-card">
                    <div class="result-card-header">
                        <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/>
                        </svg>
                        <h3 class="result-card-title">${t('Attachments')} (0)</h3>
                    </div>
                    <div class="empty-state">${t('No attachments found')}</div>
                </div>
            `;
        }

        // Every hash in one click, for pasting into VirusTotal or a sandbox.
        const allHashes = attachments.attachments
            .map(a => a.sha256).filter(Boolean).join('\n');

        const attItems = attachments.attachments.map(att => `
            <div class="attachment-item ${att.is_suspicious ? 'suspicious' : ''}">
                <div class="attachment-info">
                    <div class="attachment-name">${this.escapeHtml(att.filename)}</div>
                    <div class="attachment-meta">
                        ${this.escapeHtml(att.content_type || t('Unknown type'))} |
                        ${this.escapeHtml(att.size_formatted || att.size + ' bytes')}
                    </div>
                    ${att.issues && att.issues.length > 0 ? `
                        <div class="url-issues" style="margin-top: 0.5rem;">
                            ${att.issues.map(issue => `<span class="pill danger">${this.escapeHtml(issue)}</span>`).join('')}
                        </div>` : ''}
                    ${att.sha256 ? `<div class="value-actions">${this.copyBtn(att.sha256)}</div>` : ''}
                </div>
                ${att.severity && att.is_suspicious ? `<span class="attachment-severity ${this.escapeHtml(att.severity)}">${this.escapeHtml(t(att.severity))}</span>` : ''}
            </div>
        `).join('');

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/>
                    </svg>
                    <h3 class="result-card-title">${t('Attachments')} (${attachments.total_count} ${t('found')}, ${attachments.suspicious_count} ${t('suspicious')})</h3>
                    ${allHashes ? `<div class="card-actions">${this.copyBtn(allHashes, t('Copy all hashes'))}</div>` : ''}
                </div>
                <div class="attachment-list">${attItems}</div>
            </div>
        `;
    }

    /**
     * Render routing/hops
     */
    renderRouting(routing) {
        if (!routing || !routing.hops || routing.hops.length === 0) {
            return '';
        }

        const hopItems = routing.hops.map((hop, index) => `
            <div class="hop-item">${t('Hop')} ${index + 1}: ${this.escapeHtml(hop)}</div>
        `).join('');

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="12" y1="2" x2="12" y2="6"/>
                        <line x1="12" y1="18" x2="12" y2="22"/>
                        <line x1="2" y1="12" x2="6" y2="12"/>
                        <line x1="18" y1="12" x2="22" y2="12"/>
                    </svg>
                    <h3 class="result-card-title">${t('Email Routing')} (${routing.hop_count} ${t('hops')})</h3>
                </div>
                <div class="hops-list">${hopItems}</div>
            </div>
        `;
    }

    /**
     * Render header forensics card
     */
    renderHeaderForensics(forensics) {
        if (!forensics || forensics.hop_count === 0) return '';

        const ipBadges = forensics.public_ips && forensics.public_ips.length > 0
            ? forensics.public_ips.map(ip => `<span class="pill info">${this.escapeHtml(ip)}</span>`).join(' ')
            : `<span class="muted">${t('Not detected')}</span>`;

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                    </svg>
                    <h3 class="result-card-title">${t('Header Forensics')}</h3>
                </div>
                <table class="data-table">
                    <tr><th>${t('Hop Count')}</th><td>${forensics.hop_count}</td></tr>
                    <tr><th>${t('Originating IP')}</th><td>${this.valueCell(forensics.originating_ip, { code: true, copy: true, ip: true, empty: t('Not detected') })}</td></tr>
                    <tr><th>${t('Sender Timezone')}</th><td>${forensics.timezone_offset ? `<code>${this.escapeHtml(forensics.timezone_offset)}</code>` : `<span class="muted">${t('Not found')}</span>`}</td></tr>
                    <tr><th>${t('Public IPs in Route')}</th><td>${ipBadges}</td></tr>
                </table>
            </div>
        `;
    }

    /**
     * Render a value cell with optional copy button and lookup links.
     */
    valueCell(value, opts = {}) {
        const has = value !== null && value !== undefined && String(value).trim() !== '';
        if (!has) {
            return `<span class="muted">${this.escapeHtml(opts.empty || t('N/A'))}</span>`;
        }

        const v = String(value);
        const display = opts.code
            ? `<code>${this.escapeHtml(v)}</code>`
            : this.escapeHtml(v);

        const actions = [];
        if (opts.copy) actions.push(this.copyBtn(v));
        if (opts.ip) {
            actions.push(this.extBtn(`https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}`, 'VirusTotal'));
            actions.push(this.extBtn(`https://www.abuseipdb.com/check/${encodeURIComponent(v)}`, 'AbuseIPDB'));
        }
        if (opts.domain) {
            actions.push(this.extBtn(`https://www.virustotal.com/gui/domain/${encodeURIComponent(v)}`, 'VirusTotal'));
        }

        const actionsHtml = actions.length ? `<div class="value-actions">${actions.join('')}</div>` : '';
        return `${display}${actionsHtml}`;
    }

    copyBtn(value, label) {
        return `<button type="button" class="mini-btn copy-btn" data-copy="${this.escapeAttr(String(value))}">⧉ ${this.escapeHtml(label || t('Copy'))}</button>`;
    }

    /**
     * Defang a URL for display: hxxp://evil[.]com/path
     *
     * The UI never renders a URL as an anchor, but the same string travels
     * into the exported artifact block and the printed report — and a ticket
     * system or mail client will happily turn it back into a live link for
     * the next person to click. Only the scheme and hostname are altered, so
     * the path stays readable.
     *
     * Display only. Copy buttons carry the real URL, because the whole point
     * of copying one is to paste it into a sandbox.
     */
    defang(value) {
        // Deliberately regex-free. The input is a URL lifted out of a hostile
        // email, and the obvious pattern here -- scheme, then a greedy
        // host class, then a greedy remainder -- puts two unbounded
        // quantifiers with overlapping character classes next to each other,
        // which is the shape CodeQL flags as polynomial ReDoS on untrusted
        // input. Index arithmetic is linear and has no such failure mode.
        const raw = String(value || '');
        if (!raw) return '';

        const dotted = (text) => text.split('.').join('[.]');

        const sep = raw.indexOf('://');
        if (sep === -1) return dotted(raw);

        const scheme = raw.slice(0, sep).toLowerCase();
        if (scheme !== 'http' && scheme !== 'https') return dotted(raw);

        const rest = raw.slice(sep + 3);
        // The authority ends at the first '/', '?' or '#'; whichever comes
        // first. Everything after it is path/query/fragment and stays intact
        // so the URL is still readable.
        let end = rest.length;
        for (const mark of ['/', '?', '#']) {
            const at = rest.indexOf(mark);
            if (at !== -1 && at < end) end = at;
        }
        const defanged = scheme === 'https' ? 'hxxps' : 'hxxp';
        return `${defanged}://${dotted(rest.slice(0, end))}${rest.slice(end)}`;
    }

    extBtn(href, label) {
        return `<a class="mini-btn" href="${this.escapeAttr(href)}" target="_blank" rel="noopener noreferrer">↗ ${this.escapeHtml(label)}</a>`;
    }

    /**
     * Wire up tab switching, copy buttons, and the "analyze another" shortcut.
     */
    attachHandlers() {
        const root = this.container;
        if (!root) return;

        root.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const idx = btn.getAttribute('data-tab');
                root.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b === btn));
                root.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.getAttribute('data-tab') === idx));
            });
        });

        root.querySelectorAll('.copy-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const val = btn.getAttribute('data-copy') || '';
                await this.copyToClipboard(val);
                const original = btn.innerHTML;
                btn.classList.add('copied');
                btn.textContent = `✓ ${t('Copied')}`;
                setTimeout(() => {
                    btn.classList.remove('copied');
                    btn.innerHTML = original;
                }, 1400);
            });
        });

        const another = root.querySelector('.analyze-another');
        if (another) {
            another.addEventListener('click', () => {
                const drop = document.getElementById('dropZone');
                const input = document.getElementById('fileInput');
                if (drop) drop.scrollIntoView({ behavior: 'smooth', block: 'center' });
                if (input) input.click();
            });
        }
    }

    async copyToClipboard(text) {
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                return;
            }
        } catch (e) { /* fall through to legacy path */ }

        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (e) { /* ignore */ }
        document.body.removeChild(ta);
    }

    /**
     * Render list of items
     */
    renderList(items) {
        if (!items || items.length === 0) {
            return `<span class="muted">${t('None')}</span>`;
        }
        return items.map(item => `<span class="pill warning">${this.escapeHtml(item)}</span>`).join(' ');
    }

    /**
     * Escape HTML text content
     */
    escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }

    /**
     * Escape a value for safe use inside a double-quoted HTML attribute
     */
    escapeAttr(text) {
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    /**
     * Render error
     */
    renderError(error) {
        this.container.innerHTML = `
            <div class="result-card" style="border-color: var(--danger);">
                <h3>${t('Error')}</h3>
                <p>${this.escapeHtml(error)}</p>
            </div>
        `;
    }
}

// Create global results renderer instance
window.resultsRenderer = new ResultsRenderer('#resultsSection');
