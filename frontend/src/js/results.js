/**
 * Results Renderer
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

        const html = `
            ${this.renderRiskBanner(data.risk_assessment)}
            ${this.renderSuspicions(data.suspicions)}
            <div class="results-grid">
                ${this.renderArtifacts(data.artifacts)}
                ${this.renderHeaders(data.headers)}
                ${this.renderAuthentication(data.authentication)}
                ${this.renderSenderInfo(data.sender_info)}
                ${this.renderContent(data.content)}
                ${this.renderURLs(data.urls)}
                ${this.renderAttachments(data.attachments)}
                ${this.renderRouting(data.routing)}
                ${this.renderHeaderForensics(data.routing_forensics)}
            </div>
        `;

        this.container.innerHTML = html;
    }

    /**
     * Render risk assessment banner
     */
    renderRiskBanner(risk) {
        if (!risk) return '';

        const level = risk.level || 'unknown';
        const score = risk.score || 0;
        const verdict = risk.verdict || 'Unable to determine risk level';

        return `
            <div class="risk-banner ${level}">
                <div class="risk-level">${this.escapeHtml(t(level))} ${this.escapeHtml(t('Risk'))}</div>
                <div class="risk-score">${score}/100</div>
                <div class="risk-verdict">${this.escapeHtml(t(verdict))}</div>
            </div>
        `;
    }

    /**
     * Render suspicions list
     */
    renderSuspicions(suspicions) {
        if (!suspicions || suspicions.length === 0) {
            return '';
        }

        const items = suspicions.map(s => `
            <li class="suspicion-item ${s.severity}">
                <div class="suspicion-category">${this.escapeHtml(s.category)} <span class="pill ${s.severity}">${this.escapeHtml(t(s.severity))}</span></div>
                <div>${this.escapeHtml(s.message)}</div>
            </li>
        `).join('');

        return `
            <div class="result-card">
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
                    <tr>
                        <th>${t('From')}</th>
                        <td>${this.escapeHtml(headers.sender || t('N/A'))}</td>
                    </tr>
                    <tr>
                        <th>${t('To / Cc')}</th>
                        <td>${this.escapeHtml(headers.recipients || t('N/A'))}</td>
                    </tr>
                    <tr>
                        <th>${t('Subject')}</th>
                        <td>${this.escapeHtml(headers.subject || t('N/A'))}</td>
                    </tr>
                    <tr>
                        <th>${t('Date')}</th>
                        <td>${this.escapeHtml(headers.date || t('N/A'))}</td>
                    </tr>
                    <tr>
                        <th>${t('Reply-To')}</th>
                        <td>${this.escapeHtml(headers.reply_to || t('N/A'))}</td>
                    </tr>
                    <tr>
                        <th>${t('Return-Path')}</th>
                        <td>${this.escapeHtml(headers.return_path || t('N/A'))}</td>
                    </tr>
                    <tr>
                        <th>${t('Message-ID')}</th>
                        <td><code>${this.escapeHtml(headers.message_id || t('N/A'))}</code></td>
                    </tr>
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
        const alignment = verification.dkim_alignment_relaxed || 'not checked';

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
                    <tr>
                        <th>${t('Untrusted header claims')}</th>
                        <td>${spfClaim} ${dkimClaim} ${dmarcClaim}</td>
                    </tr>
                    <tr>
                        <th>${t('Independent verification')}</th>
                        <td>${verifiedDkim}</td>
                    </tr>
                    <tr>
                        <th>${t('DKIM alignment')}</th>
                        <td>${this.escapeHtml(alignment)}</td>
                    </tr>
                    <tr>
                        <th>SPF / DMARC</th>
                        <td class="muted">${t('SPF and DMARC cannot be verified from an uploaded file alone')}</td>
                    </tr>
                    <tr>
                        <th>${t('SPF Record')}</th>
                        <td>${auth.spf ? `<code>${this.escapeHtml(auth.spf)}</code>` : `<span class="muted">${t('Not found')}</span>`}</td>
                    </tr>
                    <tr>
                        <th>${t('DMARC Record')}</th>
                        <td>${auth.dmarc ? `<code>${this.escapeHtml(auth.dmarc)}</code>` : `<span class="muted">${t('Not found')}</span>`}</td>
                    </tr>
                    <tr>
                        <th>${t('DKIM Record')}</th>
                        <td>${auth.dkim ? `<code>${this.escapeHtml(auth.dkim)}</code>` : `<span class="muted">${t('Not found')}</span>`}</td>
                    </tr>
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
        const warnResults = ['none', 'neutral', 'temperror'];
        const failResults = ['fail', 'softfail', 'permerror'];

        let className = trusted ? 'warning' : 'info';
        if (trusted && passResults.includes(result)) className = 'success';
        else if (trusted && failResults.includes(result)) className = 'danger';

        return `<span class="pill ${className}">${name}: ${result}</span>`;
    }

    /**
     * Render sender info
     */
    renderSenderInfo(sender) {
        if (!sender) return '';

        const abuseScore = sender.abuse_report?.abuseConfidenceScore;
        let abusePill = `<span class="muted">${t('Not checked')}</span>`;

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
                    <tr>
                        <th>${t('Domain')}</th>
                        <td>${this.escapeHtml(sender.domain || t('N/A'))}</td>
                    </tr>
                    <tr>
                        <th>${t('Sender IP')}</th>
                        <td>${this.escapeHtml(sender.ip || t('Not found'))}</td>
                    </tr>
                    <tr>
                        <th>${t('IP Reputation')}</th>
                        <td>${abusePill}</td>
                    </tr>
                    <tr>
                        <th>${t('WHOIS')}</th>
                        <td>${whoisInfo}</td>
                    </tr>
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
                        <polyline points="10,9 9,9 8,9"/>
                    </svg>
                    <h3 class="result-card-title">${t('Content Analysis')}</h3>
                </div>
                <table class="data-table">
                    <tr>
                        <th>${t('Urgent Phrases')}</th>
                        <td>${this.renderList(content.urgent_phrases)}</td>
                    </tr>
                    <tr>
                        <th>${t('Generic Greetings')}</th>
                        <td>${this.renderList(content.generic_greetings)}</td>
                    </tr>
                    <tr>
                        <th>${t('Credential Requests')}</th>
                        <td>${this.renderList(content.credential_requests)}</td>
                    </tr>
                    <tr>
                        <th>${t('HTML Forms')}</th>
                        <td>${content.forms || 0}</td>
                    </tr>
                    <tr>
                        <th>${t('Scripts')}</th>
                        <td>${content.scripts || 0}</td>
                    </tr>
                    <tr>
                        <th>${t('Hidden Elements')}</th>
                        <td>${content.hidden_elements || 0}</td>
                    </tr>
                    <tr>
                        <th>${t('YARA Matches')}</th>
                        <td>${this.renderList(content.yara_matches)}</td>
                    </tr>
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
                <div class="url-link">${this.escapeHtml(url.url)}</div>
                <div class="url-domain">${t('Domain')}: ${this.escapeHtml(url.domain)}</div>
                ${url.issues.length > 0 ? `
                    <div class="url-issues">
                        ${url.issues.map(issue => `<span class="pill danger">${this.escapeHtml(issue)}</span>`).join('')}
                    </div>
                ` : ''}
            </div>
        `).join('');

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/>
                        <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>
                    </svg>
                    <h3 class="result-card-title">${t('URLs')} (${urls.total_count} ${t('found')}, ${urls.suspicious_count} ${t('suspicious')})</h3>
                </div>
                <div class="url-list">${urlItems}</div>
            </div>
        `;
    }

    /**
     * Render attachments
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

        const attItems = attachments.attachments.map(att => `
            <div class="attachment-item ${att.is_suspicious ? 'suspicious' : ''}">
                <div class="attachment-info">
                    <div class="attachment-name">${this.escapeHtml(att.filename)}</div>
                    <div class="attachment-meta">
                        ${this.escapeHtml(att.content_type || t('Unknown type'))} |
                        ${this.escapeHtml(att.size_formatted || att.size + ' bytes')}
                    </div>
                    ${att.issues.length > 0 ? `
                        <div class="url-issues" style="margin-top: 0.5rem;">
                            ${att.issues.map(issue => `<span class="pill danger">${this.escapeHtml(issue)}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
                ${att.severity && att.is_suspicious ? `
                    <span class="attachment-severity ${att.severity}">${this.escapeHtml(t(att.severity))}</span>
                ` : ''}
            </div>
        `).join('');

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/>
                    </svg>
                    <h3 class="result-card-title">${t('Attachments')} (${attachments.total_count} ${t('found')}, ${attachments.suspicious_count} ${t('suspicious')})</h3>
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
                        <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/>
                        <line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/>
                        <line x1="2" y1="12" x2="6" y2="12"/>
                        <line x1="18" y1="12" x2="22" y2="12"/>
                        <line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/>
                        <line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/>
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
                    <tr>
                        <th>${t('Hop Count')}</th>
                        <td>${forensics.hop_count}</td>
                    </tr>
                    <tr>
                        <th>${t('Originating IP')}</th>
                        <td>${forensics.originating_ip ? `<code>${this.escapeHtml(forensics.originating_ip)}</code>` : `<span class="muted">${t('Not detected')}</span>`}</td>
                    </tr>
                    <tr>
                        <th>${t('Sender Timezone')}</th>
                        <td>${forensics.timezone_offset ? `<code>${this.escapeHtml(forensics.timezone_offset)}</code>` : `<span class="muted">${t('Not found')}</span>`}</td>
                    </tr>
                    <tr>
                        <th>${t('Public IPs in Route')}</th>
                        <td>${ipBadges}</td>
                    </tr>
                </table>
            </div>
        `;
    }

    /**
     * Render the analyst triage checklist and its live enrichment.
     *
     * Every row shows where its value came from: a claim read out of the
     * uploaded file, a property computed from that claim, or a fact observed
     * from a live lookup. The distinction is the point of the card.
     */
    renderArtifacts(artifacts) {
        if (!artifacts || !artifacts.checklist) return '';

        const server = artifacts.sending_server || {};
        const enrichment = server.enrichment || {};
        const rdns = enrichment.reverse_dns || {};
        const intel = enrichment.ip_intel || {};
        const status = artifacts.enrichment_status || {};

        const rows = [
            this.artifactRow('Sender Address', artifacts.sender, artifacts.sender?.address),
            this.artifactRow('Subject Line', artifacts.subject, artifacts.subject?.value),
            this.artifactRow('Recipients', artifacts.recipients, this.recipientSummary(artifacts.recipients)),
            this.artifactRow('Date + Time', artifacts.date, this.dateSummary(artifacts.date)),
            this.artifactRow('Sending Server IP', server, server.ip),
            this.artifactRow('Reverse DNS', artifacts.reverse_dns, artifacts.reverse_dns?.value, status.reverse_dns),
            this.artifactRow('Reply-To', artifacts.reply_to, artifacts.reply_to?.address),
        ].join('');

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                    <h3 class="result-card-title">${t('Artifacts')}</h3>
                </div>
                <table class="data-table">${rows}</table>
                ${this.renderArtifactEnrichment(rdns, intel, status)}
                ${this.renderAdvisorySpf(artifacts.authentication_advisory)}
                ${this.renderArtifactFlags(artifacts.flags)}
                <p class="muted" style="margin-top:0.75rem; font-size:0.85em;">
                    ${t('Observed = checked live at analysis time. Header claim = read from the file and forgeable.')}
                </p>
            </div>
        `;
    }

    /**
     * One checklist row: label, value, trust badge.
     */
    artifactRow(label, artifact, value, statusOverride) {
        const trust = artifact && artifact.trust ? artifact.trust : 'header_claim';
        let cell;
        if (value) {
            cell = `<code>${this.escapeHtml(String(value))}</code> ${this.trustBadge(trust)}`;
        } else {
            cell = `<span class="muted">${this.escapeHtml(this.missingReason(statusOverride))}</span>`;
        }
        return `<tr><th>${t(label)}</th><td>${cell}</td></tr>`;
    }

    /**
     * Explain an empty value instead of leaving the analyst guessing.
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

    trustBadge(trust) {
        if (trust === 'observed') {
            return `<span class="pill success">${t('Observed')}</span>`;
        }
        if (trust === 'computed') {
            return `<span class="pill info">${t('Computed')}</span>`;
        }
        return `<span class="pill warning">${t('Header claim')}</span>`;
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
        return parts.join(' · ');
    }

    dateSummary(date) {
        if (!date || !date.utc) return '';
        const offset = this.formatOffset(date.offset_minutes);
        return offset ? `${date.utc} (${offset})` : date.utc;
    }

    formatOffset(minutes) {
        if (minutes === null || minutes === undefined) return '';
        const sign = minutes < 0 ? '-' : '+';
        const abs = Math.abs(minutes);
        const hh = String(Math.floor(abs / 60)).padStart(2, '0');
        const mm = String(abs % 60).padStart(2, '0');
        return `${sign}${hh}${mm}`;
    }

    /**
     * Reverse-DNS and ASN detail for the sending IP.
     */
    renderArtifactEnrichment(rdns, intel, status) {
        const rows = [];

        if (rdns.fcrdns) {
            const tone = rdns.fcrdns === 'pass' ? 'success'
                : rdns.fcrdns === 'fail' ? 'danger' : 'warning';
            rows.push(`<tr><th>${t('Forward-Confirmed rDNS')}</th><td>
                <span class="pill ${tone}">${this.escapeHtml(t(rdns.fcrdns))}</span></td></tr>`);
        }
        if (rdns.ptr_matches_helo === false && rdns.ptr_name) {
            // Half observed, half claimed: shown, never scored.
            rows.push(`<tr><th>${t('HELO vs Reverse DNS')}</th><td>
                <span class="pill warning">${t('Mismatch')}</span>
                ${this.trustBadge('header_claim')}</td></tr>`);
        }
        if (intel.asn) {
            const name = intel.as_name ? ` ${this.escapeHtml(intel.as_name)}` : '';
            rows.push(`<tr><th>${t('ASN')}</th><td><code>AS${this.escapeHtml(intel.asn)}</code>${name}
                ${this.trustBadge('observed')}</td></tr>`);
        }
        if (intel.bgp_prefix) {
            rows.push(`<tr><th>${t('BGP Prefix')}</th><td><code>${this.escapeHtml(intel.bgp_prefix)}</code></td></tr>`);
        }
        const country = intel.country || (intel.rdap || {}).country;
        if (country) {
            const registry = intel.registry ? ` / ${this.escapeHtml(intel.registry)}` : '';
            rows.push(`<tr><th>${t('Allocated To')}</th><td>${this.escapeHtml(country)}${registry}</td></tr>`);
        }
        const rdap = intel.rdap || {};
        if (rdap.name) {
            rows.push(`<tr><th>${t('Network')}</th><td>${this.escapeHtml(rdap.name)}</td></tr>`);
        }
        if (rdap.abuse_email) {
            // Deliberately plain text, not a mailto: link.
            rows.push(`<tr><th>${t('Abuse Contact')}</th><td><code>${this.escapeHtml(rdap.abuse_email)}</code></td></tr>`);
        }

        if (!rows.length) {
            if (status.ip_intel === 'disabled' && status.reverse_dns === 'disabled') return '';
            return `<p class="muted" style="margin-top:0.75rem;">${this.escapeHtml(t('No enrichment data available'))}</p>`;
        }
        return `<table class="data-table" style="margin-top:0.75rem;">${rows.join('')}</table>`;
    }

    /**
     * Advisory SPF. Never rendered as a success, whatever the result.
     */
    renderAdvisorySpf(advisory) {
        const spf = advisory && advisory.spf;
        if (!spf || !spf.result) return '';
        return `
            <table class="data-table" style="margin-top:0.75rem;">
                <tr>
                    <th>${t('Advisory SPF')}</th>
                    <td>
                        <span class="pill warning">${this.escapeHtml(t(spf.result))}</span>
                        <div class="muted" style="font-size:0.85em; margin-top:0.25rem;">
                            ${t('Advisory only - never trusted')}
                        </div>
                    </td>
                </tr>
            </table>
        `;
    }

    renderArtifactFlags(flags) {
        if (!flags || !flags.length) return '';
        const pills = flags.map(flag => {
            const tone = flag.severity === 'high' || flag.severity === 'critical' ? 'danger'
                : flag.severity === 'medium' ? 'warning' : 'info';
            return `<span class="pill ${tone}">${this.escapeHtml(t(flag.code))}</span>`;
        }).join(' ');
        return `<div style="margin-top:0.75rem;">${pills}</div>`;
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
            `| ${t('Date + Time')} | ${cell(this.dateSummary(artifacts.date) || t('N/A'))} |`,
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
     * Render list of items
     */
    renderList(items) {
        if (!items || items.length === 0) {
            return `<span class="muted">${t('None')}</span>`;
        }
        return items.map(item => `<span class="pill warning">${this.escapeHtml(item)}</span>`).join(' ');
    }

    /**
     * Escape HTML
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Render error
     */
    renderError(error) {
        this.container.innerHTML = `
            <div class="result-card" style="background: rgba(239, 68, 68, 0.1); border-color: var(--color-danger);">
                <h3>${t('Error')}</h3>
                <p>${this.escapeHtml(error)}</p>
            </div>
        `;
    }
}

// Create global results renderer instance
window.resultsRenderer = new ResultsRenderer('#resultsSection');
