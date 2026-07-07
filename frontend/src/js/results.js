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
                <div class="risk-level">${level} Risk</div>
                <div class="risk-score">${score}/100</div>
                <div class="risk-verdict">${this.escapeHtml(verdict)}</div>
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
                <div class="suspicion-category">${this.escapeHtml(s.category)}</div>
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
                    <h3 class="result-card-title">Suspicious Indicators (${suspicions.length})</h3>
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
                    <h3 class="result-card-title">Email Headers</h3>
                </div>
                <table class="data-table">
                    <tr>
                        <th>From</th>
                        <td>${this.escapeHtml(headers.sender || 'N/A')}</td>
                    </tr>
                    <tr>
                        <th>To / Cc</th>
                        <td>${this.escapeHtml(headers.recipients || 'N/A')}</td>
                    </tr>
                    <tr>
                        <th>Subject</th>
                        <td>${this.escapeHtml(headers.subject || 'N/A')}</td>
                    </tr>
                    <tr>
                        <th>Date</th>
                        <td>${this.escapeHtml(headers.date || 'N/A')}</td>
                    </tr>
                    <tr>
                        <th>Reply-To</th>
                        <td>${this.escapeHtml(headers.reply_to || 'N/A')}</td>
                    </tr>
                    <tr>
                        <th>Return-Path</th>
                        <td>${this.escapeHtml(headers.return_path || 'N/A')}</td>
                    </tr>
                    <tr>
                        <th>Message-ID</th>
                        <td><code>${this.escapeHtml(headers.message_id || 'N/A')}</code></td>
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

        const spfPill = this.renderAuthPill('SPF', auth.auth_analysis?.spf);
        const dkimPill = this.renderAuthPill('DKIM', auth.auth_analysis?.dkim);
        const dmarcPill = this.renderAuthPill('DMARC', auth.auth_analysis?.dmarc);

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0110 0v4"/>
                    </svg>
                    <h3 class="result-card-title">Authentication</h3>
                </div>
                <table class="data-table">
                    <tr>
                        <th>Results</th>
                        <td>${spfPill} ${dkimPill} ${dmarcPill}</td>
                    </tr>
                    <tr>
                        <th>SPF Record</th>
                        <td>${auth.spf ? `<code>${this.escapeHtml(auth.spf)}</code>` : '<span class="muted">Not found</span>'}</td>
                    </tr>
                    <tr>
                        <th>DMARC Record</th>
                        <td>${auth.dmarc ? `<code>${this.escapeHtml(auth.dmarc)}</code>` : '<span class="muted">Not found</span>'}</td>
                    </tr>
                    <tr>
                        <th>DKIM Record</th>
                        <td>${auth.dkim ? `<code>${this.escapeHtml(auth.dkim)}</code>` : '<span class="muted">Not found</span>'}</td>
                    </tr>
                </table>
            </div>
        `;
    }

    /**
     * Render authentication pill
     */
    renderAuthPill(name, result) {
        if (!result) {
            return `<span class="pill warning">${name}: none</span>`;
        }

        const passResults = ['pass', 'ok'];
        const warnResults = ['none', 'neutral', 'temperror'];
        const failResults = ['fail', 'softfail', 'permerror'];

        let className = 'warning';
        if (passResults.includes(result)) className = 'success';
        else if (failResults.includes(result)) className = 'danger';

        return `<span class="pill ${className}">${name}: ${result}</span>`;
    }

    /**
     * Render sender info
     */
    renderSenderInfo(sender) {
        if (!sender) return '';

        const abuseScore = sender.abuse_report?.abuseConfidenceScore;
        let abusePill = '<span class="muted">Not checked</span>';

        if (abuseScore !== undefined) {
            const className = abuseScore >= 70 ? 'danger' : abuseScore > 0 ? 'warning' : 'success';
            abusePill = `<span class="pill ${className}">Score: ${abuseScore}%</span>`;

            if (sender.abuse_report) {
                abusePill += ` <span class="pill info">Reports: ${sender.abuse_report.totalReports || 0}</span>`;
            }
        }

        const whoisInfo = sender.whois ? `
            <span class="pill info">${this.escapeHtml(sender.whois.registrar || 'Unknown')}</span>
            <span class="pill">Created: ${this.escapeHtml(sender.whois.creation_date || 'Unknown')}</span>
        ` : '<span class="muted">Not available</span>';

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="2" y1="12" x2="22" y2="12"/>
                        <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>
                    </svg>
                    <h3 class="result-card-title">Sender Information</h3>
                </div>
                <table class="data-table">
                    <tr>
                        <th>Domain</th>
                        <td>${this.escapeHtml(sender.domain || 'N/A')}</td>
                    </tr>
                    <tr>
                        <th>Sender IP</th>
                        <td>${this.escapeHtml(sender.ip || 'Not found')}</td>
                    </tr>
                    <tr>
                        <th>IP Reputation</th>
                        <td>${abusePill}</td>
                    </tr>
                    <tr>
                        <th>WHOIS</th>
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
                    <h3 class="result-card-title">Content Analysis</h3>
                </div>
                <table class="data-table">
                    <tr>
                        <th>Urgent Phrases</th>
                        <td>${this.renderList(content.urgent_phrases)}</td>
                    </tr>
                    <tr>
                        <th>Generic Greetings</th>
                        <td>${this.renderList(content.generic_greetings)}</td>
                    </tr>
                    <tr>
                        <th>Credential Requests</th>
                        <td>${this.renderList(content.credential_requests)}</td>
                    </tr>
                    <tr>
                        <th>HTML Forms</th>
                        <td>${content.forms || 0}</td>
                    </tr>
                    <tr>
                        <th>Scripts</th>
                        <td>${content.scripts || 0}</td>
                    </tr>
                    <tr>
                        <th>Hidden Elements</th>
                        <td>${content.hidden_elements || 0}</td>
                    </tr>
                    <tr>
                        <th>YARA Matches</th>
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
                        <h3 class="result-card-title">URLs (0)</h3>
                    </div>
                    <div class="empty-state">No URLs found in email</div>
                </div>
            `;
        }

        const urlItems = urls.urls.map(url => `
            <div class="url-item ${url.is_suspicious ? 'suspicious' : ''}">
                <div class="url-link">${this.escapeHtml(url.url)}</div>
                <div class="url-domain">Domain: ${this.escapeHtml(url.domain)}</div>
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
                    <h3 class="result-card-title">URLs (${urls.total_count} found, ${urls.suspicious_count} suspicious)</h3>
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
                        <h3 class="result-card-title">Attachments (0)</h3>
                    </div>
                    <div class="empty-state">No attachments found</div>
                </div>
            `;
        }

        const attItems = attachments.attachments.map(att => `
            <div class="attachment-item ${att.is_suspicious ? 'suspicious' : ''}">
                <div class="attachment-info">
                    <div class="attachment-name">${this.escapeHtml(att.filename)}</div>
                    <div class="attachment-meta">
                        ${this.escapeHtml(att.content_type || 'Unknown type')} |
                        ${this.escapeHtml(att.size_formatted || att.size + ' bytes')}
                    </div>
                    ${att.issues.length > 0 ? `
                        <div class="url-issues" style="margin-top: 0.5rem;">
                            ${att.issues.map(issue => `<span class="pill danger">${this.escapeHtml(issue)}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
                ${att.severity && att.is_suspicious ? `
                    <span class="attachment-severity ${att.severity}">${att.severity}</span>
                ` : ''}
            </div>
        `).join('');

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/>
                    </svg>
                    <h3 class="result-card-title">Attachments (${attachments.total_count} found, ${attachments.suspicious_count} suspicious)</h3>
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
            <div class="hop-item">Hop ${index + 1}: ${this.escapeHtml(hop)}</div>
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
                    <h3 class="result-card-title">Email Routing (${routing.hop_count} hops)</h3>
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
            : '<span class="muted">None detected</span>';

        return `
            <div class="result-card">
                <div class="result-card-header">
                    <svg class="result-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                    </svg>
                    <h3 class="result-card-title">Header Forensics</h3>
                </div>
                <table class="data-table">
                    <tr>
                        <th>Hop Count</th>
                        <td>${forensics.hop_count}</td>
                    </tr>
                    <tr>
                        <th>Originating IP</th>
                        <td>${forensics.originating_ip ? `<code>${this.escapeHtml(forensics.originating_ip)}</code>` : '<span class="muted">Not detected</span>'}</td>
                    </tr>
                    <tr>
                        <th>Sender Timezone</th>
                        <td>${forensics.timezone_offset ? `<code>${this.escapeHtml(forensics.timezone_offset)}</code>` : '<span class="muted">Not found</span>'}</td>
                    </tr>
                    <tr>
                        <th>Public IPs in Route</th>
                        <td>${ipBadges}</td>
                    </tr>
                </table>
            </div>
        `;
    }

    /**
     * Render list of items
     */
    renderList(items) {
        if (!items || items.length === 0) {
            return '<span class="muted">None</span>';
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
                <h3>Error</h3>
                <p>${this.escapeHtml(error)}</p>
            </div>
        `;
    }
}

// Create global results renderer instance
window.resultsRenderer = new ResultsRenderer('#resultsSection');
