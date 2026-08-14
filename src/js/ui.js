/**
 * UI Controller
 */

class UIController {
    // How long a locally stored analysis summary is kept. The entries contain
    // the filenames of emails a user analysed, which is personal data on what
    // is about to become an anonymous public tool.
    static HISTORY_TTL_MS = 7 * 24 * 60 * 60 * 1000;

    constructor() {
        this.elements = {
            dropZone: document.getElementById('dropZone'),
            fileInput: document.getElementById('fileInput'),
            progressBar: document.getElementById('progressBar'),
            progressStep: document.getElementById('progressStep'),
            resultsSection: document.getElementById('resultsSection'),
            errorSection: document.getElementById('errorSection'),
            errorMessage: document.getElementById('errorMessage'),
            retryButton: document.getElementById('retryButton'),
            exportBar: document.getElementById('exportBar'),
            downloadReportBtn: document.getElementById('downloadReportBtn'),
            historySection: document.getElementById('historySection'),
            historyList: document.getElementById('historyList'),
            clearHistoryBtn: document.getElementById('clearHistoryBtn')
        };

        this.currentFile = null;
        this._progressInterval = null;
        this._analyzeInProgress = false;
    }

    /**
     * Initialize drag and drop functionality
     */
    initDragAndDrop() {
        const { dropZone, fileInput } = this.elements;

        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            });
        });

        // Highlight drop zone when dragging over
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.add('drag-over');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.remove('drag-over');
            });
        });

        // Handle drop
        dropZone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.handleFileSelection(files[0]);
            }
        });

        // Handle file input change
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleFileSelection(e.target.files[0]);
            }
        });

        // Click on drop zone to open file selector
        dropZone.addEventListener('click', (e) => {
            if (e.target !== fileInput && !e.target.closest('label')) {
                fileInput.click();
            }
        });
    }

    /**
     * Handle file selection
     * @param {File} file - Selected file
     */
    handleFileSelection(file) {
        const validation = this.validateFile(file);
        if (!validation.valid) {
            this.showError(validation.error);
            return;
        }

        this.currentFile = file;
        this.analyzeFile(file);
    }

    /**
     * Validate selected file
     * @param {File} file - File to validate
     * @returns {Object} Validation result
     */
    validateFile(file) {
        if (!file) {
            return { valid: false, error: 'No file selected' };
        }

        if (file.size > CONFIG.MAX_FILE_SIZE) {
            return {
                valid: false,
                error: `File size exceeds maximum of ${CONFIG.MAX_FILE_SIZE / (1024 * 1024)}MB`
            };
        }

        const extension = file.name.split('.').pop().toLowerCase();
        if (!CONFIG.ALLOWED_EXTENSIONS.includes(extension)) {
            return {
                valid: false,
                error: `Invalid file type. Only ${CONFIG.ALLOWED_EXTENSIONS.join(', ')} files are supported`
            };
        }

        return { valid: true };
    }

    /**
     * Analyze file
     * @param {File} file - File to analyze
     */
    async analyzeFile(file) {
        if (this._analyzeInProgress) {
            this.showError('Analysis already in progress. Please wait.');
            return;
        }
        this._analyzeInProgress = true;
        this.showProgress();
        this.hideError();
        this.hideResults();
        try {
            const results = await window.api.analyzeEmail(file);
            this.showResults(results);
        } catch (error) {
            this.showError(error.message || 'Failed to analyze email. Please try again.');
        } finally {
            this.hideProgress();
            this._analyzeInProgress = false;
        }
    }

    /**
     * Show progress bar with animated step indicator
     */
    showProgress() {
        const steps = [
            'Parsing email...',
            'Checking DNS records...',
            'Looking up domain info...',
            'Checking IP reputation...',
            'Analyzing content & URLs...',
            'Calculating risk score...'
        ];

        this.elements.progressBar.style.display = 'block';
        if (this.elements.progressStep) {
            this.elements.progressStep.textContent = steps[0];
        }

        let stepIndex = 0;
        this._progressInterval = setInterval(() => {
            stepIndex = (stepIndex + 1) % steps.length;
            if (this.elements.progressStep) {
                this.elements.progressStep.textContent = steps[stepIndex];
            }
        }, 1500);

        this.scrollToElement(this.elements.progressBar);
    }

    /**
     * Hide progress bar and stop step animation
     */
    hideProgress() {
        if (this._progressInterval) {
            clearInterval(this._progressInterval);
            this._progressInterval = null;
        }
        this.elements.progressBar.style.display = 'none';
        if (this.elements.progressStep) {
            this.elements.progressStep.textContent = '';
        }
    }

    /**
     * Show results
     * @param {Object} results - Analysis results
     */
    showResults(results) {
        window.resultsRenderer.render(results);
        this.elements.resultsSection.style.display = 'block';

        // Store for JSON export
        window.lastAnalysisResult = results;
        if (this.elements.exportBar) {
            this.elements.exportBar.style.display = 'block';
        }

        // Save to history and refresh history panel
        this.saveToHistory(results, this.currentFile ? this.currentFile.name : 'unknown');
        this.renderHistory();

        this.scrollToElement(this.elements.resultsSection);
    }

    /**
     * Hide results
     */
    hideResults() {
        this.elements.resultsSection.style.display = 'none';
        if (this.elements.exportBar) {
            this.elements.exportBar.style.display = 'none';
        }
    }

    /**
     * Show error message
     * @param {string} message - Error message
     */
    showError(message) {
        this.elements.errorMessage.textContent = message;
        this.elements.errorSection.style.display = 'block';
        this.scrollToElement(this.elements.errorSection);
    }

    /**
     * Hide error message
     */
    hideError() {
        this.elements.errorSection.style.display = 'none';
    }

    /**
     * Scroll to element
     * @param {HTMLElement} element - Element to scroll to
     */
    scrollToElement(element) {
        if (!element) return;
        setTimeout(() => {
            element.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }, 100);
    }

    /**
     * Initialize retry button
     */
    initRetryButton() {
        this.elements.retryButton.addEventListener('click', () => {
            this.hideError();
            if (this.currentFile) {
                this.analyzeFile(this.currentFile);
            }
        });
    }

    /**
     * Initialize the JSON download button
     */
    initDownloadButton() {
        if (!this.elements.downloadReportBtn) return;

        this.elements.downloadReportBtn.addEventListener('click', () => {
            const result = window.lastAnalysisResult;
            if (!result) return;

            const json = JSON.stringify(result, null, 2);
            const blob = new Blob([json], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const a = document.createElement('a');
            a.href = url;
            a.download = `email-analysis-${timestamp}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });
    }

    /**
     * Save analysis result summary to localStorage history (max 10 entries)
     * @param {Object} result - Analysis result
     * @param {string} filename - Email filename
     */
    saveToHistory(result, filename) {
        const entry = {
            filename: filename,
            analyzed_at: new Date().toISOString(),
            risk_level: result.risk_assessment ? result.risk_assessment.level : 'unknown',
            risk_score: result.risk_assessment ? result.risk_assessment.score : 0,
            verdict: result.risk_assessment ? result.risk_assessment.verdict : ''
        };

        let history = this.loadHistory();
        history.unshift(entry);
        history = history.slice(0, 10);
        // Filenames of analysed emails are personal data and this is a public,
        // potentially shared-computer tool. Expire them rather than keeping
        // them until someone happens to press Clear.
        history = history.filter(e => !UIController.isExpired(e));

        try {
            localStorage.setItem('emailAnalyzer_history', JSON.stringify(history));
        } catch (e) {
            console.warn('Failed to save analysis history (localStorage quota exceeded or unavailable):', e);
        }
    }

    /**
     * Load analysis history from localStorage
     * @returns {Array} History entries
     */
    loadHistory() {
        try {
            const raw = localStorage.getItem('emailAnalyzer_history');
            const parsed = raw ? JSON.parse(raw) : [];
            // Stored JSON can be anything by the time it is read back; a
            // non-array would throw on .map() and blank the page.
            if (!Array.isArray(parsed)) return [];
            return parsed
                .filter(entry => entry && typeof entry === 'object')
                .filter(entry => !UIController.isExpired(entry))
                .slice(0, 10);
        } catch (e) {
            return [];
        }
    }

    /**
     * True once a history entry is older than the retention window.
     * @param {Object} entry
     * @returns {boolean}
     */
    static isExpired(entry) {
        const at = Date.parse(entry && entry.analyzed_at);
        if (Number.isNaN(at)) return true;
        return (Date.now() - at) > UIController.HISTORY_TTL_MS;
    }

    /**
     * Render history list in the history section
     */
    renderHistory() {
        const list = this.elements.historyList;
        const section = this.elements.historySection;
        if (!list || !section) return;

        const history = this.loadHistory();

        if (history.length === 0) {
            list.innerHTML = '<p style="text-align:center; color:var(--text-muted);">No previous analyses.</p>';
            section.style.display = 'none';
            return;
        }

        section.style.display = 'block';

        // Entries come back out of localStorage, which is not a trust boundary
        // this code controls — treat every field as untrusted on the way in.
        // Object.create(null) so a stored risk_level of "constructor" or
        // "toString" cannot resolve through the prototype chain and put a
        // function's source text into a class attribute.
        const levelClass = Object.assign(Object.create(null), {
            critical: 'danger', high: 'warning', medium: 'info', low: 'success'
        });
        list.innerHTML = history.map(entry => {
            const cls = levelClass[entry.risk_level] || 'info';
            const parsed = new Date(entry.analyzed_at);
            const date = Number.isNaN(parsed.getTime()) ? 'Unknown date' : parsed.toLocaleString();
            const score = Number.isFinite(Number(entry.risk_score)) ? Number(entry.risk_score) : 0;
            return `
                <div style="display:flex; align-items:center; gap:0.75rem; padding:0.6rem 0; border-bottom:1px solid var(--border-color);">
                    <span class="pill ${cls}" style="min-width:70px; text-align:center;">${this._escapeHtml(entry.risk_level || 'unknown')}</span>
                    <div style="flex:1; min-width:0;">
                        <div style="font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${this._escapeHtml(entry.filename)}</div>
                        <div style="font-size:0.75rem; color:var(--text-muted);">${this._escapeHtml(date)}</div>
                    </div>
                    <span style="font-weight:600; color:var(--text-secondary);">${score}/100</span>
                </div>
            `;
        }).join('');
    }

    /**
     * Initialize history section: render on load and wire clear button
     */
    initHistory() {
        this.renderHistory();

        if (this.elements.clearHistoryBtn) {
            this.elements.clearHistoryBtn.addEventListener('click', () => {
                localStorage.removeItem('emailAnalyzer_history');
                this.renderHistory();
            });
        }
    }

    /**
     * Escape HTML for safe display
     */
    _escapeHtml(text) {
        // Checked against null/undefined specifically: a plain falsy test drops
        // legitimate values like 0 and false.
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }
}

// Create global UI controller instance
window.uiController = new UIController();
