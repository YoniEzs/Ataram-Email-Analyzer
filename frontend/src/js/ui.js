/**
 * UI Controller
 */

class UIController {
    constructor() {
        this.elements = {
            dropZone: document.getElementById('dropZone'),
            fileInput: document.getElementById('fileInput'),
            apiKeyInput: document.getElementById('apiKeyInput'),
            apiDestination: document.getElementById('apiDestination'),
            progressBar: document.getElementById('progressBar'),
            progressStep: document.getElementById('progressStep'),
            resultsSection: document.getElementById('resultsSection'),
            errorSection: document.getElementById('errorSection'),
            errorMessage: document.getElementById('errorMessage'),
            retryButton: document.getElementById('retryButton'),
            exportBar: document.getElementById('exportBar'),
            copyArtifactsBtn: document.getElementById('copyArtifactsBtn'),
            downloadReportBtn: document.getElementById('downloadReportBtn'),
            printReportBtn: document.getElementById('printReportBtn'),
            historySection: document.getElementById('historySection'),
            historyList: document.getElementById('historyList'),
            clearHistoryBtn: document.getElementById('clearHistoryBtn'),
            themeToggle: document.getElementById('themeToggle')
        };

        this.currentFile = null;
        this._progressInterval = null;
    }

    /**
     * Initialize drag and drop functionality
     */
    initDragAndDrop() {
        const { dropZone, fileInput } = this.elements;
        if (!dropZone || !fileInput) {
            console.warn('Upload UI elements not found; drag-and-drop disabled.');
            return;
        }

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
        try {
            this.showProgress();
            this.hideError();
            this.hideResults();

            const apiKey = this.elements.apiKeyInput ? this.elements.apiKeyInput.value.trim() : '';
            const results = await window.api.analyzeEmail(file, apiKey, (percent) => {
                if (this.elements.progressStep && percent < 100) {
                    this.elements.progressStep.textContent = `${t('Uploading...')} ${percent}%`;
                }
            });

            this.hideProgress();
            this.showResults(results);

        } catch (error) {
            this.hideProgress();
            this.showError(error.message || t('Failed to analyze email. Please try again.'));
        } finally {
            if (this.elements.apiKeyInput) {
                this.elements.apiKeyInput.value = '';
            }
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

        if (!this.elements.progressBar) return;
        this.elements.progressBar.style.display = 'block';
        if (this.elements.progressStep) {
            this.elements.progressStep.textContent = t(steps[0]);
        }

        let stepIndex = 0;
        this._progressInterval = setInterval(() => {
            stepIndex = (stepIndex + 1) % steps.length;
            if (this.elements.progressStep) {
                this.elements.progressStep.textContent = t(steps[stepIndex]);
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
        if (this.elements.progressBar) {
            this.elements.progressBar.style.display = 'none';
        }
        if (this.elements.progressStep) {
            this.elements.progressStep.textContent = '';
        }
    }

    /**
     * Show results
     * @param {Object} results - Analysis results
     */
    showResults(results) {
        if (window.resultsRenderer && typeof window.resultsRenderer.render === 'function') {
            window.resultsRenderer.render(results);
        }
        if (this.elements.resultsSection) {
            this.elements.resultsSection.style.display = 'block';
        }

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
        if (this.elements.resultsSection) {
            this.elements.resultsSection.style.display = 'none';
        }
        if (this.elements.exportBar) {
            this.elements.exportBar.style.display = 'none';
        }
    }

    /**
     * Show error message
     * @param {string} message - Error message
     */
    showError(message) {
        if (!this.elements.errorSection || !this.elements.errorMessage) return;
        this.elements.errorMessage.textContent = message;
        this.elements.errorSection.style.display = 'block';
        this.scrollToElement(this.elements.errorSection);
    }

    /**
     * Hide error message
     */
    hideError() {
        if (this.elements.errorSection) {
            this.elements.errorSection.style.display = 'none';
        }
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
        if (!this.elements.retryButton) return;
        this.elements.retryButton.addEventListener('click', () => {
            this.hideError();
            if (this.currentFile) {
                this.analyzeFile(this.currentFile);
            }
        });
    }

    /**
     * Copy the artifact block as text for pasting into a ticket.
     */
    initCopyArtifactsButton() {
        if (!this.elements.copyArtifactsBtn) return;

        this.elements.copyArtifactsBtn.addEventListener('click', async () => {
            const result = window.lastAnalysisResult;
            if (!result || !window.resultsRenderer) return;

            const text = window.resultsRenderer.buildArtifactText(result);
            if (!text) return;

            let copied = false;
            // navigator.clipboard needs a secure context. The Compose stack
            // serves plain HTTP on :3000, so the fallback is load-bearing.
            if (navigator.clipboard && window.isSecureContext) {
                try {
                    await navigator.clipboard.writeText(text);
                    copied = true;
                } catch (e) {
                    copied = false;
                }
            }
            if (!copied) {
                copied = this.copyViaTextarea(text);
            }
            if (!copied) {
                window.prompt(t('Copy the artifact block below'), text);
                return;
            }
            this.flashButtonLabel(this.elements.copyArtifactsBtn, t('Copied'));
        });
    }

    /**
     * Clipboard fallback for non-secure contexts.
     */
    copyViaTextarea(text) {
        try {
            const area = document.createElement('textarea');
            area.value = text;
            area.setAttribute('readonly', '');
            area.style.position = 'fixed';
            area.style.left = '-9999px';
            document.body.appendChild(area);
            area.select();
            const ok = document.execCommand('copy');
            document.body.removeChild(area);
            return ok;
        } catch (e) {
            return false;
        }
    }

    flashButtonLabel(button, message) {
        const original = button.textContent;
        button.textContent = message;
        setTimeout(() => { button.textContent = original; }, 1500);
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
     * Initialize the light/dark theme toggle.
     *
     * With no explicit choice the page follows the OS preference (handled in
     * CSS). Clicking the toggle picks the opposite of whatever is currently
     * showing and persists it to localStorage.
     */
    initThemeToggle() {
        const toggle = this.elements.themeToggle;
        if (!toggle) return;

        const systemPrefersDark = () =>
            window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

        const currentTheme = () => {
            const explicit = document.documentElement.getAttribute('data-theme');
            if (explicit === 'light' || explicit === 'dark') return explicit;
            return systemPrefersDark() ? 'dark' : 'light';
        };

        const applyLabel = () => {
            const next = currentTheme() === 'dark' ? t('Switch to light theme') : t('Switch to dark theme');
            toggle.setAttribute('aria-label', next);
            toggle.setAttribute('title', next);
        };

        applyLabel();
        this._applyThemeLabel = applyLabel;

        toggle.addEventListener('click', () => {
            const next = currentTheme() === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            try {
                localStorage.setItem('emailAnalyzer_theme', next);
            } catch (e) { /* localStorage unavailable */ }
            applyLabel();
        });
    }

    /**
     * Initialize the print-report button (browser print → Save as PDF)
     */
    initPrintButton() {
        if (!this.elements.printReportBtn) return;
        this.elements.printReportBtn.addEventListener('click', () => {
            if (!window.lastAnalysisResult) return;
            window.print();
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

        try {
            localStorage.setItem('emailAnalyzer_history', JSON.stringify(history));
        } catch (e) {
            // localStorage quota exceeded or unavailable — silently skip
        }
    }

    /**
     * Load analysis history from localStorage
     * @returns {Array} History entries
     */
    loadHistory() {
        try {
            const raw = localStorage.getItem('emailAnalyzer_history');
            return raw ? JSON.parse(raw) : [];
        } catch (e) {
            return [];
        }
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
            list.innerHTML = `<p class="history-empty">${this._escapeHtml(t('No previous analyses.'))}</p>`;
            section.style.display = 'none';
            return;
        }

        section.style.display = 'block';

        const levelClass = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' };
        list.innerHTML = history.map(entry => {
            const cls = levelClass[entry.risk_level] || 'info';
            const date = new Date(entry.analyzed_at).toLocaleString();
            return `
                <div class="history-item">
                    <span class="pill ${cls}" style="min-width:70px; text-align:center;">${this._escapeHtml(t(entry.risk_level || 'unknown'))}</span>
                    <div class="history-item-main">
                        <div class="history-item-name">${this._escapeHtml(entry.filename)}</div>
                        <div class="history-item-date">${date}</div>
                    </div>
                    <span class="history-item-score">${entry.risk_score}/100</span>
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
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Create global UI controller instance
window.uiController = new UIController();
