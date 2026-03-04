/**
 * UI Controller
 */

class UIController {
    constructor() {
        this.elements = {
            dropZone: document.getElementById('dropZone'),
            fileInput: document.getElementById('fileInput'),
            apiKeyInput: document.getElementById('apiKeyInput'),
            progressBar: document.getElementById('progressBar'),
            resultsSection: document.getElementById('resultsSection'),
            errorSection: document.getElementById('errorSection'),
            errorMessage: document.getElementById('errorMessage'),
            retryButton: document.getElementById('retryButton')
        };

        this.currentFile = null;
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
        // Validate file
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
        // Check if file exists
        if (!file) {
            return { valid: false, error: 'No file selected' };
        }

        // Check file size
        if (file.size > CONFIG.MAX_FILE_SIZE) {
            return {
                valid: false,
                error: `File size exceeds maximum of ${CONFIG.MAX_FILE_SIZE / (1024 * 1024)}MB`
            };
        }

        // Check file extension
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

            const apiKey = this.elements.apiKeyInput.value.trim();
            const results = await window.api.analyzeEmail(file, apiKey);

            this.hideProgress();
            this.showResults(results);

        } catch (error) {
            this.hideProgress();
            this.showError(error.message || 'Failed to analyze email. Please try again.');
        }
    }

    /**
     * Show progress bar
     */
    showProgress() {
        this.elements.progressBar.style.display = 'block';
        this.scrollToElement(this.elements.progressBar);
    }

    /**
     * Hide progress bar
     */
    hideProgress() {
        this.elements.progressBar.style.display = 'none';
    }

    /**
     * Show results
     * @param {Object} results - Analysis results
     */
    showResults(results) {
        window.resultsRenderer.render(results);
        this.elements.resultsSection.style.display = 'block';
        this.scrollToElement(this.elements.resultsSection);
    }

    /**
     * Hide results
     */
    hideResults() {
        this.elements.resultsSection.style.display = 'none';
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
}

// Create global UI controller instance
window.uiController = new UIController();
