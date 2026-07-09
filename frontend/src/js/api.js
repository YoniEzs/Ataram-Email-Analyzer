/**
 * API Communication Layer
 */

class EmailAnalyzerAPI {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Analyze email file.
     * Uses XMLHttpRequest so large uploads report progress; enforces a
     * client-side timeout and maps rate-limit errors to friendly copy.
     *
     * @param {File} file - Email file (.eml or .msg)
     * @param {string} apiKey - Optional AbuseIPDB API key
     * @param {function(number):void} [onUploadProgress] - Called with 0-100
     * @returns {Promise<Object>} Analysis results
     */
    analyzeEmail(file, apiKey = '', onUploadProgress = null) {
        const formData = new FormData();
        formData.append('emailfile', file);
        if (apiKey) {
            formData.append('abuseipdb_key', apiKey);
        }

        const url = `${this.baseUrl}${CONFIG.ENDPOINTS.ANALYZE}`;

        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', url);
            xhr.responseType = 'json';
            xhr.timeout = CONFIG.REQUEST_TIMEOUT_MS;

            if (xhr.upload && typeof onUploadProgress === 'function') {
                xhr.upload.onprogress = (event) => {
                    if (event.lengthComputable) {
                        onUploadProgress(Math.round((event.loaded / event.total) * 100));
                    }
                };
            }

            xhr.onload = () => {
                const data = xhr.response;
                if (xhr.status >= 200 && xhr.status < 300 && data) {
                    resolve(data);
                    return;
                }
                if (xhr.status === 429) {
                    reject(new Error(t('Too many requests. Please wait a minute and try again.')));
                    return;
                }
                const message = (data && data.message)
                    || `Server error: ${xhr.status} ${xhr.statusText}`;
                reject(new Error(message));
            };

            xhr.ontimeout = () => {
                reject(new Error(t('The analysis timed out. Please try again.')));
            };

            xhr.onerror = () => {
                reject(new Error(t('Network error. Check that the analysis server is reachable.')));
            };

            xhr.send(formData);
        });
    }

    /**
     * Check API health (bounded by a short timeout).
     * @returns {Promise<Object>} Health status
     */
    async checkHealth() {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), CONFIG.HEALTH_TIMEOUT_MS);

        try {
            const response = await fetch(
                `${this.baseUrl}${CONFIG.ENDPOINTS.HEALTH}`,
                { signal: controller.signal }
            );

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();

        } catch (error) {
            console.error('Health check failed:', error);
            throw error;
        } finally {
            clearTimeout(timer);
        }
    }
}

// Create global API instance
window.api = new EmailAnalyzerAPI(CONFIG.API_BASE_URL);
