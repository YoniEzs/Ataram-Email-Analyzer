/**
 * API Communication Layer
 */

class EmailAnalyzerAPI {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Analyze email file
     * @param {File} file - Email file (.eml or .msg)
     * @param {string} apiKey - Optional AbuseIPDB API key
     * @returns {Promise<Object>} Analysis results
     */
    async analyzeEmail(file, apiKey = '') {
        const formData = new FormData();
        formData.append('emailfile', file);

        if (apiKey) {
            formData.append('abuseipdb_key', apiKey);
        }

        try {
            const response = await fetch(
                `${this.baseUrl}${CONFIG.ENDPOINTS.ANALYZE}`,
                {
                    method: 'POST',
                    body: formData
                }
            );

            let data;
            try {
                data = await response.json();
            } catch {
                throw new Error(`Server error: ${response.status} ${response.statusText}`);
            }

            if (!response.ok) {
                throw new Error(data.message || `HTTP error! status: ${response.status}`);
            }

            return data;

        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    /**
     * Check API health
     * @returns {Promise<Object>} Health status
     */
    async checkHealth() {
        try {
            const response = await fetch(
                `${this.baseUrl}${CONFIG.ENDPOINTS.HEALTH}`
            );

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();

        } catch (error) {
            console.error('Health check failed:', error);
            throw error;
        }
    }
}

// Create global API instance
window.api = new EmailAnalyzerAPI(CONFIG.API_BASE_URL);
