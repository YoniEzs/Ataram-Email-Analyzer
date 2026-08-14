/**
 * API Communication Layer
 */

class EmailAnalyzerAPI {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Request options every call needs when the app sits behind Cloudflare Access.
     *
     * credentials: Access requires same-origin explicitly for the CF_Authorization
     *   cookie to be attached; without it AJAX calls fail with a confusing CORS error.
     * X-Requested-With: makes Access answer an expired session with a 401 rather
     *   than a 302 to the login page. That matters because fetch() follows the
     *   redirect transparently, so the response would otherwise look like a
     *   perfectly good 200 carrying an HTML login page — which then fails to parse
     *   as JSON and surfaces to the user as a meaningless "Server error: 200".
     *
     * Both headers are safe here: the request is same-origin, so adding a custom
     * header does not trigger a CORS preflight.
     */
    static get REQUEST_DEFAULTS() {
        return {
            credentials: 'same-origin',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        };
    }

    /**
     * Shown when Cloudflare Access is in front of the app and the session has
     * lapsed. On a public deployment with Access removed this branch is
     * unreachable, and the message is deliberately worded so it does not
     * promise a sign-in flow that no longer exists.
     */
    static get SESSION_EXPIRED_MESSAGE() {
        return 'Your session has expired. Reload the page and try again.';
    }

    /**
     * Detect a Cloudflare Access session that lapsed mid-request.
     *
     * The 401 is the documented signal and the normal path. The redirect check is
     * a narrow fallback for the case where the X-Requested-With header is stripped
     * in transit — it requires an actual redirect to a cloudflareaccess.com host,
     * so it cannot misread an ordinary network failure as an expired session.
     *
     * @param {Response} response
     * @returns {boolean}
     */
    static isSessionExpired(response) {
        if (response.status === 401) {
            return true;
        }
        if (!response.redirected) {
            return false;
        }
        try {
            const target = new URL(response.url);
            return target.origin !== window.location.origin &&
                   target.hostname.endsWith('.cloudflareaccess.com');
        } catch {
            return false;
        }
    }

    /**
     * Analyze email file
     *
     * No API key is sent: the backend takes the AbuseIPDB key from server
     * configuration and ignores anything the client supplies, so transmitting
     * one would expose a user secret to no purpose.
     *
     * @param {File} file - Email file (.eml or .msg)
     * @returns {Promise<Object>} Analysis results
     */
    async analyzeEmail(file) {
        const formData = new FormData();
        formData.append('emailfile', file);

        try {
            const response = await fetch(
                `${this.baseUrl}${CONFIG.ENDPOINTS.ANALYZE}`,
                {
                    method: 'POST',
                    body: formData,
                    ...EmailAnalyzerAPI.REQUEST_DEFAULTS
                }
            );

            if (EmailAnalyzerAPI.isSessionExpired(response)) {
                throw new Error(EmailAnalyzerAPI.SESSION_EXPIRED_MESSAGE);
            }

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
                `${this.baseUrl}${CONFIG.ENDPOINTS.HEALTH}`,
                EmailAnalyzerAPI.REQUEST_DEFAULTS
            );

            if (EmailAnalyzerAPI.isSessionExpired(response)) {
                throw new Error(EmailAnalyzerAPI.SESSION_EXPIRED_MESSAGE);
            }

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
