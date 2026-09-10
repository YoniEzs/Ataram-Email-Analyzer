/**
 * Main Application Initialization
 */

document.addEventListener('DOMContentLoaded', () => {
    console.log('ITgalya Email Analyzer - Initializing...');

    // Localize static UI before anything renders text
    window.initI18n();

    // RC compatibility: one legacy translation key is still referenced by the
    // print-report template. Normalize it at the translation boundary so no
    // generated report can expose the retired Ataram product name. The key can
    // be removed from the template in the next frontend refactor without
    // changing report behaviour.
    const translate = window.t;
    if (typeof translate === 'function') {
        window.t = (key) => translate(
            key === 'Ataram Email Analyzer' ? 'ITgalya Email Analyzer' : key
        );
    }

    // Initialize UI controller
    window.uiController.initDragAndDrop();
    window.uiController.initRetryButton();
    window.uiController.initCopyArtifactsButton();
    window.uiController.initDownloadButton();
    window.uiController.initPrintButton();
    window.uiController.initThemeToggle();
    window.uiController.initHistory();

    if (window.uiController.elements.apiDestination) {
        window.uiController.elements.apiDestination.textContent = window.api.displayBaseUrl;
    }

    // Check API health on load
    checkAPIHealth();

    console.log('ITgalya Email Analyzer - Ready');
});

/**
 * Check if backend API is accessible
 */
async function checkAPIHealth() {
    try {
        await window.api.checkHealth();
        console.log('✓ Backend API is healthy');
    } catch (error) {
        console.warn('✗ Backend API health check failed:', error.message);
        console.warn('The backend may not be running. Please start the backend server.');
    }
}
