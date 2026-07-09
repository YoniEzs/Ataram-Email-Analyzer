/**
 * Main Application Initialization
 */

document.addEventListener('DOMContentLoaded', () => {
    console.log('Ataram Email Analyzer - Initializing...');

    // Localize static UI before anything renders text
    window.initI18n();

    // Initialize UI controller
    window.uiController.initDragAndDrop();
    window.uiController.initRetryButton();
    window.uiController.initDownloadButton();
    window.uiController.initPrintButton();
    window.uiController.initHistory();

    // Check API health on load
    checkAPIHealth();

    console.log('Ataram Email Analyzer - Ready');
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
