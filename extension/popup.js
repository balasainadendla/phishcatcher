/**
 * PhishCatcher Popup Script
 * Handles popup interface and user interactions
 */

const API_URL = 'http://localhost:5000';

// DOM Elements
const statusDiv = document.getElementById('status');
const totalChecksSpan = document.getElementById('totalChecks');
const phishingDetectedSpan = document.getElementById('phishingDetected');
const sitesBlockedSpan = document.getElementById('sitesBlocked');
const checkNowBtn = document.getElementById('checkNow');
const viewSettingsBtn = document.getElementById('viewSettings');
const lastCheckDiv = document.getElementById('lastCheck');
const lastCheckInfoDiv = document.getElementById('lastCheckInfo');
const backendStatusSpan = document.getElementById('backendStatus');

/**
 * Check backend health
 */
async function checkBackendHealth() {
  try {
    const response = await fetch(`${API_URL}/health`);
    if (response.ok) {
      backendStatusSpan.textContent = '✓ Connected';
      backendStatusSpan.style.color = '#22c55e';
      return true;
    } else {
      backendStatusSpan.textContent = '✗ Error';
      backendStatusSpan.style.color = '#ef4444';
      return false;
    }
  } catch (error) {
    backendStatusSpan.textContent = '✗ Offline';
    backendStatusSpan.style.color = '#ef4444';
    return false;
  }
}

/**
 * Load statistics
 */
function loadStatistics() {
  chrome.storage.local.get(['stats'], (result) => {
    const stats = result.stats || {
      totalChecks: 0,
      phishingDetected: 0,
      sitesBlocked: 0
    };
    
    totalChecksSpan.textContent = stats.totalChecks;
    phishingDetectedSpan.textContent = stats.phishingDetected;
    sitesBlockedSpan.textContent = stats.sitesBlocked;
  });
}

/**
 * Load last check result
 */
function loadLastCheck() {
  chrome.storage.local.get(['lastCheck'], (result) => {
    if (result.lastCheck) {
      const check = result.lastCheck;
      const date = new Date(check.timestamp);
      const probability = (check.result.probability * 100).toFixed(1);
      
      lastCheckDiv.style.display = 'block';
      lastCheckInfoDiv.innerHTML = `
        <strong>URL:</strong> ${truncateUrl(check.url)}<br>
        <strong>Time:</strong> ${date.toLocaleTimeString()}<br>
        <strong>Result:</strong> ${check.result.classification} (${probability}%)
      `;
      
      // Update status based on last check
      updateStatus(check.result);
    }
  });
}

/**
 * Update status display
 */
function updateStatus(result) {
  if (result.classification === 'phishing') {
    statusDiv.className = 'status danger';
    statusDiv.innerHTML = `
      <div class="status-icon">⚠️</div>
      <h3>Warning: Phishing Detected!</h3>
      <p>This site may be dangerous (${(result.probability * 100).toFixed(1)}% confidence)</p>
    `;
  } else {
    statusDiv.className = 'status safe';
    statusDiv.innerHTML = `
      <div class="status-icon">✅</div>
      <h3>Site Appears Safe</h3>
      <p>No phishing indicators detected (${(result.probability * 100).toFixed(1)}% risk)</p>
    `;
  }
}

/**
 * Truncate URL for display
 */
function truncateUrl(url, maxLength = 40) {
  if (url.length <= maxLength) return url;
  return url.substring(0, maxLength) + '...';
}

/**
 * Handle "Check Now" button click
 */
async function handleCheckNow() {
  checkNowBtn.disabled = true;
  checkNowBtn.textContent = '🔄 Checking...';
  
  statusDiv.className = 'status';
  statusDiv.innerHTML = `
    <div class="status-icon">🔍</div>
    <h3>Analyzing page...</h3>
    <p>Please wait</p>
  `;
  
  try {
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    // Send message to content script
    chrome.tabs.sendMessage(tab.id, { type: 'CHECK_NOW' }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('Error:', chrome.runtime.lastError);
        statusDiv.className = 'status danger';
        statusDiv.innerHTML = `
          <div class="status-icon">❌</div>
          <h3>Check Failed</h3>
          <p>Unable to analyze this page. Make sure the backend is running.</p>
        `;
      } else {
        // Reload last check after a brief delay
        setTimeout(() => {
          loadLastCheck();
        }, 1000);
      }
      
      checkNowBtn.disabled = false;
      checkNowBtn.textContent = '🔍 Check This Page Now';
    });
    
  } catch (error) {
    console.error('Error checking page:', error);
    statusDiv.className = 'status danger';
    statusDiv.innerHTML = `
      <div class="status-icon">❌</div>
      <h3>Error</h3>
      <p>Failed to check page: ${error.message}</p>
    `;
    checkNowBtn.disabled = false;
    checkNowBtn.textContent = '🔍 Check This Page Now';
  }
}

/**
 * Handle "Settings" button click
 */
function handleViewSettings() {
  // For now, just show an alert
  // In production, this would open a settings page
  const settingsInfo = `
PhishCatcher Settings

Current Configuration:
• Threshold: 0.6 (60%)
• Auto-block forms: Enabled
• Show warnings: Enabled

To modify settings, edit the extension configuration.
  `;
  
  alert(settingsInfo.trim());
}

/**
 * Initialize popup
 */
async function initialize() {
  // Check backend health
  await checkBackendHealth();
  
  // Load statistics
  loadStatistics();
  
  // Load last check
  loadLastCheck();
  
  // Set up event listeners
  checkNowBtn.addEventListener('click', handleCheckNow);
  viewSettingsBtn.addEventListener('click', handleViewSettings);
  
  // Refresh statistics every 2 seconds
  setInterval(loadStatistics, 2000);
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', initialize);