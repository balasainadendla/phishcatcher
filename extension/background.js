/**
 * PhishCatcher Background Service Worker
 * Handles extension lifecycle and notifications
 */

// Extension installation handler
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('PhishCatcher installed successfully');
    
    // Set default settings
    chrome.storage.local.set({
      enabled: true,
      threshold: 0.6,
      autoBlock: true,
      showNotifications: true,
      stats: {
        totalChecks: 0,
        phishingDetected: 0,
        sitesBlocked: 0
      }
    });
    
    // Open welcome page
    chrome.tabs.create({
      url: 'popup.html'
    });
  }
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'PHISHING_DETECTED') {
    handlePhishingDetection(request, sender);
  }
});

/**
 * Handle phishing detection notification
 */
async function handlePhishingDetection(request, sender) {
  console.log('Phishing detected:', request);
  
  // Update statistics
  chrome.storage.local.get(['stats'], (result) => {
    const stats = result.stats || {
      totalChecks: 0,
      phishingDetected: 0,
      sitesBlocked: 0
    };
    
    stats.phishingDetected += 1;
    stats.sitesBlocked += 1;
    
    chrome.storage.local.set({ stats });
  });
  
  // Update badge
  chrome.action.setBadgeText({
    text: '⚠️',
    tabId: sender.tab.id
  });
  
  chrome.action.setBadgeBackgroundColor({
    color: '#ff4444',
    tabId: sender.tab.id
  });
  
  // Show notification if enabled
  chrome.storage.local.get(['showNotifications'], (result) => {
    if (result.showNotifications !== false) {
      showNotification(request);
    }
  });
}

/**
 * Show system notification
 */
function showNotification(request) {
  const probabilityPercent = (request.probability * 100).toFixed(1);
  
  // Note: notifications require additional permission in manifest
  // Keeping this simple for now
  console.log(`Notification: Phishing detected (${probabilityPercent}%) on ${request.url}`);
}

/**
 * Handle tab updates
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Clear badge when navigating to new page
    chrome.action.setBadgeText({
      text: '',
      tabId: tabId
    });
    
    // Update total checks counter
    chrome.storage.local.get(['stats'], (result) => {
      const stats = result.stats || {
        totalChecks: 0,
        phishingDetected: 0,
        sitesBlocked: 0
      };
      
      stats.totalChecks += 1;
      chrome.storage.local.set({ stats });
    });
  }
});

/**
 * Handle extension icon click
 */
chrome.action.onClicked.addListener((tab) => {
  // The popup.html will open automatically due to manifest configuration
  console.log('Extension icon clicked');
});

console.log('PhishCatcher background service worker initialized');