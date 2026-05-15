/**
 * PhishCatcher Content Script
 * Extracts features from webpage and sends to backend for analysis
 */

const PHISHCATCHER_CONFIG = {
  API_URL: 'http://localhost:5000/predict',
  THRESHOLD: 0.6,
  CHECK_INTERVAL: 5000, // Check every 5 seconds
  SUSPICIOUS_KEYWORDS: [
    'verify', 'account', 'suspend', 'locked', 'confirm', 'update',
    'secure', 'banking', 'paypal', 'login', 'password', 'urgent',
    'click', 'prize', 'winner', 'claim', 'reward', 'free'
  ]
};

let isChecking = false;
let lastCheckTime = 0;
let warningBannerShown = false;

/**
 * Extract phishing features from current webpage
 */
function extractFeatures() {
  const url = window.location.href;
  const hostname = window.location.hostname;
  const pathname = window.location.pathname;
  
  // Feature 1: URL Length
  const urlLength = url.length;
  
  // Feature 2: Has @ symbol in URL
  const hasAtSymbol = url.includes('@') ? 1 : 0;
  
  // Feature 3: Number of dots in hostname
  const numDots = (hostname.match(/\./g) || []).length;
  
  // Feature 4: Is HTTPS
  const isHttps = url.startsWith('https://') ? 1 : 0;
  
  // Feature 5: Number of hyphens in hostname
  const numHyphens = (hostname.match(/-/g) || []).length;
  
  // Feature 6: Has IP address in URL
  const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  const hasIpAddress = ipPattern.test(hostname) ? 1 : 0;
  
  // Feature 7: Number of suspicious keywords in page text
  const pageText = document.body.innerText.toLowerCase();
  let numSuspiciousKeywords = 0;
  PHISHCATCHER_CONFIG.SUSPICIOUS_KEYWORDS.forEach(keyword => {
    if (pageText.includes(keyword)) {
      numSuspiciousKeywords++;
    }
  });
  
  // Feature 8: Number of input fields
  const inputFields = document.querySelectorAll('input[type="text"], input[type="email"], input:not([type])');
  const numInputFields = inputFields.length;
  
  // Feature 9: Has password field
  const passwordFields = document.querySelectorAll('input[type="password"]');
  const hasPasswordField = passwordFields.length > 0 ? 1 : 0;
  
  // Feature 10: Form action mismatch
  let formActionMismatch = 0;
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const action = form.getAttribute('action');
    if (action && action.startsWith('http') && !action.includes(hostname)) {
      formActionMismatch = 1;
    }
  });
  
  // Feature 11: Number of external links
  const links = document.querySelectorAll('a[href]');
  let numExternalLinks = 0;
  links.forEach(link => {
    const href = link.getAttribute('href');
    if (href && href.startsWith('http') && !href.includes(hostname)) {
      numExternalLinks++;
    }
  });
  
  // Feature 12: Has hidden fields
  const hiddenFields = document.querySelectorAll('input[type="hidden"]');
  const hasHiddenFields = hiddenFields.length > 0 ? 1 : 0;
  
  // Feature 13: Number of iframes
  const iframes = document.querySelectorAll('iframe');
  const numIframes = iframes.length;
  
  // Feature 14: URL entropy (simplified calculation)
  const urlEntropy = calculateEntropy(url);
  
  // Feature 15: Domain age (simplified - use 365 as default for unknown)
  // In production, this would require external API call
  const domainAgeDays = 365;
  
  return [
    urlLength,
    hasAtSymbol,
    numDots,
    isHttps,
    numHyphens,
    hasIpAddress,
    numSuspiciousKeywords,
    numInputFields,
    hasPasswordField,
    formActionMismatch,
    numExternalLinks,
    hasHiddenFields,
    numIframes,
    urlEntropy,
    domainAgeDays
  ];
}

/**
 * Calculate Shannon entropy of a string
 */
function calculateEntropy(str) {
  const len = str.length;
  const frequencies = {};
  
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  
  let entropy = 0;
  for (let char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

/**
 * Send features to backend API for prediction
 */
async function checkPhishing(features) {
  try {
    const response = await fetch(PHISHCATCHER_CONFIG.API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ features: features })
    });
    
    if (!response.ok) {
      console.error('PhishCatcher: API request failed:', response.status);
      return null;
    }
    
    const data = await response.json();
    return data;
    
  } catch (error) {
    console.error('PhishCatcher: Error connecting to backend:', error);
    return null;
  }
}

/**
 * Show warning banner for phishing site
 */
function showWarningBanner(probability, confidence) {
  // Remove existing banner if present
  const existingBanner = document.getElementById('phishcatcher-warning');
  if (existingBanner) {
    existingBanner.remove();
  }
  
  // Create warning banner
  const banner = document.createElement('div');
  banner.id = 'phishcatcher-warning';
  banner.className = 'phishcatcher-banner';
  
  const probabilityPercent = (probability * 100).toFixed(1);
  
  banner.innerHTML = `
    <div class="phishcatcher-banner-content">
      <div class="phishcatcher-icon">⚠️</div>
      <div class="phishcatcher-text">
        <strong>Warning: Potential Phishing Site Detected</strong>
        <p>PhishCatcher detected suspicious patterns on this page (${probabilityPercent}% confidence - ${confidence}). 
        This site may be attempting to steal your personal information.</p>
        <p><strong>Recommendation:</strong> Do not enter passwords, credit card numbers, or personal information.</p>
      </div>
      <button id="phishcatcher-close" class="phishcatcher-close">×</button>
    </div>
  `;
  
  // Insert at top of page
  document.body.insertBefore(banner, document.body.firstChild);
  
  // Close button handler
  document.getElementById('phishcatcher-close').addEventListener('click', () => {
    banner.remove();
    warningBannerShown = false;
  });
  
  warningBannerShown = true;
}

/**
 * Block form submission on phishing site
 */
function blockFormSubmission() {
  const forms = document.querySelectorAll('form');
  
  forms.forEach(form => {
    // Add visual indicator
    form.style.border = '3px solid #ff4444';
    form.style.position = 'relative';
    
    // Create overlay
    const overlay = document.createElement('div');
    overlay.className = 'phishcatcher-form-overlay';
    overlay.innerHTML = `
      <div class="phishcatcher-form-block">
        <div class="phishcatcher-form-block-icon">🛡️</div>
        <div class="phishcatcher-form-block-text">
          Form submission blocked by PhishCatcher
        </div>
      </div>
    `;
    
    form.style.position = 'relative';
    form.appendChild(overlay);
    
    // Prevent form submission
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      e.stopPropagation();
      alert('PhishCatcher blocked this form submission because this appears to be a phishing site.');
      return false;
    }, true);
  });
}

/**
 * Main phishing check function
 */
async function performPhishingCheck() {
  // Prevent multiple simultaneous checks
  if (isChecking) {
    return;
  }
  
  // Rate limiting
  const now = Date.now();
  if (now - lastCheckTime < PHISHCATCHER_CONFIG.CHECK_INTERVAL) {
    return;
  }
  
  isChecking = true;
  lastCheckTime = now;
  
  try {
    // Extract features
    const features = extractFeatures();
    console.log('PhishCatcher: Extracted features:', features);
    
    // Send to backend
    const result = await checkPhishing(features);
    
    if (result) {
      console.log('PhishCatcher: Prediction result:', result);
      
      // Store result with proper error handling
      try {
        await chrome.storage.local.set({
          lastCheck: {
            url: window.location.href,
            timestamp: new Date().toISOString(),
            result: result
          }
        });
      } catch (storageError) {
        console.warn('PhishCatcher: Could not save to storage:', storageError);
        // Continue execution even if storage fails
      }
      
      // Show warning if phishing detected
      if (result.probability > PHISHCATCHER_CONFIG.THRESHOLD && !warningBannerShown) {
        showWarningBanner(result.probability, result.confidence);
        blockFormSubmission();
        
        // Notify background script
        try {
          chrome.runtime.sendMessage({
            type: 'PHISHING_DETECTED',
            url: window.location.href,
            probability: result.probability
          });
        } catch (messageError) {
          console.warn('PhishCatcher: Could not send message to background:', messageError);
          // Continue execution even if message fails
        }
      }
    }
    
  } catch (error) {
    console.error('PhishCatcher: Error during check:', error);
  } finally {
    isChecking = false;
  }
}

/**
 * Initialize PhishCatcher
 */
function initialize() {
  // Skip checking on localhost and known safe domains
  const hostname = window.location.hostname;
  const safeDomains = ['localhost', '127.0.0.1', 'chrome-extension'];
  
  if (safeDomains.some(domain => hostname.includes(domain))) {
    console.log('PhishCatcher: Skipping check for safe domain');
    return;
  }
  
  console.log('PhishCatcher: Initialized on', window.location.href);
  
  // Perform initial check after page load
  if (document.readyState === 'complete') {
    setTimeout(performPhishingCheck, 1000);
  } else {
    window.addEventListener('load', () => {
      setTimeout(performPhishingCheck, 1000);
    });
  }
  
  // Listen for messages from popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'CHECK_NOW') {
      performPhishingCheck().then(() => {
        sendResponse({ success: true });
      }).catch((error) => {
        console.error('PhishCatcher: Error during manual check:', error);
        sendResponse({ success: false, error: error.message });
      });
      return true; // Keep message channel open
    }
  });
}

// Start PhishCatcher
initialize(); 