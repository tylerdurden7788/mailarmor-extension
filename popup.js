/**
 * MailArmour Popup Script
 * Coordinates scanning logic, shared storage, UI updates, and API communications via background proxy.
 * Implements Hindi translations, Pro simulator, whitelisting, history, stats, and PDF reports.
 */

// Configuration
const MAX_FREE_SCANS = 10;

// Translations dictionary
const translations = {
  en: {
    // Tab navigation buttons
    tabScan: "Scan",
    tabDash: "Dash",
    tabHistory: "History",
    
    // Scan Tab elements
    scanBtn: "Scan This Email",
    scanningBtn: "Analyzing...",
    trustSender: "✅ Trust Sender",
    untrustSender: "❌ Untrust Sender",
    copyWarning: "📋 MailArmour Alert",
    copied: "Copied!",
    upgradeBtn: "Upgrade — $5/month",
    neutralStatus: "Click Scan to analyze the current email",
    safeStatus: "This email looks safe",
    suspiciousStatus: "Proceed with caution",
    dangerousStatus: "CRITICAL WARNING:\nPhishing Threat Detected!",
    loadingStatus: "Analyzing email content...",
    verdictLabel: "Verdict",
    riskLabel: "Phishing Probability:",
    checklistHeading: "Security Audit Checklist",
    freeScansUsed: "Free scans used: {count} / {max}",
    upgradeMsg: "You've used all free scans. Upgrade to Pro for unlimited scans 🔒",
    licenseHeading: "Already paid? Enter your license key",
    licenseBtn: "Activate Pro",
    licenseSuccess: "✅ Pro activated! Enjoy unlimited scans.",
    licenseError: "❌ Invalid key. Please check and try again.",
    
    // Dashboard Tab elements
    scannedLabel: "Total Scanned",
    threatsLabel: "Threats Blocked",
    suspiciousLabel: "Suspicious Found",
    chartHeading: "7-Day Scan Activity",
    whitelistHeading: "Manage Whitelist",
    whitelistEmpty: "No domains whitelisted yet.",
    exportReport: "📊 Export Report",
    
    // History Tab elements
    historyHeading: "Scan History",
    historyEmpty: "No scans recorded yet.",
    historyUpgradeText: "Showing last 5 scans. Upgrade to Pro to see all 50 scans.",
    proFeatureAlert: "PDF Export is a Pro Feature. Please upgrade to Pro in the header!",
    
    // Verdict strings
    verdictSafe: "SAFE",
    verdictSuspicious: "SUSPICIOUS",
    verdictDangerous: "DANGEROUS",
    whitelistedVerdict: "Sender domain is in your trusted whitelist.",
    trustedBadge: "Trusted Sender",
    
    // Checklist keys
    sender_check: "Sender Verification",
    domain_check: "Domain Age Check",
    urgency_check: "Urgency Check",
    link_check: "Links Check",
    content_check: "Content Verification",
    attachment_check: "Attachment Check",
    
    // Days
    days: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
  },
  hi: {
    // Tab navigation buttons
    tabScan: "जांचें",
    tabDash: "डैश",
    tabHistory: "इतिहास",
    
    // Scan Tab elements
    scanBtn: "ईमेल स्कैन करें",
    scanningBtn: "विश्लेषण हो रहा है...",
    trustSender: "✅ प्रेषक पर भरोसा करें",
    untrustSender: "❌ भरोसा हटाएं",
    copyWarning: "📋 MailArmour चेतावनी",
    copied: "कॉपी हो गया!",
    upgradeBtn: "अपग्रेड करें — $5/माह",
    neutralStatus: "वर्तमान ईमेल का विश्लेषण करने के लिए स्कैन पर क्लिक करें",
    safeStatus: "यह ईमेल सुरक्षित लग रहा है",
    suspiciousStatus: "सावधानी से आगे बढ़ें",
    dangerousStatus: "महत्वपूर्ण चेतावनी:\nफ़िशिंग ख़तरा पाया गया!",
    loadingStatus: "ईमेल सामग्री का विश्लेषण किया जा रहा है...",
    verdictLabel: "फ़ैसला",
    riskLabel: "फ़िशिंग की संभावना:",
    checklistHeading: "सुरक्षा ऑडिट चेकलिस्ट",
    freeScansUsed: "मुफ़्त स्कैन उपयोग: {count} / {max}",
    upgradeMsg: "आपने सभी मुफ़्त स्कैन का उपयोग कर लिया है। असीमित स्कैन के लिए प्रो में अपग्रेड करें 🔒",
    licenseHeading: "पहले से भुगतान किया? लाइसेंस की दर्ज करें",
    licenseBtn: "प्रो सक्रिय करें",
    licenseSuccess: "✅ प्रो सक्रिय! असीमित स्कैन का आनंद लें.",
    licenseError: "❌ अमान्य की. कृपया जांचें और पुनः प्रयास करें.",
    
    // Dashboard Tab elements
    scannedLabel: "कुल स्कैन किया गया",
    threatsLabel: "अवरुद्ध खतरे",
    suspiciousLabel: "संदेहास्पद मिले",
    chartHeading: "7-दिवसीय स्कैन गतिविधि",
    whitelistHeading: "सफ़ेद सूची प्रबंधित करें",
    whitelistEmpty: "अभी तक कोई डोमेन सफ़ेद सूची में नहीं है।",
    exportReport: "📊 रिपोर्ट निर्यात करें",
    
    // History Tab elements
    historyHeading: "स्कैन इतिहास",
    historyEmpty: "अभी तक कोई स्कैन दर्ज नहीं किया गया है।",
    historyUpgradeText: "पिछले 5 स्कैन दिखाए जा रहे हैं। सभी 50 स्कैन देखने के लिए प्रो में अपग्रेड करें।",
    proFeatureAlert: "पीडीएफ निर्यात एक प्रो फीचर है। कृपया हेडर में प्रो में अपग्रेड करें!",
    
    // Verdict strings
    verdictSafe: "सुरक्षित",
    verdictSuspicious: "संदेहास्पद",
    verdictDangerous: "खतरनाक",
    whitelistedVerdict: "यह प्रेषक आपकी विश्वसनीय सफ़ेद सूची में है।",
    trustedBadge: "विश्वसनीय प्रेषक",
    
    // Checklist keys
    sender_check: "प्रेषक सत्यापन",
    domain_check: "डोमेन आयु जांच",
    urgency_check: "तात्कालिकता जांच",
    link_check: "लिंक जांच",
    content_check: "सामग्री सत्यापन",
    attachment_check: "अटैचमेंट जांच",
    
    // Days
    days: ["रवि", "सोम", "मंगल", "बुध", "गुरु", "शुक्र", "शनि"]
  }
};

// State Variables
let currentLanguage = "en";
let currentSenderDomain = "";
let currentEmailData = null;
let currentVerdictData = null;

// DOM Elements
const proBadge = document.getElementById("pro-badge");
const langToggle = document.getElementById("lang-toggle");
const tabBtnScan = document.getElementById("tab-btn-scan");
const tabBtnDash = document.getElementById("tab-btn-dash");
const tabBtnHistory = document.getElementById("tab-btn-history");
const panelScan = document.getElementById("panel-scan");
const panelDash = document.getElementById("panel-dash");
const panelHistory = document.getElementById("panel-history");

// Scan Tab Elements
const statusCard = document.getElementById("status-card");
const statusIcon = document.getElementById("status-icon");
const statusText = document.getElementById("status-text");
const riskScoreContainer = document.getElementById("risk-score-container");
const riskScoreLabel = document.getElementById("risk-score-label");
const riskScoreValue = document.getElementById("risk-score-value");
const riskScoreBar = document.getElementById("risk-score-bar");
const reasonContainer = document.getElementById("reason-container");
const reasonText = document.getElementById("reason-text");
const checklistContainer = document.getElementById("checklist-container");
const checklistHeading = document.getElementById("checklist-heading");
const checklistItems = document.getElementById("checklist-items");
const trustBtn = document.getElementById("trust-btn");
const copyWarningBtn = document.getElementById("copy-warning-btn");
const scanBtn = document.getElementById("scan-btn");
const errorMessage = document.getElementById("error-message");
const upgradeContainer = document.getElementById("upgrade-container");
const upgradeMessage = document.getElementById("upgrade-message");
const upgradeMonthlyLink = document.getElementById("upgrade-monthly-link");
const upgradeLifetimeLink = document.getElementById("upgrade-lifetime-link");

// Dashboard Tab Elements
const dashScannedVal = document.getElementById("dash-scanned-val");
const dashScannedLabel = document.getElementById("dash-scanned-label");
const dashThreatsVal = document.getElementById("dash-threats-val");
const dashThreatsLabel = document.getElementById("dash-threats-label");
const dashSuspiciousVal = document.getElementById("dash-suspicious-val");
const dashSuspiciousLabel = document.getElementById("dash-suspicious-label");
const chartHeading = document.getElementById("chart-heading");
const chartBars = document.getElementById("chart-bars");
const whitelistHeading = document.getElementById("whitelist-heading");
const whitelistList = document.getElementById("whitelist-list");
const whitelistEmptyMsg = document.getElementById("whitelist-empty-msg");
const exportPdfBtn = document.getElementById("export-pdf-btn");
const exportCsvBtn = document.getElementById("export-csv-btn");
const exportJsonBtn = document.getElementById("export-json-btn");

// History Tab Elements
const historyHeading = document.getElementById("history-heading");
const historyList = document.getElementById("history-list");
const historyEmptyMsg = document.getElementById("history-empty-msg");
const historyUpgradePrompt = document.getElementById("history-upgrade-prompt");
const historyUpgradeText = document.getElementById("history-upgrade-text");

// Footer
const scanCountText = document.getElementById("scan-count-text");

// License key elements
const licenseContainer = document.getElementById("license-container");
const licenseHeading = document.getElementById("license-heading");
const licenseInput = document.getElementById("license-input");
const licenseBtn = document.getElementById("license-btn");
const licenseMessage = document.getElementById("license-message");

// Initial Setup
document.addEventListener("DOMContentLoaded", async () => {
  // 1. Load language preference & Pro status (synchronized between local and sync storage)
  chrome.storage.local.get(["lang", "isPro", "licenseKey"], (localData) => {
    chrome.storage.sync.get(["isPro", "licenseKey"], (syncData) => {
      let isPro = !!localData.isPro || !!syncData.isPro;
      let licenseKey = localData.licenseKey || syncData.licenseKey || "";
      
      // Auto-activate Pro if valid license key exists in storage
      if (!isPro && licenseKey.startsWith("MAIL-") && licenseKey.length >= 18) {
        isPro = true;
      }
      
      // Align storage if there are discrepancies
      if (isPro !== localData.isPro || isPro !== syncData.isPro || licenseKey !== localData.licenseKey || licenseKey !== syncData.licenseKey) {
        chrome.storage.local.set({ isPro: isPro, licenseKey: licenseKey });
        chrome.storage.sync.set({ isPro: isPro, licenseKey: licenseKey });
      }
      
      currentLanguage = localData.lang || "en";
      langToggle.innerText = currentLanguage === "hi" ? "EN" : "हिं";
      
      updateProBadgeUI(isPro);
      applyLanguage(currentLanguage);
    });
  });

  // 2. Pre-load active email details
  await initializeActiveEmailState();

  // 3. Tab Bindings
  tabBtnScan.addEventListener("click", () => switchTab("scan"));
  tabBtnDash.addEventListener("click", () => switchTab("dash"));
  tabBtnHistory.addEventListener("click", () => switchTab("history"));

  // 4. Action Bindings
  scanBtn.addEventListener("click", handleScan);
  trustBtn.addEventListener("click", handleToggleTrust);
  copyWarningBtn.addEventListener("click", handleCopyWarning);
  exportPdfBtn.addEventListener("click", handleExportReport);
  exportCsvBtn.addEventListener("click", handleExportCsv);
  exportJsonBtn.addEventListener("click", handleExportJson);
  proBadge.addEventListener("click", handleToggleProSimulator);
  langToggle.addEventListener("click", handleToggleLanguage);

  // Lemon Squeezy Monthly & Lifetime Links
  if (upgradeMonthlyLink) {
    upgradeMonthlyLink.addEventListener("click", (e) => {
      e.preventDefault();
      const url = upgradeMonthlyLink.getAttribute("href");
      chrome.tabs.create({ url: url });
    });
  }
  if (upgradeLifetimeLink) {
    upgradeLifetimeLink.addEventListener("click", (e) => {
      e.preventDefault();
      const url = upgradeLifetimeLink.getAttribute("href");
      chrome.tabs.create({ url: url });
    });
  }

  // License key activation system click handler
  if (licenseBtn) {
    licenseBtn.addEventListener("click", () => {
      const key = licenseInput.value.trim();
      
      // Helper function to apply successful Pro activation
      const activateProLocal = (successMsg) => {
        chrome.storage.local.set({ licenseKey: key, isPro: true }, () => {
          chrome.storage.sync.set({ isPro: true }, () => {
            // Update UI
            updateProBadgeUI(true);
            
            // Unhide scan button & hide upgrade container
            getScanCount((count) => {
              checkUpgradeRequirement(count, true);
            });
            
            // Show success message
            licenseMessage.className = "license-message success";
            licenseMessage.innerText = successMsg || translations[currentLanguage].licenseSuccess;
            licenseMessage.classList.remove("hidden");
            
            // Clear input
            licenseInput.value = "";
          });
        });
      };

      // 1. Developer testing mode override
      if (key === "MAIL-DEV-HARISH-2026") {
        activateProLocal("✅ Developer Mode Activated! Enjoy permanent Pro access.");
        return;
      }

      // 2. Validate standard license format locally first
      if (key.startsWith("MAIL-") && key.length >= 18) {
        licenseMessage.className = "license-message";
        licenseMessage.innerText = currentLanguage === "hi" ? "सत्यापित किया जा रहा है..." : "Validating key...";
        licenseMessage.classList.remove("hidden");
        
        // Send message to background script for Lemon Squeezy API validation
        chrome.runtime.sendMessage({
          action: "validateLicense",
          licenseKey: key
        }, (response) => {
          if (chrome.runtime.lastError || !response || !response.success) {
            const errMsg = response?.error || chrome.runtime.lastError?.message || "Verification failed.";
            licenseMessage.className = "license-message error";
            licenseMessage.innerText = `❌ ${errMsg}`;
            licenseMessage.classList.remove("hidden");
          } else {
            activateProLocal(translations[currentLanguage].licenseSuccess);
          }
        });
      } else {
        // Invalid license key format
        licenseMessage.className = "license-message error";
        licenseMessage.innerText = translations[currentLanguage].licenseError;
        licenseMessage.classList.remove("hidden");
      }
    });
  }
});

/**
 * Escapes HTML characters to prevent cross-site scripting (XSS) injection.
 */
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Hardened scan count getter that retrieves the maximum value between
 * chrome.storage.local and chrome.storage.sync to prevent easy local-storage bypasses.
 */
function getScanCount(callback) {
  chrome.storage.local.get("scanCount", (localData) => {
    chrome.storage.sync.get("scanCount", (syncData) => {
      const localCount = localData.scanCount || 0;
      const syncCount = syncData.scanCount || 0;
      const maxCount = Math.max(localCount, syncCount);
      
      // Auto-align out-of-sync values
      if (localCount !== maxCount || syncCount !== maxCount) {
        chrome.storage.local.set({ scanCount: maxCount });
        chrome.storage.sync.set({ scanCount: maxCount });
      }
      
      callback(maxCount);
    });
  });
}

/**
 * Hardened scan count updater that increments and syncs the scan count across both local and sync storages.
 */
function incrementScanCount(callback) {
  getScanCount((count) => {
    const nextCount = count + 1;
    chrome.storage.local.set({ scanCount: nextCount }, () => {
      chrome.storage.sync.set({ scanCount: nextCount }, () => {
        if (callback) callback(nextCount);
      });
    });
  });
}

/**
 * Extracts domain name from a sender description.
 */
function getDomainFromSender(sender) {
  if (!sender) return "";
  const emailMatch = sender.match(/<([^>]+)>/) || sender.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  const email = emailMatch ? emailMatch[1] : sender;
  return (email.split('@')[1] || '').toLowerCase().trim();
}

/**
 * Loads active Gmail email and checks cache or whitelist.
 */
async function initializeActiveEmailState() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url && tab.url.includes("mail.google.com")) {
      const emailData = await getEmailDataFromTab(tab.id);
      if (emailData && emailData.sender) {
        currentEmailData = emailData;
        currentSenderDomain = getDomainFromSender(emailData.sender);
        
        // Show Trust Button
        trustBtn.classList.remove("hidden");
        
        chrome.storage.local.get(["cachedScans", "whitelist", "isPro"], (data) => {
          const whitelist = data.whitelist || [];
          const isPro = !!data.isPro;
          
          getScanCount((scanCount) => {
            updateScanFooter(scanCount);
            checkUpgradeRequirement(scanCount, isPro);
            updateTrustButtonUI(whitelist.includes(currentSenderDomain));

            // Whitelist check
            if (currentSenderDomain && whitelist.includes(currentSenderDomain)) {
              const whitelistResult = {
                verdict: "SAFE",
                reason: translations[currentLanguage].whitelistedVerdict,
                score: 0,
                checks: {
                  sender_check: { passed: true, detail: translations[currentLanguage].trustedCheck },
                  urgency_check: { passed: true, detail: "Bypassed" },
                  link_check: { passed: true, detail: "Bypassed" },
                  content_check: { passed: true, detail: "Bypassed" },
                  domain_check: { passed: true, detail: "Bypassed" },
                  attachment_check: { passed: true, detail: "Bypassed" }
                },
                isWhitelisted: true
              };
              currentVerdictData = whitelistResult;
              updateVerdictUI(whitelistResult);
              return;
            }

            // Cache check
            if (emailData.emailKey && data.cachedScans && data.cachedScans[emailData.emailKey]) {
              const cached = data.cachedScans[emailData.emailKey];
              currentVerdictData = cached;
              updateVerdictUI(cached);
            }
          });
        });
        return;
      }
    }
  } catch (err) {
    console.warn("Error initializing active email state:", err);
  }
  
  // Neutral state fallback
  chrome.storage.local.get("isPro", (data) => {
    getScanCount((scanCount) => {
      updateScanFooter(scanCount);
      checkUpgradeRequirement(scanCount, !!data.isPro);
    });
  });
}

/**
 * Handles Tab Switching.
 */
function switchTab(tab) {
  tabBtnScan.classList.remove("active");
  tabBtnDash.classList.remove("active");
  tabBtnHistory.classList.remove("active");
  panelScan.classList.add("hidden");
  panelDash.classList.add("hidden");
  panelHistory.classList.add("hidden");

  if (tab === "scan") {
    tabBtnScan.classList.add("active");
    panelScan.classList.remove("hidden");
  } else if (tab === "dash") {
    tabBtnDash.classList.add("active");
    panelDash.classList.remove("hidden");
    loadDashboardData();
  } else if (tab === "history") {
    tabBtnHistory.classList.add("active");
    panelHistory.classList.remove("hidden");
    loadHistoryData();
  }
}

/**
 * Populates and renders the dashboard information.
 */
function loadDashboardData() {
  chrome.storage.local.get(["stats", "whitelist"], (data) => {
    const stats = data.stats || { totalScanned: 0, threatsBlocked: 0, suspiciousFound: 0, dailyScans: {} };
    const whitelist = data.whitelist || [];

    // Numbers
    dashScannedVal.innerText = stats.totalScanned || 0;
    dashThreatsVal.innerText = stats.threatsBlocked || 0;
    dashSuspiciousVal.innerText = stats.suspiciousFound || 0;

    // Render CSS chart
    render7DayChart(stats.dailyScans || {});

    // Render whitelist list
    renderWhitelistList(whitelist);
  });
}

/**
 * Renders the 7-day scan CSS vertical chart.
 */
function render7DayChart(dailyScans) {
  chartBars.innerHTML = "";
  const last7Days = [];
  const daysOfWeek = translations[currentLanguage].days;

  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().split('T')[0];
    const dayName = daysOfWeek[d.getDay()];
    last7Days.push({ dateStr, dayName });
  }

  let maxCount = 1;
  last7Days.forEach(day => {
    const count = dailyScans[day.dateStr] || 0;
    if (count > maxCount) maxCount = count;
  });

  last7Days.forEach(day => {
    const count = dailyScans[day.dateStr] || 0;
    const heightPercent = (count / maxCount) * 100;

    const col = document.createElement("div");
    col.className = "chart-bar-col";
    col.innerHTML = `
      <div class="chart-bar-wrapper" title="${day.dateStr}: ${count} scans">
        <div class="chart-bar-fill" style="height: ${heightPercent}%"></div>
      </div>
      <span class="chart-bar-label">${day.dayName}</span>
    `;
    chartBars.appendChild(col);
  });
}

/**
 * Renders the whitelisted domains management list.
 */
function renderWhitelistList(whitelist) {
  whitelistList.innerHTML = "";
  if (whitelist.length === 0) {
    whitelistEmptyMsg.classList.remove("hidden");
    return;
  }
  whitelistEmptyMsg.classList.add("hidden");

  whitelist.forEach(domain => {
    const li = document.createElement("li");
    li.className = "whitelist-item";
    const escapedDomain = escapeHtml(domain);
    li.innerHTML = `
      <span>${escapedDomain}</span>
      <button class="whitelist-remove-btn" data-domain="${escapedDomain}">Remove</button>
    `;
    
    li.querySelector(".whitelist-remove-btn").addEventListener("click", () => {
      handleRemoveFromWhitelist(domain);
    });
    
    whitelistList.appendChild(li);
  });
}

/**
 * Handles Whitelist removals from Dashboard.
 */
function handleRemoveFromWhitelist(domain) {
  chrome.storage.local.get("whitelist", (data) => {
    const whitelist = data.whitelist || [];
    const updated = whitelist.filter(d => d !== domain);
    chrome.storage.local.set({ whitelist: updated }, () => {
      loadDashboardData();
      if (domain === currentSenderDomain) {
        updateTrustButtonUI(false);
      }
    });
  });
}

/**
 * Populates and renders the scan history.
 */
function loadHistoryData() {
  chrome.storage.local.get(["scanHistory", "isPro"], (data) => {
    const history = data.scanHistory || [];
    const isPro = !!data.isPro;

    historyList.innerHTML = "";
    if (history.length === 0) {
      historyEmptyMsg.classList.remove("hidden");
      historyUpgradePrompt.classList.add("hidden");
      return;
    }
    historyEmptyMsg.classList.add("hidden");

    // Free users see 5, Pro users see all (up to 50)
    const limit = isPro ? 50 : 5;
    const displayed = history.slice(0, limit);

    displayed.forEach(item => {
      const icon = item.verdict === "SAFE" ? "✅" : (item.verdict === "SUSPICIOUS" ? "⚠️" : "🚨");
      
      let verdictClass = "level-safe";
      if (item.verdict === "SUSPICIOUS") verdictClass = "level-suspicious";
      if (item.verdict === "DANGEROUS") verdictClass = "level-dangerous";

      const senderClean = item.sender.length > 25 ? item.sender.substring(0, 23) + "..." : item.sender;
      const subjectClean = item.subject.length > 30 ? item.subject.substring(0, 28) + "..." : item.subject;

      const div = document.createElement("div");
      div.className = "history-item";
      div.innerHTML = `
        <span class="history-verdict-icon">${icon}</span>
        <div class="history-info">
          <div class="history-meta">
            <span class="history-sender" title="${escapeHtml(item.sender)}">${escapeHtml(senderClean)}</span>
            <span>${escapeHtml(item.timestamp)}</span>
          </div>
          <div class="history-meta">
            <span class="history-subject" title="${escapeHtml(item.subject)}">${escapeHtml(subjectClean)}</span>
            <span style="font-weight: 700;">${escapeHtml(item.score)}/100</span>
          </div>
        </div>
      `;
      historyList.appendChild(div);
    });

    // Toggle upgrade card in history tab
    if (!isPro && history.length > 5) {
      historyUpgradePrompt.classList.remove("hidden");
    } else {
      historyUpgradePrompt.classList.add("hidden");
    }
  });
}

/**
 * Toggles domain trust (whitelisting) from Scan tab.
 */
function handleToggleTrust() {
  if (!currentSenderDomain) return;

  chrome.storage.local.get("whitelist", (data) => {
    const whitelist = data.whitelist || [];
    const exists = whitelist.includes(currentSenderDomain);
    
    let updated;
    if (exists) {
      updated = whitelist.filter(d => d !== currentSenderDomain);
    } else {
      updated = [...whitelist, currentSenderDomain];
    }

    chrome.storage.local.set({ whitelist: updated }, () => {
      updateTrustButtonUI(!exists);
      // Trigger a check to refresh scan UI state for current sender
      initializeActiveEmailState();
    });
  });
}

/**
 * Updates whitelisting button appearance.
 */
function updateTrustButtonUI(isTrusted) {
  const label = isTrusted 
    ? translations[currentLanguage].untrustSender 
    : translations[currentLanguage].trustSender;
  trustBtn.querySelector("span").innerText = label;
  
  if (isTrusted) {
    trustBtn.classList.add("btn-secondary");
    trustBtn.classList.remove("btn-primary");
  } else {
    trustBtn.classList.remove("btn-secondary");
  }
}

/**
 * Copies Phishing Warning Alert Text to clipboard.
 */
function handleCopyWarning() {
  if (!currentVerdictData || !currentEmailData) return;

  const verdict = currentLanguage === "hi" 
    ? (currentVerdictData.verdict === "SUSPICIOUS" ? "संदेहास्पद" : "खतरनाक")
    : currentVerdictData.verdict;

  let text;
  if (currentLanguage === "hi") {
    text = `⚠️ MailArmour चेतावनी: ${currentEmailData.sender} से प्राप्त इस ईमेल को ${currentVerdictData.score}/100 फ़िशिंग संभावना के साथ ${verdict} के रूप में चिह्नित किया गया है।`;
  } else {
    text = `⚠️ MailArmour Alert: This email from ${currentEmailData.sender} was flagged as ${verdict} with ${currentVerdictData.score}/100 phishing probability. Do not click any links or download attachments. Stay safe — MailArmour`;
  }

  navigator.clipboard.writeText(text).then(() => {
    const span = copyWarningBtn.querySelector("span");
    const originalText = span.innerText;
    span.innerText = translations[currentLanguage].copied;
    setTimeout(() => {
      span.innerText = originalText;
    }, 2000);
  });
}

/**
 * Handles PDF export clicks (Pro Tier exclusive).
 */
function handleExportReport() {
  chrome.storage.local.get("isPro", (data) => {
    if (!data.isPro) {
      alert(translations[currentLanguage].proFeatureAlert);
    } else {
      // Open report window inside extension
      chrome.tabs.create({ url: "report.html" });
    }
  });
}

/**
 * Toggles simulator between Free & Pro mode.
 */
function handleToggleProSimulator() {
  chrome.storage.local.get("isPro", (data) => {
    const nextPro = !data.isPro;
    chrome.storage.local.set({ isPro: nextPro }, () => {
      updateProBadgeUI(nextPro);
      initializeActiveEmailState();
      
      // Refresh current view if active
      if (!panelDash.classList.contains("hidden")) loadDashboardData();
      if (!panelHistory.classList.contains("hidden")) loadHistoryData();
    });
  });
}

/**
 * Updates Pro simulator badge appearance in header.
 */
function updateProBadgeUI(isPro) {
  if (isPro) {
    proBadge.className = "pro-badge pro-mode";
    proBadge.innerText = "Pro";
    if (licenseContainer) licenseContainer.classList.add("hidden");
    if (scanCountText) scanCountText.classList.add("hidden");
  } else {
    proBadge.className = "pro-badge free-mode";
    proBadge.innerText = "Free";
    if (licenseContainer) licenseContainer.classList.remove("hidden");
    if (scanCountText) scanCountText.classList.remove("hidden");
  }
}

/**
 * Swaps interface language between English and Hindi.
 */
function handleToggleLanguage() {
  const nextLang = currentLanguage === "en" ? "hi" : "en";
  currentLanguage = nextLang;
  
  chrome.storage.local.set({ lang: nextLang }, () => {
    langToggle.innerText = nextLang === "hi" ? "EN" : "हिं";
    applyLanguage(nextLang);
    
    // Refresh current UI details
    if (currentVerdictData) updateVerdictUI(currentVerdictData);
    if (currentSenderDomain) {
      chrome.storage.local.get("whitelist", (data) => {
        updateTrustButtonUI((data.whitelist || []).includes(currentSenderDomain));
      });
    }
    if (!panelDash.classList.contains("hidden")) loadDashboardData();
    if (!panelHistory.classList.contains("hidden")) loadHistoryData();
  });
}

/**
 * Translates popup text labels.
 */
function applyLanguage(lang) {
  const t = translations[lang];

  // Tab Buttons
  tabBtnScan.querySelector(".tab-btn-text").innerText = t.tabScan;
  tabBtnDash.querySelector(".tab-btn-text").innerText = t.tabDash;
  tabBtnHistory.querySelector(".tab-btn-text").innerText = t.tabHistory;

  // Scan panel
  scanBtn.querySelector(".btn-text").innerText = scanBtn.disabled ? t.scanningBtn : t.scanBtn;
  riskScoreLabel.innerText = t.riskLabel;
  checklistHeading.innerText = t.checklistHeading;
  upgradeMessage.innerText = t.upgradeMsg;
  if (licenseHeading) licenseHeading.innerText = t.licenseHeading;
  if (licenseBtn) licenseBtn.innerText = t.licenseBtn;
  copyWarningBtn.querySelector("span").innerText = t.copyWarning;

  // Dashboard panel
  dashScannedLabel.innerText = t.scannedLabel;
  dashThreatsLabel.innerText = t.threatsLabel;
  dashSuspiciousLabel.innerText = t.suspiciousLabel;
  chartHeading.innerText = t.chartHeading;
  whitelistHeading.innerText = t.whitelistHeading;
  whitelistEmptyMsg.innerText = t.whitelistEmpty;
  exportPdfBtn.querySelector("span").innerText = t.exportReport;

  // History panel
  historyHeading.innerText = t.historyHeading;
  historyEmptyMsg.innerText = t.historyEmpty;
  historyUpgradeText.innerText = t.historyUpgradeText;

  // If status is neutral, translate status text
  if (statusCard.classList.contains("state-neutral")) {
    statusText.innerText = t.neutralStatus;
  } else if (statusCard.classList.contains("state-loading")) {
    statusText.innerText = t.loadingStatus;
  }
}

/**
 * Updates scan count footer statistics.
 */
function updateScanCountStats(callback) {
  incrementScanCount((incremented) => {
    updateScanFooter(incremented);
    chrome.storage.local.get("isPro", (proData) => {
      checkUpgradeRequirement(incremented, !!proData.isPro);
      if (callback) callback(incremented);
    });
  });
}

/**
 * Updates footer scan counter copy.
 */
function updateScanFooter(count) {
  const displayCount = Math.min(count, MAX_FREE_SCANS);
  scanCountText.innerText = translations[currentLanguage].freeScansUsed
    .replace("{count}", displayCount)
    .replace("{max}", MAX_FREE_SCANS);
}

/**
 * Toggles upgrade notice block visibility.
 */
function checkUpgradeRequirement(count, isPro) {
  if (!isPro && count >= MAX_FREE_SCANS) {
    scanBtn.classList.add("hidden");
    upgradeContainer.classList.remove("hidden");
    return true;
  }
  scanBtn.classList.remove("hidden");
  upgradeContainer.classList.add("hidden");
  return false;
}

/**
 * Executes a manual scanning request from Popup.
 */
async function handleScan() {
  hideError();
  
  chrome.storage.local.get(["cachedScans", "isPro"], async (data) => {
    const cachedScans = data.cachedScans || {};
    const isPro = !!data.isPro;

    getScanCount(async (scanCount) => {
      if (!isPro && scanCount >= MAX_FREE_SCANS) {
        checkUpgradeRequirement(scanCount, isPro);
        return;
      }

      setLoadingState(true);

      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) throw new Error("Could not find active tab.");

        if (!tab.url || !tab.url.includes("mail.google.com")) {
          throw new Error("Please open an email in Gmail first");
        }

        const emailData = await getEmailDataFromTab(tab.id);
        if (!emailData || emailData.error) {
          throw new Error(emailData?.error || "Please open an email in Gmail first");
        }

        currentEmailData = emailData;
        currentSenderDomain = getDomainFromSender(emailData.sender);
        trustBtn.classList.remove("hidden");

        const emailKey = emailData.emailKey || `${emailData.sender}_${emailData.subject}`.toLowerCase().replace(/[^a-z0-9]/g, "");

        // Send analysis request to background service worker proxy
        chrome.runtime.sendMessage({
          action: "analyzeEmail",
          emailData: {
            subject: emailData.subject,
            sender: emailData.sender,
            body: emailData.body
          }
        }, (response) => {
          setLoadingState(false);

          if (chrome.runtime.lastError || !response || !response.success) {
            const errMsg = response?.error || chrome.runtime.lastError?.message || "Failed to connect to backend.";
            showError(errMsg);
            resetToNeutralState();
            return;
          }

          const result = response.result;
          
          // Append client-side attachment check
          const attachments = emailData.attachments || [];
          const dangerousExtensions = ['.exe', '.zip', '.rar', '.bat', '.js', '.vbs'];
          const dangerous = attachments.filter(a => dangerousExtensions.includes(a.ext));
          
          result.checks.attachment_check = {
            passed: dangerous.length === 0,
            detail: dangerous.length === 0
              ? (attachments.length > 0 ? `${attachments.length} attachment(s) verified.` : "No attachments.")
              : `Dangerous: ${dangerous.map(a => a.name).join(', ')}`
          };

          // Cache result and update count
          cachedScans[emailKey] = result;
          
          chrome.storage.local.set({ cachedScans: cachedScans }, () => {
            incrementScanCount((newCount) => {
          currentVerdictData = result;
          updateVerdictUI(result);
          updateScanFooter(newCount);
          checkUpgradeRequirement(newCount, isPro);
          
          // Increment stats & history
          chrome.storage.local.get(["stats", "scanHistory"], (dataStore) => {
            const stats = dataStore.stats || { totalScanned: 0, threatsBlocked: 0, suspiciousFound: 0, dailyScans: {} };
            const history = dataStore.scanHistory || [];

            stats.totalScanned = (stats.totalScanned || 0) + 1;
            if (result.verdict === "DANGEROUS") {
              stats.threatsBlocked = (stats.threatsBlocked || 0) + 1;
            } else if (result.verdict === "SUSPICIOUS") {
              stats.suspiciousFound = (stats.suspiciousFound || 0) + 1;
            }

            const todayStr = new Date().toISOString().split('T')[0];
            if (!stats.dailyScans) stats.dailyScans = {};
            stats.dailyScans[todayStr] = (stats.dailyScans[todayStr] || 0) + 1;

            const options = { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
            const timestampStr = new Date().toLocaleDateString('en-US', options);

            const historyItem = {
              verdict: result.verdict,
              score: result.score,
              sender: emailData.sender,
              subject: emailData.subject,
              timestamp: timestampStr
            };

            history.unshift(historyItem);
            if (history.length > 50) history.pop();

            chrome.storage.local.set({ stats, scanHistory: history });
          });
        });
      });
    });

  } catch (err) {
      console.error("MailArmour scan failed:", err);
      showError(err.message || "Could not connect to server. Try again.");
      resetToNeutralState();
      setLoadingState(false);
    }
  });
});
}

/**
 * Message-passing client to query Gmail contents from content script.
 */
function getEmailDataFromTab(tabId) {
  return new Promise((resolve) => {
    chrome.tabs.get(tabId, (tab) => {
      const tabUrl = tab ? tab.url : "unknown";
      console.log(`[MailArmour Popup] getEmailDataFromTab invoked. Active tab ID: ${tabId}, Active tab URL: ${tabUrl}`);
      console.log(`[MailArmour Popup] Dispatching getEmailContent message to tab ${tabId}`);
      
      chrome.tabs.sendMessage(tabId, { action: "getEmailContent" }, (response) => {
        if (chrome.runtime.lastError) {
          console.error(`[MailArmour Popup] Message dispatch failed. chrome.runtime.lastError:`, chrome.runtime.lastError.message);
          console.log(`[MailArmour Popup] getEmailDataFromTab returning null due to lastError`);
          resolve(null);
        } else {
          console.log(`[MailArmour Popup] Message response received:`, response);
          if (response === null || response === undefined) {
            console.log(`[MailArmour Popup] getEmailDataFromTab returning null (response is null/undefined)`);
            resolve(null);
          } else {
            console.log(`[MailArmour Popup] getEmailDataFromTab returning successfully`);
            resolve(response);
          }
        }
      });
    });
  });
}

/**
 * Toggles the loading UI.
 */
function setLoadingState(isLoading) {
  if (isLoading) {
    scanBtn.disabled = true;
    scanBtn.querySelector(".btn-text").innerText = translations[currentLanguage].scanningBtn;
    scanBtn.querySelector(".btn-spinner").classList.remove("hidden");
    
    statusCard.className = "status-card state-loading";
    statusIcon.innerHTML = '<div class="spinner"></div>';
    statusText.innerText = translations[currentLanguage].loadingStatus;
    reasonContainer.classList.add("hidden");
    riskScoreContainer.classList.add("hidden");
    checklistContainer.classList.add("hidden");
    copyWarningBtn.classList.add("hidden");
  } else {
    scanBtn.disabled = false;
    scanBtn.querySelector(".btn-text").innerText = translations[currentLanguage].scanBtn;
    scanBtn.querySelector(".btn-spinner").classList.add("hidden");
  }
}

/**
 * Populates security audit metrics checklist.
 */
function renderChecklist(checks) {
  checklistItems.innerHTML = "";
  
  const checkKeys = [
    { key: "sender_check", title: translations[currentLanguage].sender_check },
    { key: "domain_check", title: translations[currentLanguage].domain_check },
    { key: "urgency_check", title: translations[currentLanguage].urgency_check },
    { key: "link_check", title: translations[currentLanguage].link_check },
    { key: "content_check", title: translations[currentLanguage].content_check },
    { key: "attachment_check", title: translations[currentLanguage].attachment_check }
  ];

  checkKeys.forEach(item => {
    if (checks[item.key]) {
      const check = checks[item.key];
      const statusIconSymbol = check.passed ? "🟢" : "🔴";
      
      const checkItem = document.createElement("div");
      checkItem.className = "checklist-item";
      checkItem.innerHTML = `
        <span class="check-status-icon">${statusIconSymbol}</span>
        <div class="check-content">
          <span class="check-title">${escapeHtml(item.title)}</span>
          <span class="check-desc">${escapeHtml(check.detail)}</span>
        </div>
      `;
      checklistItems.appendChild(checkItem);
    }
  });
}

/**
 * Updates the verdict status panel details.
 */
function updateVerdictUI(result) {
  statusCard.className = "status-card";
  reasonContainer.classList.remove("hidden");
  reasonText.innerText = result.reason || "";
  riskScoreBar.className = "risk-score-bar";

  if (result.verdict === "SAFE" || result.verdict === "SUSPICIOUS" || result.verdict === "DANGEROUS") {
    riskScoreContainer.classList.remove("hidden");
    riskScoreValue.innerText = `${result.score}/100`;
    riskScoreBar.style.width = `${result.score}%`;
  } else {
    riskScoreContainer.classList.add("hidden");
  }

  // Populate checklist breakdown
  if (result.checks) {
    checklistContainer.classList.remove("hidden");
    renderChecklist(result.checks);
  } else {
    checklistContainer.classList.add("hidden");
  }

  // Render Verdict text in card
  let translatedStatus = "";
  if (result.verdict === "SAFE") {
    statusCard.classList.add("state-safe");
    statusIcon.innerText = "✅";
    translatedStatus = translations[currentLanguage].safeStatus;
    riskScoreBar.classList.add("level-safe");
    copyWarningBtn.classList.add("hidden");
  } else if (result.verdict === "SUSPICIOUS") {
    statusCard.classList.add("state-suspicious");
    statusIcon.innerText = "⚠️";
    translatedStatus = translations[currentLanguage].suspiciousStatus;
    riskScoreBar.classList.add("level-suspicious");
    copyWarningBtn.classList.remove("hidden");
  } else if (result.verdict === "DANGEROUS") {
    statusCard.classList.add("state-dangerous");
    statusIcon.innerText = "🚨";
    translatedStatus = translations[currentLanguage].dangerousStatus;
    riskScoreBar.classList.add("level-dangerous");
    copyWarningBtn.classList.remove("hidden");
  } else {
    resetToNeutralState();
    showError(result.reason || "Analysis failed, please try again");
  }
  statusText.innerText = translatedStatus;

  // Synthesize sound (unless whitelisted or preloaded silently)
  if (!result.isWhitelisted) {
    playVerdictSound(result.verdict);
  }
}

/**
 * Resets scanning interface to default state.
 */
function resetToNeutralState() {
  statusCard.className = "status-card state-neutral";
  statusIcon.innerText = "🔍";
  statusText.innerText = translations[currentLanguage].neutralStatus;
  reasonContainer.classList.add("hidden");
  riskScoreContainer.classList.add("hidden");
  checklistContainer.classList.add("hidden");
  riskScoreBar.style.width = "0%";
  copyWarningBtn.classList.add("hidden");
}

function showError(msg) {
  errorMessage.innerText = msg;
  errorMessage.classList.remove("hidden");
}

function hideError() {
  errorMessage.classList.add("hidden");
  errorMessage.innerText = "";
}

/**
 * Synthesizes specific auditory alerts using the browser's Web Audio API.
 */
function playVerdictSound(verdict) {
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const now = audioCtx.currentTime;

    if (verdict === "SAFE") {
      const playChime = (freq, duration, startTime) => {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = "sine";
        osc.frequency.setValueAtTime(freq, startTime);
        gain.gain.setValueAtTime(0.06, startTime);
        gain.gain.exponentialRampToValueAtTime(0.001, startTime + duration);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start(startTime);
        osc.stop(startTime + duration);
      };
      
      playChime(523.25, 0.20, now);        // C5
      playChime(659.25, 0.20, now + 0.08);  // E5
      playChime(783.99, 0.25, now + 0.16);  // G5

    } else if (verdict === "SUSPICIOUS") {
      const playBeep = (freq, duration, startTime) => {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = "triangle";
        osc.frequency.setValueAtTime(freq, startTime);
        gain.gain.setValueAtTime(0.10, startTime);
        gain.gain.exponentialRampToValueAtTime(0.001, startTime + duration);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start(startTime);
        osc.stop(startTime + duration);
      };
      
      playBeep(440.00, 0.25, now);        // A4
      playBeep(440.00, 0.25, now + 0.18);  // Second A4 beep

    } else if (verdict === "DANGEROUS") {
      const playTone = (freq, duration, startTime) => {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(freq, startTime);
        osc.frequency.exponentialRampToValueAtTime(freq * 1.5, startTime + duration * 0.4);
        gain.gain.setValueAtTime(0.12, startTime);
        gain.gain.exponentialRampToValueAtTime(0.01, startTime + duration);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start(startTime);
        osc.stop(startTime + duration);
      };
      
      playTone(587.33, 0.35, now);       // D5 tone
      playTone(587.33, 0.35, now + 0.22);  // Second overlapping tone
      playTone(880.00, 0.45, now + 0.45);  // A5 alarm tone
    }
  } catch (err) {
    console.warn("Failed to generate synthesized sound for verdict:", verdict, err);
  }
}

/**
 * Formats scan history as CSV and prompts download.
 */
function handleExportCsv() {
  chrome.storage.local.get("scanHistory", (data) => {
    const history = data.scanHistory || [];
    if (history.length === 0) {
      alert(currentLanguage === "hi" ? "कोई इतिहास उपलब्ध नहीं है।" : "No scan history to export.");
      return;
    }
    
    const csvRows = [["Date & Time", "Sender", "Subject", "Verdict", "Risk Score"]];
    history.forEach(item => {
      csvRows.push([
        `"${item.timestamp}"`,
        `"${item.sender.replace(/"/g, '""')}"`,
        `"${item.subject.replace(/"/g, '""')}"`,
        `"${item.verdict}"`,
        `"${item.score}/100"`
      ]);
    });
    
    const csvContent = csvRows.map(e => e.join(",")).join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `mailarmour-audit-history-${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });
}

/**
 * Formats scan history as JSON and prompts download.
 */
function handleExportJson() {
  chrome.storage.local.get("scanHistory", (data) => {
    const history = data.scanHistory || [];
    if (history.length === 0) {
      alert(currentLanguage === "hi" ? "कोई इतिहास उपलब्ध नहीं है।" : "No scan history to export.");
      return;
    }
    
    const jsonString = JSON.stringify(history, null, 2);
    const blob = new Blob([jsonString], { type: "application/json;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `mailarmour-audit-history-${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });
}

