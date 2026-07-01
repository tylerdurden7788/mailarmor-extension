/**
 * MailArmor Content Script
 * Runs inside Gmail pages. Responsible for injecting the inline security badge,
 * performing auto-scans via background service worker, caching results,
 * highlighting deceptive link mismatches and scam keywords inside email bodies,
 * and intercepting clicks on suspicious links to show a warning modal.
 */

// Inject MailArmor custom styles directly into Gmail page DOM
const style = document.createElement("style");
style.textContent = `
  .mailarmor-badge-container {
    display: inline-flex;
    align-items: center;
    margin-left: 12px;
    vertical-align: middle;
    font-family: 'Inter', sans-serif;
    position: relative;
  }
  .mailarmor-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    user-select: none;
    border: 1px solid transparent;
  }
  .mailarmor-badge:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 6px rgba(0,0,0,0.15);
  }
  .mailarmor-badge-loading {
    background-color: #f3f4f6;
    color: #374151;
    border-color: #d1d5db;
  }
  .mailarmor-badge-scan {
    background-color: #e8f0fe;
    color: #1a73e8;
    border-color: #d2e3fc;
  }
  .mailarmor-badge-scan:hover {
    background-color: #d2e3fc;
  }
  .mailarmor-badge-safe {
    background-color: #ecfdf5;
    color: #047857;
    border-color: #a7f3d0;
  }
  .mailarmor-badge-suspicious {
    background-color: #fffbeb;
    color: #b45309;
    border-color: #fde68a;
  }
  .mailarmor-badge-dangerous {
    background-color: #fef2f2;
    color: #b91c1c;
    border-color: #fecaca;
  }
  .mailarmor-badge-limit {
    background-color: #f3f4f6;
    color: #4b5563;
    border-color: #e5e7eb;
  }
  .mailarmor-badge-error {
    background-color: #f3f4f6;
    color: #4b5563;
    border-color: #e5e7eb;
  }

  /* Spinner */
  .mailarmor-spinner {
    width: 12px;
    height: 12px;
    border: 2px solid rgba(0, 0, 0, 0.1);
    border-top-color: #2563eb;
    border-radius: 50%;
    animation: mailarmor-spin 0.8s linear infinite;
    display: inline-block;
  }
  @keyframes mailarmor-spin {
    to { transform: rotate(360deg); }
  }

  /* Dropdown panel */
  .mailarmor-dropdown {
    position: absolute;
    top: 100%;
    left: 0;
    margin-top: 8px;
    width: 290px;
    background-color: #121824;
    border: 1px solid #212c3e;
    border-radius: 12px;
    box-shadow: 0 10px 15px -3px rgba(0,0,0,0.5), 0 4px 6px -2px rgba(0,0,0,0.3);
    color: #f3f4f6;
    z-index: 99999;
    padding: 14px;
    display: none;
    flex-direction: column;
    gap: 8px;
    text-align: left;
  }
  .mailarmor-dropdown.show {
    display: flex;
  }
  .mailarmor-dropdown-header {
    font-weight: 700;
    font-size: 13px;
    color: #2563eb;
    border-bottom: 1px solid #212c3e;
    padding-bottom: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .mailarmor-dropdown-close {
    cursor: pointer;
    color: #9ca3af;
    font-size: 16px;
    font-weight: bold;
    line-height: 1;
  }
  .mailarmor-dropdown-close:hover {
    color: #f3f4f6;
  }
  .mailarmor-checklist {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 6px;
  }
  .mailarmor-check-item {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 11px;
    line-height: 1.4;
  }
  .mailarmor-check-icon {
    font-size: 12px;
    margin-top: 1px;
  }
  .mailarmor-check-details {
    display: flex;
    flex-direction: column;
  }
  .mailarmor-check-title {
    font-weight: 600;
    color: #e5e7eb;
  }
  .mailarmor-check-desc {
    color: #9ca3af;
  }

  /* Suspicious link styling */
  .mailarmor-suspicious-link {
    border-bottom: 2px dashed #ef4444 !important;
    background-color: rgba(239, 68, 68, 0.1) !important;
    cursor: help !important;
    position: relative !important;
  }
  .mailarmor-suspicious-link::after {
    content: "⚠️ Deceptive link. Points to: " attr(data-mailarmor-dest);
    position: absolute;
    bottom: 100%;
    left: 50%;
    transform: translate(-50%, -6px);
    background-color: #1e293b;
    border: 1px solid #ef4444;
    color: #fca5a5;
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 10px;
    white-space: nowrap;
    box-shadow: 0 4px 6px rgba(0,0,0,0.4);
    z-index: 100000;
    visibility: hidden;
    opacity: 0;
    transition: opacity 0.2s ease, visibility 0.2s ease;
  }
  .mailarmor-suspicious-link:hover::after {
    visibility: visible;
    opacity: 1;
  }

  /* Scam Word Highlight style */
  .mailarmor-scam-word {
    border-bottom: 2px dashed #f59e0b !important;
    background-color: rgba(245, 158, 11, 0.15) !important;
    cursor: help !important;
    font-weight: 500;
  }
`;
document.head.appendChild(style);

let currentEmailKey = "";
const MAX_FREE_SCANS = 20;

/**
 * Extracts key elements from the Gmail DOM.
 */
function findGmailElements() {
  const subjectEl = document.querySelector(".hP");
  const subject = subjectEl ? subjectEl.innerText.trim() : "";

  const senderElements = document.querySelectorAll(".gD");
  let sender = "";
  if (senderElements.length > 0) {
    const activeSenderElement = senderElements[senderElements.length - 1];
    const senderEmail = activeSenderElement.getAttribute("email");
    const senderName = activeSenderElement.getAttribute("name") || activeSenderElement.innerText;
    sender = senderEmail ? `${senderName} <${senderEmail}>` : senderName;
  }

  const bodyElements = document.querySelectorAll(".a3s.aiL");
  let body = "";
  let bodyEl = null;
  if (bodyElements.length > 0) {
    bodyEl = bodyElements[bodyElements.length - 1];
    body = bodyEl.innerText.trim();
  }

  return { subjectEl, subject, sender, body, bodyEl };
}

/**
 * Periodically called or event-triggered to check if a new email has been loaded.
 */
function checkEmailOpened() {
  if (!isContextValid()) return;
  const elements = findGmailElements();
  
  if (!elements.subject || !elements.sender) {
    removeBadge();
    currentEmailKey = "";
    return;
  }

  const emailKey = `${elements.sender}_${elements.subject}`.toLowerCase().replace(/[^a-z0-9]/g, "");

  if (emailKey !== currentEmailKey) {
    currentEmailKey = emailKey;
    handleNewEmailOpen(elements, emailKey);
  }
}

/**
 * Helper to translate UI elements in content script.
 */
function getTranslation(key, lang) {
  const dict = {
    en: {
      scanBadge: "🛡️ Scan Email",
      safeBadge: "✅ Safe Email",
      suspiciousBadge: "⚠️ Suspicious",
      dangerousBadge: "🚨 Phishing Threat",
      loadingBadge: "Analyzing Email...",
      limitBadge: "🔒 Limit Reached",
      errorBadge: "⚠️ Error Scan",
      trustedBadge: "✅ Trusted Sender",
      reportTitle: "MailArmor Security Report",
      verdictLabel: "Verdict",
      riskLabel: "Risk",
      reasonLabel: "Reason",
      sender_check: "Sender Verification",
      urgency_check: "Urgency Check",
      link_check: "Links Check",
      content_check: "Content Verification",
      domain_check: "Domain Age Check",
      attachment_check: "Attachment Check",
      limitDesc: "You've used all 20 free scans. Open the MailArmor extension popup in your browser toolbar to upgrade to Pro for unlimited scans 🔒",
      passedText: "Passed",
      failedText: "Warning"
    },
    hi: {
      scanBadge: "🛡️ ईमेल स्कैन करें",
      safeBadge: "✅ सुरक्षित ईमेल",
      suspiciousBadge: "⚠️ संदेहास्पद",
      dangerousBadge: "🚨 फ़िशिंग ख़तरा",
      loadingBadge: "ईमेल विश्लेषण...",
      limitBadge: "🔒 सीमा समाप्त",
      errorBadge: "⚠️ त्रुटि स्कैन",
      trustedBadge: "✅ विश्वसनीय प्रेषक",
      reportTitle: "MailArmor सुरक्षा रिपोर्ट",
      verdictLabel: "फ़ैसला",
      riskLabel: "जोखिम",
      reasonLabel: "कारण",
      sender_check: "प्रेषक सत्यापन",
      urgency_check: "तात्कालिकता जांच",
      link_check: "लिंक जांच",
      content_check: "सामग्री सत्यापन",
      domain_check: "डोमेन आयु जांच",
      attachment_check: "अटैचमेंट जांच",
      limitDesc: "आपने सभी 20 मुफ़्त स्कैन का उपयोग कर लिया है। असीमित स्कैन के लिए अपग्रेड करने के लिए ब्राउज़र टूलबार में MailArmor एक्सटेंशन खोलें 🔒",
      passedText: "उत्तीर्ण",
      failedText: "चेतावनी"
    }
  };
  return dict[lang]?.[key] || dict['en']?.[key] || key;
}

/**
 * Safely checks if the extension context is still valid.
 * When the extension is reloaded or updated, the content script's context gets invalidated,
 * making chrome.runtime and chrome.storage APIs undefined or causing them to throw errors.
 */
function isContextValid() {
  return typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id && chrome.storage && chrome.storage.local;
}

/**
 * Escapes HTML special characters to prevent cross-site scripting (XSS) injections.
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
  if (!isContextValid()) return;
  chrome.storage.local.get("scanCount", (localData) => {
    if (!isContextValid()) return;
    chrome.storage.sync.get("scanCount", (syncData) => {
      if (!isContextValid()) return;
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
  if (!isContextValid()) return;
  getScanCount((count) => {
    if (!isContextValid()) return;
    const nextCount = count + 1;
    chrome.storage.local.set({ scanCount: nextCount }, () => {
      if (!isContextValid()) return;
      chrome.storage.sync.set({ scanCount: nextCount }, () => {
        if (callback) callback(nextCount);
      });
    });
  });
}

/**
 * Extracts sender domain.
 */
function getDomainFromSender(sender) {
  if (!sender) return "";
  const emailMatch = sender.match(/<([^>]+)>/) || sender.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  const email = emailMatch ? emailMatch[1] : sender;
  return (email.split('@')[1] || '').toLowerCase().trim();
}

/**
 * Detect Gmail attachments inside the current message DOM.
 */
function detectAttachments(bodyEl) {
  const dangerousExtensions = ['.exe', '.zip', '.rar', '.bat', '.js', '.vbs'];
  const attachments = [];
  if (!bodyEl) return attachments;

  const container = bodyEl.closest('.gE') || bodyEl.closest('.h7') || bodyEl.closest('.adn') || document;
  const nodes = container.querySelectorAll('.a1p, .brx, .aox, .vq, .a1a, .brh, a[download]');
  nodes.forEach(node => {
    const text = (node.textContent || node.innerText || node.getAttribute('download') || '').trim();
    if (text && text.includes('.')) {
      const match = text.match(/\.([a-zA-Z0-9]+)$/);
      if (match) {
        const ext = '.' + match[1].toLowerCase();
        if (!attachments.some(a => a.name === text)) {
          attachments.push({ name: text, ext: ext });
        }
      }
    }
  });
  return attachments;
}

/**
 * Updates global scan statistics and history inside local storage.
 */
function updateScanStatsAndHistory(result, sender, subject) {
  if (!isContextValid()) return;
  chrome.storage.local.get(["stats", "scanHistory"], (data) => {
    if (!isContextValid()) return;
    const stats = data.stats || { totalScanned: 0, threatsBlocked: 0, suspiciousFound: 0, dailyScans: {} };
    const history = data.scanHistory || [];

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
      sender: sender,
      subject: subject,
      timestamp: timestampStr
    };

    history.unshift(historyItem);
    if (history.length > 50) {
      history.pop();
    }

    chrome.storage.local.set({ stats, scanHistory: history });
  });
}

/**
 * Injects a modern custom Gmail-like toast notification.
 */
function showToast(message) {
  let toast = document.getElementById("mailarmor-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "mailarmor-toast";
    toast.style.cssText = `
      position: fixed;
      bottom: 30px;
      left: 30px;
      background-color: rgba(18, 24, 38, 0.95);
      color: #f3f4f6;
      border: 1px solid #212c3e;
      padding: 12px 20px;
      border-radius: 8px;
      font-family: 'Inter', sans-serif;
      font-size: 13px;
      font-weight: 500;
      z-index: 1000000;
      box-shadow: 0 10px 15px -3px rgba(0,0,0,0.5);
      backdrop-filter: blur(8px);
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      transform: translateY(100px);
      opacity: 0;
    `;
    document.body.appendChild(toast);
  }
  toast.innerText = message;
  toast.style.transform = "translateY(0)";
  toast.style.opacity = "1";
  setTimeout(() => {
    toast.style.transform = "translateY(100px)";
    toast.style.opacity = "0";
  }, 3000);
}

/**
 * Scans email text nodes and wraps scam keywords in warning classes.
 */
function highlightScamKeywords(element, lang) {
  if (!element) return;
  const keywords = [
    "urgent", "action required", "wire transfer", "gift card",
    "verify your account", "suspend", "password reset",
    "immediate action", "login details", "security alert",
    "तात्कालिक", "आवश्यक कार्रवाई", "बैंक ट्रांसफर", "गिफ्ट कार्ड",
    "सत्यापित करें", "खाता निलंबित", "पासवर्ड रीसेट"
  ];

  const walk = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null, false);
  const textNodes = [];
  let node;
  while (node = walk.nextNode()) {
    const parentName = node.parentNode.nodeName.toUpperCase();
    if (parentName !== 'SCRIPT' && parentName !== 'STYLE' && parentName !== 'NOSCRIPT' && parentName !== 'SPAN' && !node.parentNode.classList.contains('mailarmor-scam-word')) {
      textNodes.push(node);
    }
  }

  textNodes.forEach(textNode => {
    let content = escapeHtml(textNode.textContent);
    let modified = false;

    keywords.forEach(word => {
      const regex = new RegExp(`\\b(${word})\\b`, 'gi');
      const hasWord = lang === 'hi' ? content.toLowerCase().includes(word) : regex.test(content);
      if (hasWord) {
        const titleText = lang === 'hi' ? 'MailArmor चेतावनी: उच्च जोखिम वाला शब्द पाया गया।' : 'MailArmor Alert: High-risk keyword detected.';
        content = lang === 'hi'
          ? content.replace(new RegExp(word, 'g'), `<span class="mailarmor-scam-word" title="${titleText}">${word}</span>`)
          : content.replace(regex, `<span class="mailarmor-scam-word" title="${titleText}">$1</span>`);
        modified = true;
      }
    });

    if (modified) {
      const temp = document.createElement('div');
      temp.innerHTML = content;
      while (temp.firstChild) {
        textNode.parentNode.insertBefore(temp.firstChild, textNode);
      }
      textNode.parentNode.removeChild(textNode);
    }
  });
}

/**
 * Attaches click listeners on email body links to show a safety warning modal.
 */
function setupLinkClickInterception(bodyEl, result) {
  if (!bodyEl || !result || result.verdict === "SAFE") return;

  bodyEl.querySelectorAll('a').forEach(link => {
    if (link.dataset.mailarmorIntercepted) return;
    link.dataset.mailarmorIntercepted = "true";

    link.addEventListener('click', (e) => {
      e.preventDefault();
      const href = link.getAttribute('href');
      if (href && href.startsWith('http')) {
        showLinkWarningModal(href, result);
      }
    });
  });
}

/**
 * Injects overlay warning block modal in the tab body.
 */
function showLinkWarningModal(url, result) {
  const existing = document.getElementById("mailarmor-warning-modal");
  if (existing) existing.remove();

  if (!isContextValid()) return;
  chrome.storage.local.get("lang", (data) => {
    if (!isContextValid()) return;
    const lang = data.lang || "en";
    
    const modal = document.createElement("div");
    modal.id = "mailarmor-warning-modal";
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background-color: rgba(9, 13, 22, 0.85);
      backdrop-filter: blur(8px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000000;
      font-family: 'Inter', sans-serif;
    `;

    const box = document.createElement("div");
    box.style.cssText = `
      background-color: #121824;
      border: 1px solid #ef4444;
      border-radius: 16px;
      width: 450px;
      max-width: 90%;
      padding: 24px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.6);
      color: #f3f4f6;
      display: flex;
      flex-direction: column;
      gap: 16px;
    `;

    const titleText = lang === "hi" ? "🚨 MailArmor सुरक्षा चेतावनी" : "🚨 MailArmor Security Alert";
    const header = document.createElement("div");
    header.style.cssText = "font-size: 18px; font-weight: 700; color: #ef4444;";
    header.innerHTML = `<span>${titleText}</span>`;

    const transVerdict = lang === "hi" 
      ? (result.verdict === "SUSPICIOUS" ? "संदेहास्पद" : "खतरनाक")
      : result.verdict;
    const escapedVerdict = escapeHtml(transVerdict);
    const escapedScore = escapeHtml(result.score);
    const escapedUrl = escapeHtml(url);

    let bodyHtml = "";
    if (lang === "hi") {
      bodyHtml = `
        यह ईमेल <strong>${escapedVerdict}</strong> के रूप में चिह्नित किया गया है (जोखिम: <strong>${escapedScore}/100</strong>)।
        <br><br>
        आप जिस लिंक पर जा रहे हैं वह है:<br>
        <div style="background-color: rgba(255,255,255,0.03); border: 1px solid #212c3e; padding: 10px; border-radius: 8px; font-family: monospace; word-break: break-all; margin: 8px 0; color: #f59e0b;">
          ${escapedUrl}
        </div>
        फ़िशिंग साइटें अक्सर आधिकारिक लॉग इन स्क्रीनों की नकल करके आपके पासवर्ड और गोपनीय जानकारी चुराने का प्रयास करती हैं।
      `;
    } else {
      bodyHtml = `
        This email was flagged as <strong>${escapedVerdict}</strong> with a risk probability of <strong>${escapedScore}/100</strong>.
        <br><br>
        The link you clicked leads to:<br>
        <div style="background-color: rgba(255,255,255,0.03); border: 1px solid #212c3e; padding: 10px; border-radius: 8px; font-family: monospace; word-break: break-all; margin: 8px 0; color: #f59e0b;">
          ${escapedUrl}
        </div>
        Phishing pages often copy official banking or social login pages to harvest your credentials.
      `;
    }

    const bodyText = document.createElement("div");
    bodyText.style.cssText = "font-size: 13px; line-height: 1.5; color: #d1d5db;";
    bodyText.innerHTML = bodyHtml;

    const footer = document.createElement("div");
    footer.style.cssText = "display: flex; justify-content: flex-end; gap: 12px; margin-top: 8px;";

    const cancelBtn = document.createElement("button");
    cancelBtn.innerText = lang === "hi" ? "वापस जाएं (सुरक्षित)" : "Cancel (Go Back)";
    cancelBtn.style.cssText = `
      background-color: #2563eb;
      color: #ffffff;
      border: none;
      padding: 10px 18px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    `;

    const proceedBtn = document.createElement("button");
    proceedBtn.innerText = lang === "hi" ? "फिर भी आगे बढ़ें" : "Proceed Anyway";
    proceedBtn.style.cssText = `
      background-color: transparent;
      color: #9ca3af;
      border: 1px solid #212c3e;
      padding: 10px 18px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    `;

    cancelBtn.addEventListener('click', () => modal.remove());
    proceedBtn.addEventListener('click', () => {
      window.open(url, '_blank');
      modal.remove();
    });

    footer.appendChild(proceedBtn);
    footer.appendChild(cancelBtn);
    box.appendChild(header);
    box.appendChild(bodyText);
    box.appendChild(footer);
    modal.appendChild(box);
    document.body.appendChild(modal);
  });
}

/**
 * Orchestrates rendering the badge, checking caching, and triggering auto-scan.
 */
function handleNewEmailOpen(elements, emailKey) {
  if (!isContextValid()) return;
  chrome.storage.local.get(["lang"], (data) => {
    if (!isContextValid()) return;
    const lang = data.lang || "en";

    injectBadge(elements.subjectEl, lang, () => {
      performScan(elements, emailKey, lang);
    });
  });
}

/**
 * Triggers the actual scanning logic for the email when manually requested.
 */
function performScan(elements, emailKey, lang) {
  const badge = document.querySelector(".mailarmor-badge");
  if (!badge) return;

  badge.className = "mailarmor-badge mailarmor-badge-loading";
  badge.innerHTML = `<span class="mailarmor-spinner"></span> <span>${getTranslation("loadingBadge", lang)}</span>`;

  if (!isContextValid()) return;
  chrome.storage.local.get(["cachedScans", "whitelist", "isPro"], (data) => {
    if (!isContextValid()) return;
    const cachedScans = data.cachedScans || {};
    const whitelist = data.whitelist || [];
    const isPro = !!data.isPro;

    // 1. Whitelist check
    const domain = getDomainFromSender(elements.sender);
    if (domain && whitelist.includes(domain)) {
      const whitelistResult = {
        verdict: "SAFE",
        reason: lang === "hi" ? "यह प्रेषक आपकी विश्वसनीय सफ़ेद सूची में है।" : "Sender domain is in your trusted whitelist.",
        score: 0,
        checks: {
          sender_check: { passed: true, detail: lang === "hi" ? "सफ़ेद सूची में मौजूद।" : "Sender is whitelisted." },
          urgency_check: { passed: true, detail: "Bypassed" },
          link_check: { passed: true, detail: "Bypassed" },
          content_check: { passed: true, detail: "Bypassed" },
          domain_check: { passed: true, detail: "Bypassed" },
          attachment_check: { passed: true, detail: "Bypassed" }
        },
        isWhitelisted: true
      };
      
      updateBadgeUI(whitelistResult, lang);
      highlightSuspiciousLinks(elements.bodyEl);
      return;
    }

    // 2. Cache check
    if (cachedScans[emailKey]) {
      const attachments = detectAttachments(elements.bodyEl);
      const dangerousExtensions = ['.exe', '.zip', '.rar', '.bat', '.js', '.vbs'];
      const dangerous = attachments.filter(a => dangerousExtensions.includes(a.ext));
      
      cachedScans[emailKey].checks.attachment_check = {
        passed: dangerous.length === 0,
        detail: dangerous.length === 0 
          ? (attachments.length > 0 ? `${attachments.length} attachment(s) verified.` : "No attachments.")
          : `Dangerous: ${dangerous.map(a => a.name).join(', ')}`
      };

      updateBadgeUI(cachedScans[emailKey], lang);
      highlightSuspiciousLinks(elements.bodyEl);
      highlightScamKeywords(elements.bodyEl, lang);
      setupLinkClickInterception(elements.bodyEl, cachedScans[emailKey]);
      return;
    }

    // 3. Load hardened scan count to enforce limits check
    getScanCount((scanCount) => {
      if (!isPro && scanCount >= MAX_FREE_SCANS) {
        updateBadgeToLimitState(lang);
        return;
      }

      // 4. Background scan trigger
      if (!isContextValid()) return;
      chrome.runtime.sendMessage(
        {
          action: "analyzeEmail",
          emailData: {
            subject: elements.subject,
            sender: elements.sender,
            body: elements.body
          }
        },
        (response) => {
          if (!isContextValid()) return;
          if (chrome.runtime.lastError || !response || !response.success) {
            const errMsg = response?.error || chrome.runtime.lastError?.message || "Failed to scan.";
            updateBadgeToErrorState(errMsg, lang);
          } else {
            const result = response.result;
            
            const attachments = detectAttachments(elements.bodyEl);
            const dangerousExtensions = ['.exe', '.zip', '.rar', '.bat', '.js', '.vbs'];
            const dangerous = attachments.filter(a => dangerousExtensions.includes(a.ext));
            
            result.checks.attachment_check = {
              passed: dangerous.length === 0,
              detail: dangerous.length === 0
                ? (attachments.length > 0 ? `${attachments.length} attachment(s) verified.` : "No attachments.")
                : `Dangerous: ${dangerous.map(a => a.name).join(', ')}`
            };

            cachedScans[emailKey] = result;
            
            chrome.storage.local.set({ cachedScans: cachedScans }, () => {
              incrementScanCount((updatedCount) => {
                updateBadgeUI(result, lang);
                highlightSuspiciousLinks(elements.bodyEl);
                highlightScamKeywords(elements.bodyEl, lang);
                setupLinkClickInterception(elements.bodyEl, result);
                updateScanStatsAndHistory(result, elements.sender, elements.subject);
              });
            });
          }
        }
      );
    });
  });
}

/**
 * Creates and injects the badge structure into the DOM.
 */
function injectBadge(subjectEl, lang, onScanClick) {
  removeBadge();

  const container = document.createElement("div");
  container.id = "mailarmor-inline-badge-container";
  container.className = "mailarmor-badge-container";

  const badge = document.createElement("div");
  badge.className = "mailarmor-badge mailarmor-badge-scan";
  badge.innerHTML = getTranslation("scanBadge", lang);
  container.appendChild(badge);

  const dropdown = document.createElement("div");
  dropdown.className = "mailarmor-dropdown";
  dropdown.id = "mailarmor-inline-dropdown";
  container.appendChild(dropdown);

  badge.addEventListener("click", (e) => {
    e.stopPropagation();
    if (badge.classList.contains("mailarmor-badge-scan")) {
      onScanClick();
    } else if (!badge.classList.contains("mailarmor-badge-loading")) {
      dropdown.classList.toggle("show");
    }
  });

  dropdown.addEventListener("click", (e) => {
    e.stopPropagation();
  });

  // Note: Document click listener moved to global file scope to avoid memory leaks

  subjectEl.parentNode.insertBefore(container, subjectEl.nextSibling);
}

/**
 * Updates the UI state of the badge and dropdown with detailed metrics.
 */
function updateBadgeUI(result, lang) {
  const badge = document.querySelector(".mailarmor-badge");
  const dropdown = document.querySelector("#mailarmor-inline-dropdown");
  if (!badge || !dropdown) return;

  badge.className = "mailarmor-badge";
  
  if (result.isWhitelisted) {
    badge.classList.add("mailarmor-badge-safe");
    badge.innerHTML = getTranslation("trustedBadge", lang);
  } else if (result.verdict === "SAFE") {
    badge.classList.add("mailarmor-badge-safe");
    badge.innerHTML = getTranslation("safeBadge", lang);
  } else if (result.verdict === "SUSPICIOUS") {
    badge.classList.add("mailarmor-badge-suspicious");
    badge.innerHTML = getTranslation("suspiciousBadge", lang);
  } else if (result.verdict === "DANGEROUS") {
    badge.classList.add("mailarmor-badge-dangerous");
    badge.innerHTML = getTranslation("dangerousBadge", lang);
  }

  const checks = result.checks || {};
  const checkItems = [
    { key: "sender_check", title: getTranslation("sender_check", lang) },
    { key: "domain_check", title: getTranslation("domain_check", lang) },
    { key: "urgency_check", title: getTranslation("urgency_check", lang) },
    { key: "link_check", title: getTranslation("link_check", lang) },
    { key: "content_check", title: getTranslation("content_check", lang) },
    { key: "attachment_check", title: getTranslation("attachment_check", lang) }
  ];

  let checklistHtml = "";
  checkItems.forEach(item => {
    if (checks[item.key]) {
      const checkResult = checks[item.key];
      const checkIcon = checkResult.passed ? "🟢" : "🔴";
      checklistHtml += `
        <div class="mailarmor-check-item">
          <span class="mailarmor-check-icon">${checkIcon}</span>
          <div class="mailarmor-check-details">
            <span class="mailarmor-check-title">${escapeHtml(item.title)}</span>
            <span class="mailarmor-check-desc">${escapeHtml(checkResult.detail)}</span>
          </div>
        </div>
      `;
    }
  });

  let translatedVerdict = result.verdict;
  if (lang === "hi") {
    translatedVerdict = result.verdict === "SAFE" ? "सुरक्षित" : (result.verdict === "SUSPICIOUS" ? "संदेहास्पद" : "खतरनाक");
  }

  dropdown.innerHTML = `
    <div class="mailarmor-dropdown-header">
      <span>${escapeHtml(getTranslation("reportTitle", lang))}</span>
      <span class="mailarmor-dropdown-close">&times;</span>
    </div>
    <div style="font-size: 12px; font-weight: 700; margin-top: 4px; display: flex; justify-content: space-between;">
      <span>${escapeHtml(getTranslation("verdictLabel", lang))}: ${escapeHtml(translatedVerdict)}</span>
      <span style="color: ${result.verdict === 'SAFE' ? '#10b981' : result.verdict === 'SUSPICIOUS' ? '#f59e0b' : '#ef4444'}">${escapeHtml(result.score)}/100 ${escapeHtml(getTranslation("riskLabel", lang))}</span>
    </div>
    <div style="font-size: 11px; color: #9ca3af; margin-bottom: 6px; font-style: italic; line-height: 1.3;">
      "${escapeHtml(result.reason)}"
    </div>
    <div class="mailarmor-checklist">
      ${checklistHtml}
    </div>
  `;

  dropdown.querySelector(".mailarmor-dropdown-close").addEventListener("click", (e) => {
    e.stopPropagation();
    dropdown.classList.remove("show");
  });
}

function updateBadgeToLimitState(lang) {
  const badge = document.querySelector(".mailarmor-badge");
  const dropdown = document.querySelector("#mailarmor-inline-dropdown");
  if (!badge || !dropdown) return;

  badge.className = "mailarmor-badge mailarmor-badge-limit";
  badge.innerHTML = getTranslation("limitBadge", lang);

  dropdown.innerHTML = `
    <div class="mailarmor-dropdown-header">
      <span>${getTranslation("reportTitle", lang)}</span>
      <span class="mailarmor-dropdown-close">&times;</span>
    </div>
    <div style="font-size: 11px; color: #e5e7eb; margin-top: 6px; line-height: 1.4;">
      ${getTranslation("limitDesc", lang)}
    </div>
  `;

  dropdown.querySelector(".mailarmor-dropdown-close").addEventListener("click", (e) => {
    e.stopPropagation();
    dropdown.classList.remove("show");
  });
}

function updateBadgeToErrorState(errorMsg, lang) {
  const badge = document.querySelector(".mailarmor-badge");
  const dropdown = document.querySelector("#mailarmor-inline-dropdown");
  if (!badge || !dropdown) return;

  badge.className = "mailarmor-badge mailarmor-badge-error";
  badge.innerHTML = getTranslation("errorBadge", lang);

  dropdown.innerHTML = `
    <div class="mailarmor-dropdown-header">
      <span>${escapeHtml(getTranslation("reportTitle", lang))}</span>
      <span class="mailarmor-dropdown-close">&times;</span>
    </div>
    <div style="font-size: 11px; color: #fca5a5; margin-top: 6px; line-height: 1.4;">
      ${escapeHtml(errorMsg)}
    </div>
  `;

  dropdown.querySelector(".mailarmor-dropdown-close").addEventListener("click", (e) => {
    e.stopPropagation();
    dropdown.classList.remove("show");
  });
}

function removeBadge() {
  const badge = document.getElementById("mailarmor-inline-badge-container");
  if (badge) badge.remove();
}

/**
 * Scans the links in the email body and highlights mismatches.
 */
function highlightSuspiciousLinks(bodyEl) {
  if (!bodyEl) return;
  const links = bodyEl.querySelectorAll("a");

  links.forEach(link => {
    if (link.classList.contains("mailarmor-suspicious-link")) return;

    const href = link.getAttribute("href");
    if (!href) return;

    const text = link.innerText.trim();
    const domainRegex = /^(https?:\/\/)?([\w\-]+\.)+[\w\-]{2,}/i;

    if (domainRegex.test(text)) {
      const textDomain = getDomainFromUrl(text);
      const hrefDomain = getDomainFromUrl(href);

      if (textDomain && hrefDomain && textDomain !== hrefDomain) {
        link.classList.add("mailarmor-suspicious-link");
        link.setAttribute("data-mailarmor-dest", hrefDomain);
      }
    }
  });
}

/**
 * Helper to clean and parse the host/domain name from a URL string.
 */
function getDomainFromUrl(url) {
  try {
    let cleanUrl = url.trim();
    if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
      cleanUrl = "http://" + cleanUrl;
    }
    const parsed = new URL(cleanUrl);
    return parsed.hostname.replace("www.", "").toLowerCase();
  } catch (e) {
    return null;
  }
}

// Listen for messages from popup script & background shortcuts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!isContextValid()) return false;
  if (request.action === "getEmailContent") {
    try {
      const elements = findGmailElements();
      if (!elements.subject && !elements.sender && !elements.body) {
        sendResponse({ error: "No email open or content not found" });
      } else {
        const emailKey = `${elements.sender}_${elements.subject}`.toLowerCase().replace(/[^a-z0-9]/g, "");
        sendResponse({
          subject: elements.subject,
          sender: elements.sender,
          body: elements.body,
          emailKey: emailKey,
          attachments: detectAttachments(elements.bodyEl)
        });
      }
    } catch (err) {
      console.error("MailArmor getEmailContent listener error:", err);
      sendResponse({ error: "Failed to extract email contents: " + err.message });
    }
  } else if (request.action === "shortcutTriggered") {
    if (!isContextValid()) return false;
    chrome.storage.local.get("lang", (data) => {
      if (!isContextValid()) return;
      const lang = data.lang || "en";
      const toastMsg = lang === "hi" ? "MailArmor: स्कैनिंग..." : "MailArmor: Scanning...";
      showToast(toastMsg);

      const elements = findGmailElements();
      if (elements.subject && elements.sender) {
        const emailKey = `${elements.sender}_${elements.subject}`.toLowerCase().replace(/[^a-z0-9]/g, "");
        handleNewEmailOpen(elements, emailKey);
      }
    });
    sendResponse({ success: true });
  }
  return true;
});

// Setup listeners for URL hashchanges and periodic polling to catch dynamic Gmail rendering
window.addEventListener("hashchange", checkEmailOpened);
setInterval(checkEmailOpened, 1000);

// Global click listener to dismiss the inline badge dropdown contextually (resolves event listener accrual memory leak)
document.addEventListener("click", () => {
  if (!isContextValid()) return;
  const dropdown = document.getElementById("mailarmor-inline-dropdown");
  if (dropdown) {
    dropdown.classList.remove("show");
  }
});

console.log("MailArmor content script listener loaded successfully");
