/**
 * MailArmour Service Worker (Background Script)
 * Manifest V3 service worker running in the background.
 */

// ==========================================
// RUNTIME BUILD CONFIGURATION
// ==========================================
const IS_DEVELOPMENT_BUILD = true; // SET TO false FOR PRODUCTION BUILDS
const DEV_BYPASS_KEY = IS_DEVELOPMENT_BUILD ? "MAIL-DEV-HARISH-2026" : ""; // CLEAR FOR PRODUCTION
const DOMAIN_AGE_THRESHOLD_DAYS = 30;

// Log message when the background service worker starts up
console.log("MailArmour background service started");

// Listen for installation event
chrome.runtime.onInstalled.addListener(() => {
  console.log("MailArmour extension successfully installed");
});

// Listen for keyboard shortcuts
chrome.commands.onCommand.addListener((command) => {
  if (command === "trigger-scan") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && tabs[0].id) {
        chrome.tabs.sendMessage(tabs[0].id, { action: "shortcutTriggered" });
      }
    });
  }
});

// Proxy API requests from content scripts / popup to the local FastAPI server and perform domain checks
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeEmail") {
    const API_URL = "https://mailarmour-extension-production.up.railway.app/analyze";
    const emailData = request.emailData || {};
    
    // Extract domain from sender
    const senderStr = emailData.sender || "";
    const emailMatch = senderStr.match(/<([^>]+)>/) || senderStr.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    const email = emailMatch ? emailMatch[1] : senderStr;
    const domain = email.split('@')[1] || '';

    // Function to execute the domain age check
    const checkDomainAge = async (dom) => {
      let resultCheck = { passed: true, status: "verified", detail: "Domain age verified." };
      if (!dom) return resultCheck;
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      
      try {
        const response = await fetch(`https://api.domainsdb.info/v1/domains/search?domain=${dom}&zone=com`, {
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (response.ok) {
          const data = await response.json();
          if (data && data.domains && data.domains.length > 0) {
            const match = data.domains.find(d => d.domain.toLowerCase().includes(dom.toLowerCase())) || data.domains[0];
            if (match && match.create_date) {
              const createDate = new Date(match.create_date);
              const diffDays = Math.ceil(Math.abs(new Date() - createDate) / (1000 * 60 * 60 * 24));
              if (diffDays < DOMAIN_AGE_THRESHOLD_DAYS) {
                resultCheck = { passed: false, status: "suspicious", detail: `Newly registered domain (${diffDays} days old).` };
              } else {
                resultCheck = { passed: true, status: "verified", detail: `Domain is ${diffDays} days old.` };
              }
            }
          }
        } else {
          resultCheck = {
            passed: true,
            status: "unknown",
            neutral: true,
            detail: "Domain age could not be verified because the lookup service was unavailable. This does not indicate a phishing attempt."
          };
        }
      } catch (err) {
        console.warn("Domain age API failed or timed out:", err);
        clearTimeout(timeoutId);
        resultCheck = {
          passed: true,
          status: "unknown",
          neutral: true,
          detail: "Domain age could not be verified because the lookup service was unavailable. This does not indicate a phishing attempt."
        };
      }
      return resultCheck;
    };

    // Function to trace redirects of a shortened link
    const traceRedirect = async (url) => {
      const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", "is.gd", "buff.ly", "adf.ly"];
      try {
        const parsed = new URL(url);
        const host = parsed.hostname.toLowerCase().replace("www.", "");
        if (!shorteners.includes(host)) return null;

        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), 2000);
        // Follow redirect using HEAD method to fetch header details only
        const response = await fetch(url, { 
          method: "HEAD", 
          signal: controller.signal,
          redirect: "follow"
        });
        clearTimeout(id);
        
        if (response.url && response.url !== url) {
          return { original: url, resolved: response.url };
        }
      } catch (err) {
        console.warn("Redirect check failed for link:", url, err);
      }
      return null;
    };

    // Run backend analysis, domain age checker, and redirect tracers in parallel
    const runAnalysis = async () => {
      try {
        const serverPromise = fetch(API_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            subject: emailData.subject || "",
            sender: emailData.sender || "",
            body: emailData.body || ""
          })
        }).then(res => {
          if (!res.ok) throw new Error("Could not connect to server. Try again.");
          return res.json();
        });

        const domainPromise = checkDomainAge(domain);

        // Resolve redirects of any short links
        const links = emailData.links || [];
        const redirectPromises = links.map(traceRedirect);

        const results = await Promise.allSettled([
          serverPromise,
          domainPromise,
          Promise.all(redirectPromises)
        ]);

        let result = null;
        let serverFailed = false;

        if (results[0].status === "fulfilled") {
          result = results[0].value;
        } else {
          serverFailed = true;
          result = {
            verdict: "SAFE",
            score: 0,
            reason: "MailArmour cloud analysis is offline. Using local checks only.",
            user_explanation: "MailArmour cloud analysis is offline. Using local checks only.",
            checks: {}
          };
        }

        const domainCheckResult = results[1].status === "fulfilled" ? results[1].value : { passed: true, status: "unknown", neutral: true, detail: "Domain age could not be verified (Check Bypassed)" };
        const redirectTraces = results[2].status === "fulfilled" ? results[2].value : [];

        // Inject domain checker result
        if (!result.checks) result.checks = {};
        result.checks.domain_check = domainCheckResult;
        
        if (serverFailed) {
          result.checks.sender_check = { passed: true, detail: "Sender checks bypassed." };
          result.checks.urgency_check = { passed: true, detail: "Urgency checks bypassed." };
          result.checks.content_check = { passed: true, detail: "Content checks bypassed." };
          result.checks.attachment_check = { passed: true, detail: "Attachment checks bypassed." };
          
          if (domainCheckResult.status === "suspicious") {
            result.verdict = "SUSPICIOUS";
            result.score = 50;
            result.reason = `Local Warning: ${domainCheckResult.detail}. Cloud analysis offline.`;
          }
        }

        // Inject redirect logs into links check
        const activeTraces = redirectTraces.filter(t => t !== null);
        if (!result.checks.link_check) {
          result.checks.link_check = { passed: true, detail: "No links checked." };
        }
        if (activeTraces.length > 0) {
          const logs = activeTraces.map(t => {
            const origPath = new URL(t.original).hostname + new URL(t.original).pathname;
            const resPath = new URL(t.resolved).hostname;
            return `${origPath} -> ${resPath}`;
          });
          result.checks.link_check.passed = false;
          result.checks.link_check.detail = `Shortener Redirect: ${logs.join(", ")}`;
          if (serverFailed) {
            result.verdict = "SUSPICIOUS";
            result.score = 60;
            result.reason = `Local Warning: Link redirect detected. Cloud analysis offline.`;
          }
        }

        sendResponse({ success: true, result });
      } catch (error) {
        console.error("Background scan failed:", error);
        sendResponse({ success: false, error: error.message });
      }
    };

    runAnalysis();
    return true; // Keep message channel open for async response
  } else if (request.action === "validateLicense") {
    const key = request.licenseKey || "";
    
    // Developer testing mode override
    if (IS_DEVELOPMENT_BUILD && DEV_BYPASS_KEY && key === DEV_BYPASS_KEY) {
      sendResponse({ success: true, message: "Developer mode activated" });
      return false; // synchronous response
    }
    
    // Lemon Squeezy API License Key validation
    const validateLicenseKey = async () => {
      try {
        const response = await fetch("https://api.lemonsqueezy.com/v1/licenses/validate", {
          method: "POST",
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({ license_key: key }).toString()
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data && data.valid === true) {
            sendResponse({ success: true });
          } else {
            sendResponse({ success: false, error: "Invalid license key." });
          }
        } else {
          const errData = await response.json().catch(() => ({}));
          sendResponse({ 
            success: false, 
            error: errData.error || `Validation server responded with status: ${response.status}` 
          });
        }
      } catch (err) {
        console.error("License key validation failed:", err);
        sendResponse({ success: false, error: "Could not connect to the license verification server." });
      }
    };
    
    validateLicenseKey();
    return true; // keep channel open for async response
  }
});

