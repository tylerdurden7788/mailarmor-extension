/**
 * MailArmor Service Worker (Background Script)
 * Manifest V3 service worker running in the background.
 */

// Log message when the background service worker starts up
console.log("MailArmor background service started");

// Listen for installation event
chrome.runtime.onInstalled.addListener(() => {
  console.log("MailArmor extension successfully installed");
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
    const API_URL = "https://mailarmor-extension-production.up.railway.app/analyze";
    const emailData = request.emailData || {};
    
    // Extract domain from sender
    const senderStr = emailData.sender || "";
    const emailMatch = senderStr.match(/<([^>]+)>/) || senderStr.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    const email = emailMatch ? emailMatch[1] : senderStr;
    const domain = email.split('@')[1] || '';

    // Function to execute the domain age check
    const checkDomainAge = async (dom) => {
      let resultCheck = { passed: true, detail: "Domain age verified." };
      if (!dom) return resultCheck;
      
      try {
        const response = await fetch(`https://api.domainsdb.info/v1/domains/search?domain=${dom}&zone=com`);
        if (response.ok) {
          const data = await response.json();
          if (data && data.domains && data.domains.length > 0) {
            const match = data.domains.find(d => d.domain.toLowerCase().includes(dom.toLowerCase())) || data.domains[0];
            if (match && match.create_date) {
              const createDate = new Date(match.create_date);
              const diffDays = Math.ceil(Math.abs(new Date() - createDate) / (1000 * 60 * 60 * 24));
              if (diffDays < 30) {
                resultCheck = { passed: false, detail: `🚨 New domain — ${diffDays} days old` };
              } else {
                resultCheck = { passed: true, detail: `Domain is ${diffDays} days old.` };
              }
            }
          }
        }
      } catch (err) {
        console.warn("Domain age API failed silently:", err);
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
        }).catch(err => {
          throw new Error("MailArmor server is offline. Please ensure the backend is running at https://mailarmor-extension-production.up.railway.app");
        });

        const domainPromise = checkDomainAge(domain);

        // Resolve redirects of any short links
        const links = emailData.links || [];
        const redirectPromises = links.map(traceRedirect);

        const [result, domainCheckResult, redirectTraces] = await Promise.all([
          serverPromise,
          domainPromise,
          Promise.all(redirectPromises)
        ]);

        // Inject domain checker result
        if (result && result.checks) {
          result.checks.domain_check = domainCheckResult;
          
          // Inject redirect logs into links check
          const activeTraces = redirectTraces.filter(t => t !== null);
          if (activeTraces.length > 0 && result.checks.link_check) {
            const logs = activeTraces.map(t => {
              const origPath = new URL(t.original).hostname + new URL(t.original).pathname;
              const resPath = new URL(t.resolved).hostname;
              return `${origPath} -> ${resPath}`;
            });
            result.checks.link_check.passed = false;
            result.checks.link_check.detail += ` (Shortener Redirect: ${logs.join(", ")})`;
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
  }
});

