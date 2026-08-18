/**
 * MailArmour Cinematic Ocean of Typography (Simplified Fisherman Spotlight Redesign)
 * Built exactly according to the finalized visual specification.
 */

document.addEventListener('DOMContentLoaded', () => {
  initDeveloperSignature();
  initHeaderScroll();
  initOceanHero();
  initSecurityLensAnimation();
  initComparisonLensAnimation();
  initFaqAccordion();
  initXpThemeSwitcher();
});

/**
 * 1. Developer Console Welcome Signature
 */
function initDeveloperSignature() {
  console.log(
    `%c
   __  ___      _ __ ___  ___ ___  __  __
  /  |/  /___ _(_) /  /  |/  // __ \\/ / / /
 / /|_/ / __ \`/ / /  / /|_/ // /_/ / /_/ / 
/ /  / / /_/ / / /  / /  / // _, _/ __  /  
/_/  /_/\\__,_/_/_/  /_/  /_//_/ |_|/_/ /_/   v1.5.0
`,
    "font-family: monospace; font-weight: bold; color: #3b82f6;"
  );
}

/**
 * 2. Header Scroll Transition
 */
function initHeaderScroll() {
  const header = document.querySelector('header');
  if (!header) return;

  window.addEventListener('scroll', () => {
    if (window.scrollY > 50) {
      header.classList.add('scrolled');
    } else {
      header.classList.remove('scrolled');
    }
  });
}

/**
 * 3. Cinematic Ocean of Typography
 */

// Expanded 200+ Keyword Registry Configuration
const NORMAL_TERMS = [
  // EMAIL AUTHENTICATION
  "SPF", "DKIM", "DMARC", "ARC", "BIMI", "MTA-STS", "TLS-RPT", "SMTP", 
  "Authentication-Results", "SPF Alignment", "DKIM Alignment", "DMARC Alignment", 
  "Domain Alignment", "Email Authentication", "Sender Authentication", "Message Authentication", 
  "Authentication Failure", "Authentication Bypass", "Email Header", "Header Analysis", 
  "Header Spoofing", "Return-Path", "Envelope From", "Message-ID", "Received Header", 
  "Reply-To", "From Header",
  
  // PHISHING TYPES
  "Phishing", "Spear Phishing", "Whaling", "Vishing", "Smishing", "Clone Phishing", 
  "OAuth Phishing", "Credential Phishing", "Email Phishing", "Social Engineering", 
  "Business Email Compromise", "BEC", "CEO Fraud", "Executive Impersonation", 
  "Vendor Impersonation", "Supplier Fraud", "Invoice Fraud", "Payment Diversion", 
  "Payroll Fraud", "Account Takeover", "Credential Theft", "Identity Theft", 
  "Email Fraud", "Financial Phishing", "Targeted Phishing", "Mass Phishing", 
  "Automated Phishing", "Adversary-in-the-Middle", "AiTM",
  
  // IDENTITY
  "Email Impersonation", "Brand Impersonation", "Domain Impersonation", "Sender Impersonation", 
  "Lookalike Domain", "Lookalike Sender", "Domain Spoofing", "Email Spoofing", 
  "Sender Spoofing", "Brand Spoofing", "Display Name Spoofing", "Display Name Deception", 
  "Trusted Sender Abuse", "Identity Verification", "Sender Verification", "Domain Verification", 
  "Organization Verification",
  
  // DOMAIN THREATS
  "Typosquatting", "Homograph Attack", "IDN Homograph", "Punycode", "Unicode Confusable", 
  "Cousin Domain", "Similar Domain", "Domain Squatting", "Subdomain Spoofing", 
  "Subdomain Abuse", "Malicious Domain", "Suspicious Domain", "Newly Registered Domain", 
  "Domain Reputation", "Domain Intelligence", "Domain Similarity", "Domain Age", 
  "WHOIS", "DNS Reputation", "DNS Analysis",
  
  // URL THREATS
  "Malicious URL", "URL Intelligence", "URL Analysis", "URL Reputation", "URL Inspection", 
  "URL Normalization", "URL Parsing", "Redirect Chain", "Open Redirect", "Redirect Abuse", 
  "Link Spoofing", "Link Manipulation", "Credential Harvesting", "Credential Capture", 
  "Phishing Link", "Malicious Link", "Suspicious Link", "Shortened URL", "URL Obfuscation", 
  "URL Encoding", "Double Encoding", "Percent Encoding", "IP URL", "Domain Mismatch", 
  "Display Mismatch", "Hidden URL", "Tracking URL", "Redirector", "Link Reputation",
  
  // CREDENTIAL THREATS
  "Password Theft", "Password Harvesting", "Login Harvesting", "Login Capture", 
  "Session Theft", "Cookie Theft", "Token Theft", "Authentication Theft", 
  "Credential Stuffing", "Password Spraying", "Brute Force", "Session Hijacking", 
  "OAuth Token Theft", "Access Token Theft", "MFA Fatigue", "MFA Bypass", 
  "MFA Phishing", "Fake Login Page", "Fake Authentication",
  
  // EMAIL CONTENT
  "Malicious Attachment", "Suspicious Attachment", "Weaponized Attachment", "Macro Malware", 
  "HTML Attachment", "Archive Attachment", "ZIP Attachment", "Office Attachment", 
  "PDF Phishing", "Malware Delivery", "Payload Delivery", "Malicious Document", 
  "Embedded Link", "Embedded URL", "Attachment Analysis", "Content Analysis", 
  "Email Analysis", "Semantic Analysis", "Threat Analysis", "Behavior Analysis", 
  "Message Analysis",
  
  // SOCIAL ENGINEERING
  "Urgency", "Fear Tactic", "Authority Impersonation", "Trust Exploitation", 
  "Psychological Manipulation", "Urgent Request", "Executive Pressure", "Payment Pressure", 
  "Account Threat", "Deadline Pressure", "Secrecy Request", "Confidential Request", 
  "Information Request", "Identity Pretext", "Financial Pretext",
  
  // THREAT INTELLIGENCE
  "Threat Intelligence", "Threat Detection", "Threat Analysis", "Threat Classification", "Risk Score", 
  "Threat Score", "Reputation Analysis", "IP Reputation", "Malware Reputation", 
  "Threat Indicator", "Indicator of Compromise", "IOC", "Threat Actor", 
  "Campaign", "Phishing Campaign", "Attack Campaign", "Threat Campaign", 
  "Detection Engine", "Evidence Engine", "Evidence Analysis", "Behavior Detection", 
  "Anomaly Detection", "Pattern Analysis", "Risk Assessment", "Confidence Score",
  
  // EMAIL SECURITY
  "Email Security", "Email Protection", "Email Defense", "Threat Prevention", 
  "Fraud Detection", "Email Monitoring", "Email Filtering", "Secure Email", 
  "Inbox Protection", "Email Gateway", "Secure Gateway", "Mail Security", 
  "Identity Intelligence", "Content Intelligence", "Sender Intelligence",
  
  // MAILARMOUR CONCEPTS
  "Rule Engine", "Evidence Collection", "Decision Engine", "Risk Analysis", 
  "Semantic Detection", "AI Detection", "Email Scanner", "Threat Scanner", 
  "Phishing Scanner", "Security Analysis", "Email Inspection", "Threat Evidence", 
  "Detection Evidence"
];

const INCIDENT_TERMS = [
  {
    text: "Reddit Breach — 2023",
    id: "reddit-breach-feb-2023",
    whatHappened: "A Reddit employee was targeted by a phishing attack that led to unauthorized access to Reddit's internal systems. Attackers accessed internal documents, source code, dashboards and business systems. Reddit's main production systems and user passwords were not compromised.",
    howDone: "The attacker sent a convincing phishing message that directed the employee to a fake Reddit internal IT/intranet login page. The employee entered their credentials and 2FA token into the fraudulent page, giving the attackers a foothold into internal systems.",
    howWarned: "MailArmour could have analyzed the sender identity, authentication results, suspicious destination domain, URL characteristics and credential-harvesting behavior, potentially warning the employee before they entered their credentials."
  },
  {
    text: "Mailchimp Breach — 2022",
    id: "mailchimp-breach-2022",
    whatHappened: "Mailchimp suffered phishing-related employee/contractor compromises that gave attackers access to customer account information. The stolen information was later used in follow-up phishing campaigns, including attacks targeting customers of cryptocurrency hardware wallet company Trezor.",
    howDone: "Attackers impersonated internal IT/support through phishing emails. Employees were directed to fake login pages where credentials were harvested, allowing attackers to access internal customer support and account administration tools.",
    howWarned: "MailArmour could have detected impersonation indicators, suspicious login URLs, sender/domain inconsistencies and credential-harvesting behavior, potentially warning employees before credentials were submitted."
  },
  {
    text: "GoDaddy Breach — 2022–2023",
    id: "godaddy-breach-2022-2023",
    whatHappened: "GoDaddy disclosed a multi-year campaign in which attackers gained access to internal systems. Source code was stolen, malware was installed on some customer websites, and information associated with approximately 1.2 million WordPress hosting customers was exposed.",
    howDone: "Attackers used sustained phishing campaigns targeting GoDaddy employees and tricked them into providing login credentials. Those credentials were then used to access internal provisioning systems involved in web hosting.",
    howWarned: "MailArmour could have analyzed sender authenticity, authentication results, suspicious URLs/domains, impersonation signals and credential-harvesting indicators to warn employees about the phishing messages before credentials were exposed."
  },
  {
    text: "Barracuda ESG Zero-Day — 2023",
    id: "barracuda-networks-esg-zero-day-2023",
    whatHappened: "Hundreds of organizations using Barracuda Email Security Gateway appliances were compromised. Attackers gained persistent access and Barracuda ultimately instructed affected customers to replace compromised appliances rather than simply patch them.",
    howDone: "Attackers sent specially crafted malicious email attachments to organizations using Barracuda ESG appliances. The malicious attachment exploited a zero-day vulnerability when the email was processed by the appliance. Importantly, the victim did NOT need to click the attachment for exploitation to occur.",
    howWarned: "MailArmour could potentially have identified the malicious attachment and suspicious email characteristics through attachment analysis, sender identity analysis, threat intelligence and behavioral indicators. However, because this attack exploited a zero-day during email processing, detection cannot be guaranteed solely through traditional phishing analysis."
  },
  {
    text: "Ukraine Spear-Phishing Campaign — 2021–2022",
    id: "ukraine-spear-phishing-2021-2022",
    whatHappened: "Government organizations and NGOs in Ukraine were targeted in a cyberespionage campaign that resulted in sensitive information being compromised and exfiltrated.",
    howDone: "Gamaredon operators impersonated trusted contacts and sent targeted spear-phishing emails containing malicious macro-enabled attachments. The campaign also used tracking mechanisms to determine whether messages were opened. Victims who opened the malicious attachment and enabled macros could become infected.",
    howWarned: "MailArmour could have analyzed sender impersonation, attachment behavior, suspicious macros, authentication inconsistencies and other spear-phishing indicators, potentially warning the recipient before the malicious attachment was opened or executed."
  },
  {
    text: "Mint Sandstorm Spear-Phishing — 2024",
    id: "mint-sandstorm-spear-phishing-2024",
    whatHappened: "U.S. presidential campaign official targeted in a spear-phishing attack. Raised major national security concerns regarding attempted espionage/interference in a U.S. presidential election through a single targeted email.",
    howDone: "Iranian state-sponsored hackers, identified as Mint Sandstorm (also known as Charming Kitten or APT35), launched a spear-phishing attack against a high-ranking official in a U.S. presidential campaign, using a compromised email account to send a malicious link aiming to gather intelligence and influence the electoral process.",
    howWarned: "MailArmour could have analyzed the compromised sender account, sender identity inconsistencies, suspicious URL characteristics, link destination, and spear-phishing indicators to flag the message as a high-risk targeted attack before the recipient interacted with the malicious link."
  },
  {
    text: "Sefri-Cime CEO Fraud — 2022",
    id: "sefri-cime-ceo-fraud-2022",
    whatHappened: "A Paris real estate developer, Sefri-Cime, was targeted by an international email 'CEO fraud' gang. The group stole €38 million through the scam, which was then laundered through bank accounts in various countries, including China and Israel.",
    howDone: "The firm's CFO received an email from someone claiming to be a lawyer at a well-known French accounting firm, and within days the fraudster had gained the CFO's trust and began making successful requests for large, urgent transfers of millions of euros.",
    howWarned: "MailArmour could have detected signs of executive impersonation, sender identity anomalies, unusual communication patterns, urgency around large financial transfers, and payment-diversion/BEC indicators, potentially warning the CFO before acting on the fraudulent requests."
  },
  {
    text: "Medicare/Medicaid BEC — 2022",
    id: "medicare-medicaid-bec-2022",
    whatHappened: "A group of scammers impersonated legitimate parties in Medicare, state Medicaid programs, and private health insurer transactions. The DOJ charged 10 people in 2022 for collecting over $11 million dollars through this scheme.",
    howDone: "Scammers used spoofed email addresses and bank account takeovers to trick staff into redirecting payments to fraudulent accounts over a period of years.",
    howWarned: "MailArmour could have identified spoofed sender identities, domain inconsistencies, unusual payment-related requests, account-takeover indicators, and attempts to redirect legitimate payments to unfamiliar accounts, potentially warning staff before the payment information was changed."
  },
  {
    text: "DocuSign API Invoice Fraud — 2024",
    id: "docusign-api-invoice-fraud-2024",
    whatHappened: "Threat actors abused DocuSign's real infrastructure to distribute counterfeit invoices, causing widespread direct financial losses to individual businesses and major concern industry-wide about trusted-platform abuse making phishing far harder to detect with standard email security tools.",
    howDone: "Threat actors abused DocuSign's legitimate Envelopes API to create and distribute counterfeit invoices resembling legitimate documents. Because the emails came through DocuSign's real infrastructure, they bypassed normal spam/phishing filters and looked authentic to recipients.",
    howWarned: "MailArmour could have looked beyond the fact that the email came from legitimate DocuSign infrastructure and analyzed the invoice content, sender context, payment request, recipient relationship, URL/document behavior, and financial-fraud indicators to warn that the legitimate platform was being abused."
  },
  {
    text: "Bybit Lazarus Heist — 2025",
    id: "bybit-lazarus-heist-2025",
    whatHappened: "North Korea's Lazarus Group executed a cryptocurrency heist against Bybit. The heist totaled $1.5 billion, making it the largest cryptocurrency theft in history — demonstrating how a single phishing email can cascade into a massive financial loss.",
    howDone: "The heist originated from a spear phishing attack targeting an exchange employee, which gave them the access needed to manipulate a routine wallet transfer.",
    howWarned: "MailArmour could have analyzed the spear-phishing message for sender impersonation, malicious links, suspicious domains, social-engineering indicators, and credential/session-harvesting behavior, potentially warning the targeted employee before the initial compromise occurred."
  }
];

function initOceanHero() {
  const container = document.getElementById('hero-ocean');
  const fieldContainer = document.getElementById('bubble-field-container');
  const boatEl = container?.querySelector('.phisher-scene');
  
  if (!container || !fieldContainer || !boatEl) return;

  // LCG Pseudo-random generator to ensure deterministic layout
  function createLCG(seedVal) {
    let s = seedVal;
    return function() {
      s = (s * 9301 + 49297) % 233280;
      return s / 233280;
    };
  }

  let bubbles = [];
  let caughtIncident = null;

  // Snaps the hook to the clicked bubble and opens explanation modal
  function triggerIncidentCatch(item) {
    if (caughtIncident) return; // Prevent double catching
    caughtIncident = item;

    // Get clicked bubble element
    const bubbleEl = fieldContainer.querySelector(`[data-bubble-id="${item.data.id}"]`);
    if (bubbleEl) {
      bubbleEl.classList.add('caught');
    }

    // Snapping logic: redirect target coordinates to the center of the bubble
    const containerRect = container.getBoundingClientRect();
    const rect = bubbleEl.getBoundingClientRect();
    const targetCenterX = rect.left + rect.width / 2 - containerRect.left;
    const targetCenterY = rect.top + rect.height / 2 - containerRect.top;

    targetX = targetCenterX;
    targetY = targetCenterY;

    // Show the modal after a short easing delay (450ms) to allow the hook to reach the bubble
    setTimeout(() => {
      openIncidentModal(item.data);
    }, 450);
  }

  // Populate and open explanation modal
  function openIncidentModal(data) {
    const modal = document.getElementById('incident-modal');
    const title = document.getElementById('modal-title');
    const what = document.getElementById('modal-what');
    const how = document.getElementById('modal-how');
    const warn = document.getElementById('modal-warn');

    if (!modal || !title || !what || !how || !warn) return;

    title.textContent = data.text;
    what.textContent = data.whatHappened;
    how.textContent = data.howDone;
    warn.textContent = data.howWarned;

    modal.classList.add('active');
  }

  // Close explanation modal and release lock
  function closeIncidentModal() {
    if (!caughtIncident) return;

    const modal = document.getElementById('incident-modal');
    if (modal) {
      modal.classList.remove('active');
    }

    const bubbleEl = fieldContainer.querySelector(`[data-bubble-id="${caughtIncident.data.id}"]`);
    if (bubbleEl) {
      bubbleEl.classList.remove('caught');
    }

    caughtIncident = null;
    isCursorActive = false; // Resume cursor tracking on next movement
  }

  // Bind close button listeners
  const closeX = document.getElementById('modal-close-x');
  const closeBtn = document.getElementById('modal-close-btn');
  if (closeX) closeX.addEventListener('click', closeIncidentModal);
  if (closeBtn) closeBtn.addEventListener('click', closeIncidentModal);

  // Phase 1: DOM Elements Generation (Executed once on startup)
  function createBubbles() {
    fieldContainer.innerHTML = '';
    bubbles = [];

    const random = createLCG(101); // Deterministic seed

    // Construct normal pool first
    const tempNormals = [...NORMAL_TERMS];
    const pool = [];
    const count = 350;

    // Fill pool with normal keywords
    for (let i = 0; i < count - INCIDENT_TERMS.length; i++) {
      if (tempNormals.length > 0) {
        const idx = Math.floor(random() * tempNormals.length);
        pool.push({ text: tempNormals.splice(idx, 1)[0], isIncident: false });
      } else {
        const text = NORMAL_TERMS[Math.floor(random() * NORMAL_TERMS.length)];
        pool.push({ text: text, isIncident: false });
      }
    }

    // Shuffle normal pool deterministically via LCG
    for (let i = pool.length - 1; i > 0; i--) {
      const j = Math.floor(random() * (i + 1));
      const temp = pool[i];
      pool[i] = pool[j];
      pool[j] = temp;
    }

    // Splice the 10 incidents at distributed early indices to guarantee rendering and natural spread
    const incidentInsertIndices = [3, 11, 19, 27, 35, 43, 51, 59, 67, 75];
    INCIDENT_TERMS.forEach((inc, idx) => {
      const insertIdx = incidentInsertIndices[idx];
      pool.splice(insertIdx, 0, {
        text: inc.text,
        isIncident: true,
        data: inc
      });
    });

    pool.forEach((item, index) => {
      const bubble = document.createElement('div');
      bubble.className = `phishing-bubble${item.isIncident ? ' incident' : ''}`;
      bubble.textContent = item.text;
      bubble.setAttribute('aria-hidden', 'true');
      
      // Phase 2 Metadata Readiness for capturing/hover logic in subsequent updates
      const cleanId = item.text.toLowerCase().replace(/[^a-z0-9]+/g, '-');
      bubble.setAttribute('data-bubble-id', item.isIncident ? item.data.id : `${cleanId}-${index}`);
      bubble.setAttribute('data-bubble-type', item.isIncident ? 'incident' : 'keyword');

      // Click listener to snap hook and open explanation modal
      if (item.isIncident) {
        bubble.addEventListener('click', (e) => {
          e.stopPropagation();
          triggerIncidentCatch(item);
        });
      }

      // Temporary styling for batch layout offset measurement
      bubble.style.position = 'absolute';
      bubble.style.left = '-9999px';
      bubble.style.top = '-9999px';
      bubble.style.transform = 'none';
      bubble.style.visibility = 'hidden';
      
      fieldContainer.appendChild(bubble);
      bubbles.push({
        element: bubble,
        item: item,
        w: 0,
        h: 0
      });
    });
  }

  // Phase 2: Measure natural unrotated dimensions (Executed once after fonts/styles load)
  function measureBubbles() {
    bubbles.forEach(b => {
      b.w = b.element.offsetWidth;
      b.h = b.element.offsetHeight;
    });
  }

  // Globally track coordinates for the dynamic line and hook cursor follow system
  let rodTipX = 0, rodTipY = 0;
  let restingX = 0, restingY = 0;
  let targetX = 0, targetY = 0;
  let currentX = 0, currentY = 0;
  let isCursorActive = false;
  let seaStartY = 0;

  // Phase 3: Pack Layout coordinates (Executed on load and resize shifts)
  function packLayout() {
    if (bubbles.length === 0) return;

    const width = container.clientWidth;
    const height = container.clientHeight;

    // Dynamically calculate the bottom edge of the boat hull relative to container top
    const boatRect = boatEl.getBoundingClientRect();
    const containerRect = container.getBoundingClientRect();
    const boatBottomY = (boatRect.top - containerRect.top) + boatRect.height * (115 / 160);
    seaStartY = boatBottomY + 2; // Tightly sit 2px directly below boat hull

    // Recalculate stationary rod tip coordinates relative to the container
    rodTipX = (boatRect.left - containerRect.left) + boatRect.width * (148 / 160);
    rodTipY = (boatRect.top - containerRect.top) + boatRect.height * (108 / 160);
    
    // Set default/resting coordinates relative to the stationary rod tip
    restingX = rodTipX + 25;
    restingY = rodTipY + 30;

    // Reset current coordinates immediately if the cursor has not hovered the interaction zone
    if (!isCursorActive) {
      targetX = restingX;
      targetY = restingY;
      currentX = restingX;
      currentY = restingY;
    }

    const gap = 0.5; // Tight 0.5px horizontal/vertical gap (LOCKED)
    let poolIndex = 0;
    let currentYCoordinate = seaStartY;

    while (currentYCoordinate < height && poolIndex < bubbles.length) {
      // Start every row at exactly x = -60px (rely on variable bubble widths for natural staggering)
      let currentX = -60;
      const currentRow = [];

      // Place bubbles horizontally side-by-side inside current row
      while (currentX < width + 60 && poolIndex < bubbles.length) {
        let b = bubbles[poolIndex];

        // Prevent red incident bubbles from clipping at left/right viewport edges
        if (b.item.isIncident) {
          const fits = (currentX >= 0) && (currentX + b.w <= width);
          if (!fits) {
            // Find the next normal keyword bubble in the pool to swap
            let swapIdx = poolIndex + 1;
            while (swapIdx < bubbles.length && bubbles[swapIdx].item.isIncident) {
              swapIdx++;
            }
            if (swapIdx < bubbles.length) {
              // Swap the incident bubble with the normal keyword bubble
              const temp = bubbles[poolIndex];
              bubbles[poolIndex] = bubbles[swapIdx];
              bubbles[swapIdx] = temp;
              b = bubbles[poolIndex]; // Update reference to the swapped normal bubble
            }
          }
        }

        poolIndex++;

        currentRow.push({
          element: b.element,
          x: currentX,
          w: b.w,
          h: b.h
        });
        currentX += b.w + gap;
      }

      // Compute row height based on tallest bubble height in this row
      let maxRowH = 0;
      currentRow.forEach(b => {
        if (b.h > maxRowH) maxRowH = b.h;
      });

      // Position each row bubble absolutely, static, unrotated (LOCKED packing offsets)
      currentRow.forEach(b => {
        b.element.style.visibility = 'visible';
        b.element.style.display = 'block';
        b.element.style.left = `${b.x}px`;
        b.element.style.top = `${currentYCoordinate}px`;
        b.element.style.transform = 'none'; // Strictly no rotation, no jitter, no float
      });

      currentYCoordinate += maxRowH + gap; // 0.5px vertical gap between rows
    }

    // Hide any unused pre-rendered bubbles exceeding viewport height
    for (let i = poolIndex; i < bubbles.length; i++) {
      bubbles[i].element.style.display = 'none';
    }
  }

  // 1. Create DOM Elements
  createBubbles();

  // 2. Measure & Pack layout only after fonts and stylesheets are fully ready
  const runFullLayout = () => {
    measureBubbles();
    packLayout();
  };

  if (document.readyState === 'complete') {
    runFullLayout();
  } else {
    window.addEventListener('load', runFullLayout);
  }

  if (document.fonts) {
    document.fonts.ready.then(runFullLayout);
  }

  // 3. Setup ResizeObserver to detect real visual shifts on overlay and boat, preventing shifts
  let resizeTimeout;
  const onResizeTrigger = () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(packLayout, 30); // Fast debounced reposition without DOM recreate
  };

  const introEl = container.querySelector('.hero-intro-overlay');
  if (window.ResizeObserver && (introEl || boatEl)) {
    const observer = new ResizeObserver(onResizeTrigger);
    if (introEl) observer.observe(introEl);
    if (boatEl) observer.observe(boatEl);
    observer.observe(container);
  } else {
    window.addEventListener('resize', onResizeTrigger);
  }

  // 4. Easing & Cursor Following loop
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const speechBubble = document.getElementById('phisher-speech');

  function updateSpeechBubbleProximity(mouseX, mouseY) {
    if (!speechBubble || !boatEl) return;

    const containerRect = container.getBoundingClientRect();
    const boatRect = boatEl.getBoundingClientRect();
    const boatCenterX = boatRect.left + boatRect.width / 2 - containerRect.left;
    const boatCenterY = boatRect.top + boatRect.height / 2 - containerRect.top;

    const distToBoat = Math.hypot(mouseX - boatCenterX, mouseY - boatCenterY);
    const distToHook = Math.hypot(mouseX - currentX, mouseY - currentY);

    // Show bubble if cursor is near the Phisher/boat or the hook
    if (distToBoat < 145 || distToHook < 95) {
      speechBubble.classList.add('active');
    } else {
      speechBubble.classList.remove('active');
    }
  }

  // Mobile / Touch devices brief display when entering the viewport
  if ('IntersectionObserver' in window && boatEl) {
    const mobileObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
          if (isTouch && speechBubble) {
            speechBubble.classList.add('active');
            setTimeout(() => {
              speechBubble.classList.remove('active');
            }, 5000); // Show briefly for 5 seconds
          }
        }
      });
    }, { threshold: 0.1 });
    mobileObserver.observe(boatEl);
  }

  // Track cursor movement on container and interaction zone state
  container.addEventListener('pointermove', (e) => {
    if (caughtIncident) return; // Do not move hook with cursor while snapping/modal is open

    const rect = container.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    updateSpeechBubbleProximity(mouseX, mouseY);

    const width = container.clientWidth;
    const height = container.clientHeight;

    // Check if the cursor is within the dynamic bounds of the fishing zone
    const isInsideFishingZone = (mouseY >= seaStartY && mouseY <= height && mouseX >= 0 && mouseX <= width);

    if (isInsideFishingZone) {
      isCursorActive = true;
      // Clamp coordinates so the hook is locked inside the fishing zone boundary
      targetX = Math.max(0, Math.min(width, mouseX));
      targetY = Math.max(seaStartY, Math.min(height, mouseY));
    } else {
      isCursorActive = false;
      targetX = restingX;
      targetY = restingY;
    }
  });

  // Track when cursor leaves the window to restore resting hook placement
  document.addEventListener('pointerleave', () => {
    if (speechBubble) speechBubble.classList.remove('active');
    if (caughtIncident) return; // Keep hook on bubble if modal is active
    isCursorActive = false;
    targetX = restingX;
    targetY = restingY;
  });

  // Dynamic SVG redraw render loop
  function renderHookFrame() {
    // Calculate and update rendering coordinates (Cursor is the absolute source of truth)
    const ease = prefersReducedMotion ? 1.0 : 0.12; // 0.12 coefficient for smooth tracking
    currentX += (targetX - currentX) * ease;
    currentY += (targetY - currentY) * ease;

    const lineEl = document.getElementById('dynamic-line');
    const hookEl = document.getElementById('dynamic-hook');

    // Update dynamic fishing line coordinates stretching between rod tip and hook
    if (lineEl) {
      lineEl.setAttribute('d', `M ${rodTipX} ${rodTipY} L ${currentX} ${currentY}`);
    }

    // Update dynamic hook coordinates translation transform
    if (hookEl) {
      hookEl.setAttribute('transform', `translate(${currentX}, ${currentY})`);
    }

    requestAnimationFrame(renderHookFrame);
  }

  // Start rendering frames
  requestAnimationFrame(renderHookFrame);
}
/**
 * 5. Section 2: Security Lens Animation and Proximity Highlights
 */
function initSecurityLensAnimation() {
  const sectionEl = document.getElementById('security-lens');
  if (!sectionEl) return;

  // Viewport Observer for entry animations
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          sectionEl.classList.add('triggered');
          observer.unobserve(sectionEl); // Only animate once
        }
      });
    }, { threshold: 0.15 });
    
    observer.observe(sectionEl);
  } else {
    // Fallback if IntersectionObserver not supported
    sectionEl.classList.add('triggered');
  }

  // Interactive connection: Hovering clues in the email highlights the corresponding card
  const highlights = document.querySelectorAll('.email-clue-highlight');
  const cards = document.querySelectorAll('.analysis-card');

  highlights.forEach(highlight => {
    const targetClue = highlight.dataset.target;
    
    highlight.addEventListener('mouseenter', () => {
      cards.forEach(card => {
        if (card.dataset.clue === targetClue) {
          card.classList.add('focused');
        } else {
          card.classList.remove('focused');
        }
      });
    });

    highlight.addEventListener('mouseleave', () => {
      cards.forEach(card => card.classList.remove('focused'));
    });

    // Touch device support
    highlight.addEventListener('click', (e) => {
      e.preventDefault();
      cards.forEach(card => {
        if (card.dataset.clue === targetClue) {
          card.classList.toggle('focused');
        } else {
          card.classList.remove('focused');
        }
      });
    });
  });
}

/**
 * 5b. Section 7: Comparison Viewport Trigger
 */
function initComparisonLensAnimation() {
  const sectionEl = document.getElementById('comparison');
  if (!sectionEl) return;

  // Viewport Observer for entry animations
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          sectionEl.classList.add('triggered');
          observer.unobserve(sectionEl); // Only animate once
        }
      });
    }, { threshold: 0.15 });
    
    observer.observe(sectionEl);
  } else {
    // Fallback if IntersectionObserver not supported
    sectionEl.classList.add('triggered');
  }
}

/**
 * 6. FAQ Accordion Toggle
 */
function initFaqAccordion() {
  const triggers = document.querySelectorAll('.faq-trigger');
  
  triggers.forEach(btn => {
    btn.addEventListener('click', () => {
      const item = btn.parentElement;
      const body = item.querySelector('.faq-body');
      const active = item.classList.contains('active');
      
      document.querySelectorAll('.faq-item').forEach(i => {
        i.classList.remove('active');
        i.querySelector('.faq-body').style.maxHeight = null;
      });

      if (!active) {
        item.classList.add('active');
        body.style.maxHeight = `${body.scrollHeight}px`;
      } else {
        item.classList.remove('active');
        body.style.maxHeight = null;
      }
    });
  });
}

/**
 * 7. Windows XP Theme Switcher (Luna vs Royale Noir/Dark)
 */
function initXpThemeSwitcher() {
  const themeSelect = document.getElementById('xp-theme-select');
  if (!themeSelect) return;

  const storageKey = 'mailarmour-xp-theme';
  
  // Apply saved theme on load
  const savedTheme = localStorage.getItem(storageKey);
  if (savedTheme === 'dark') {
    document.body.classList.add('xp-dark-theme');
    themeSelect.value = 'dark';
  } else {
    document.body.classList.remove('xp-dark-theme');
    themeSelect.value = 'luna';
  }

  // Handle dropdown change event
  themeSelect.addEventListener('change', (e) => {
    const selectedTheme = e.target.value;
    if (selectedTheme === 'dark') {
      document.body.classList.add('xp-dark-theme');
      localStorage.setItem(storageKey, 'dark');
    } else {
      document.body.classList.remove('xp-dark-theme');
      localStorage.setItem(storageKey, 'luna');
    }
  });
}

