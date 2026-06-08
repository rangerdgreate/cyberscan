const page = document.body.dataset.page;
let pendingChallengeId = "";
let latestReport = null;
let findings = [];
let scanHistory = [];
let activeScanId = localStorage.getItem("cyberscan.activeScanId") || "";
let pollTimer = null;
let progress = 0;
let inactivityTimer = null;
let currentUser = null;
let sessionExpired = false;
const INACTIVITY_LIMIT_MS = 2 * 60 * 1000;

document.querySelectorAll(".nav a").forEach((link) => {
  if (link.dataset.nav === page) link.classList.add("active");
});

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  }[char]));
}

function friendlyErrorMessage(error) {
  const message = String(error?.message || error || "");
  if (/Invalid owner credentials|Invalid username|Invalid password|credentials/i.test(message)) {
    return "Invalid username/email or password. Please try again.";
  }
  if (/Verification.*expired|invalid.*verification|link.*expired/i.test(message)) {
    return "The verification link is invalid or expired. Please request a new link.";
  }
  if (/Confirm authorized|authorization|permission/i.test(message)) {
    return "Please confirm that you have permission to scan this target.";
  }
  if (/Username and Password not accepted|BadCredentials|SMTPAuthentication|Gmail rejected/i.test(message)) {
    return "Gmail rejected the login. Use a 16-character Google App Password, not your normal Gmail password.";
  }
  if (/Could not send OTP email|SMTP|MAIL_|smtp\.gmail\.com/i.test(message)) {
    return message.split("https://")[0].trim() || "Email delivery failed. Check email delivery settings.";
  }
  return message || "Something went wrong. Please try again.";
}

function isValidTarget(value) {
  const target = String(value || "").trim();
  if (!target) return false;
  if (/^https?:\/\//i.test(target)) {
    try {
      const url = new URL(target);
      return Boolean(url.hostname);
    } catch {
      return false;
    }
  }
  return /^(localhost|(\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9.-]+\.[A-Za-z]{2,})(:\d+)?(\/.*)?$/.test(target);
}

function setLoading(button, isLoading, text) {
  if (!button) return;
  if (isLoading) {
    button.dataset.originalText = button.textContent;
    button.textContent = text || "Loading...";
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    return;
  }
  button.textContent = button.dataset.originalText || button.textContent;
  button.disabled = false;
  button.removeAttribute("aria-busy");
}

async function apiGet(path) {
  const response = await fetch(path, { credentials: "same-origin" });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || payload.message || `Request failed: ${response.status}`);
  return payload;
}

async function apiPost(path, body = {}) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed: ${response.status}`);
  return payload;
}

async function logout(reason = "manual") {
  clearTimeout(inactivityTimer);
  try {
    await apiPost("/api/logout", { reason });
  } catch {
    // Redirect even if the session was already gone.
  }
  localStorage.removeItem("cyberscan.activeScanId");
  window.location.href = "/login";
}

async function expireInactiveSession() {
  if (sessionExpired) return;
  sessionExpired = true;
  clearTimeout(inactivityTimer);
  try {
    await apiPost("/api/logout", { reason: "inactive_2_minutes" });
  } catch {
    // The session may already be gone; the modal still gives the user a clear next step.
  }
  localStorage.removeItem("cyberscan.activeScanId");
  const modal = document.querySelector("[data-session-expired-modal]");
  if (modal) {
    modal.hidden = false;
    document.body.classList.add("session-modal-open");
    modal.querySelector("[data-login-again]")?.focus();
  } else {
    window.location.href = "/login";
  }
}

function resetInactivityTimer() {
  if (page === "login" || sessionExpired) return;
  clearTimeout(inactivityTimer);
  inactivityTimer = setTimeout(() => {
    expireInactiveSession();
  }, INACTIVITY_LIMIT_MS);
}

if (page !== "login") {
  ["mousemove", "mousedown", "keydown", "scroll", "touchstart", "click"].forEach((eventName) => {
    window.addEventListener(eventName, resetInactivityTimer, { passive: true });
  });
  resetInactivityTimer();
}

document.querySelector("[data-logout]")?.addEventListener("click", () => {
  logout("manual");
});

const navbarMenu = document.querySelector("[data-navbar-menu]");
document.querySelector("[data-mobile-menu-toggle]")?.addEventListener("click", () => {
  navbarMenu?.classList.toggle("open");
});

document.querySelectorAll(".navbar-item.dropdown").forEach((item) => {
  const button = item.querySelector(".navbar-link");
  button?.addEventListener("click", (event) => {
    if (window.matchMedia("(max-width: 900px)").matches) {
      event.preventDefault();
      item.classList.toggle("open");
    }
  });
});

document.addEventListener("click", (event) => {
  if (!event.target.closest(".top-navbar")) {
    navbarMenu?.classList.remove("open");
    document.querySelectorAll(".navbar-item.open").forEach((item) => item.classList.remove("open"));
  }
});

document.querySelectorAll("[data-toggle-password]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = button.closest(".password-field")?.querySelector("input");
    if (!input) return;
    const showing = input.type === "text";
    input.type = showing ? "password" : "text";
    button.textContent = showing ? "Show" : "Hide";
  });
});

document.querySelectorAll(".faq-question").forEach((button) => {
  button.addEventListener("click", () => {
    const item = button.closest(".faq-item");
    if (!item) return;
    item.classList.toggle("active");
    const icon = item.querySelector(".faq-icon");
    if (icon) icon.textContent = item.classList.contains("active") ? "-" : "+";
  });
});

document.querySelectorAll(".tool-category-tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tool-category-tab").forEach((item) => item.classList.remove("active"));
    document.querySelectorAll(".tool-category-panel").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    document.querySelector(`[data-tool-panel="${button.dataset.toolCategory}"]`)?.classList.add("active");
  });
});

const TOOL_FIELD_GROUPS = {
  port_scanner: ["target", "ports", "timeout"],
  network_scanner: ["target", "ports", "timeout"],
  url_fuzzer: ["target", "wordlist", "max_requests", "delay"],
  subdomain_finder: ["target", "wordlist", "delay"],
  virtual_host_finder: ["target", "wordlist", "delay"],
  api_scanner: ["target", "max_requests", "delay"],
  password_audit: ["target", "username", "passwords", "max_requests", "delay", "stop_success"],
  report_generator: ["target"],
  website_scanner: ["target", "scan_type", "max_requests", "delay"],
  default: ["target", "wordlist", "max_requests", "delay", "timeout"]
};

function applyToolFieldVisibility(form) {
  const tool = form?.dataset.selectedTool || form?.selected_tool?.value || "website_scanner";
  const allowed = new Set(TOOL_FIELD_GROUPS[tool] || TOOL_FIELD_GROUPS.default);
  form?.querySelectorAll("[data-tool-field]").forEach((field) => {
    field.classList.toggle("hidden", !allowed.has(field.dataset.toolField));
  });
}

document.querySelectorAll("[data-tool-runner-form]").forEach((form) => {
  applyToolFieldVisibility(form);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = form.querySelector("[data-tool-message]");
    const submitButton = form.querySelector('button[type="submit"]');
    const tool = form.dataset.selectedTool || form.selected_tool?.value || "website_scanner";
    if (!form.target.value.trim()) {
      message.textContent = "Please enter a target URL before starting the scan.";
      form.target.focus();
      return;
    }
    if (!isValidTarget(form.target.value)) {
      message.textContent = "Please enter a valid URL, example: https://example.com";
      form.target.focus();
      return;
    }
    if (!form.authorization_confirmed.checked) {
      message.textContent = "Please confirm that you have permission to scan this target.";
      return;
    }
    message.textContent = "Running tool...";
    setLoading(submitButton, true, "Running Tool...");
    try {
      const payload = await apiPost("/api/run-tool", {
        tool,
        target: form.target.value,
        scan_type: form.scan_type?.value || "light",
        authorization_confirmed: form.authorization_confirmed.checked,
        options: {
          ports: form.tool_ports?.value || "",
          wordlist: form.tool_wordlist?.value || "",
          subdomains: form.tool_wordlist?.value || "",
          host_list: form.tool_wordlist?.value || "",
          max_requests: Number(form.tool_max_requests?.value || 10),
          delay: Number(form.tool_delay?.value || 0.5),
          timeout: Number(form.tool_timeout?.value || 1),
          username: form.tool_username?.value || "",
          password_list: form.tool_password_list?.value || "",
          max_attempts: Number(form.tool_max_requests?.value || 5),
          stop_on_success: form.tool_stop_on_success?.checked !== false,
          scan_id: form.target.value
        }
      });
      message.textContent = payload.message || "Scan completed successfully.";
      localStorage.setItem("cyberscan.progressScanId", payload.scan_id || "");
      localStorage.setItem("cyberscan.progressTarget", form.target.value || "Active target");
      localStorage.setItem("cyberscan.progressTool", tool.replace(/_/g, " "));
      localStorage.setItem("cyberscan.progressType", form.scan_type?.value || "light");
      setTimeout(() => {
        const scanId = encodeURIComponent(payload.scan_id || "");
        window.location.href = payload.scan_id ? `/scan-progress?scan_id=${scanId}&result_url=${encodeURIComponent(`/results/${payload.scan_id}`)}` : "/scan-progress";
      }, 700);
    } catch (error) {
      message.textContent = friendlyErrorMessage(error);
    } finally {
      setLoading(submitButton, false);
    }
  });
});

document.querySelectorAll("[data-scan-tabs]").forEach((group) => {
  group.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => {
      group.querySelectorAll("button").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
    });
  });
});

function severityClass(severity) {
  return String(severity || "Info").toLowerCase().replace(/\s+/g, "-");
}

function severityMeaning(severity) {
  const key = severityClass(severity);
  return {
    critical: "Fix immediately.",
    high: "Important security issue.",
    medium: "Should be fixed soon.",
    low: "Minor issue or improvement.",
    info: "For awareness and documentation."
  }[key] || "Review this finding.";
}

function statusClass(status) {
  if (status === "Fixed") return "fixed";
  if (status === "Accepted Risk") return "accepted-risk";
  return "open";
}

function formatDate(value) {
  if (!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function normalizeFinding(finding) {
  const lifecycle = finding.lifecycle_status || "Open";
  return {
    severity: finding.severity || "Info",
    vulnerability: finding.title || "Security Finding",
    url: finding.affected_url || latestReport?.target || "",
    evidence: finding.evidence || finding.description || "",
    impact: finding.impact || finding.owasp_category || "Potential web application impact.",
    recommendation: finding.recommendation || "Review and validate this finding.",
    status: ["Fixed", "Accepted Risk"].includes(lifecycle) ? lifecycle : "Open",
    description: finding.description || "No description was provided.",
    fingerprint: finding.fingerprint || "",
    raw: finding
  };
}

function hasPermission(permission) {
  return Boolean(currentUser?.permissions?.includes(permission));
}

function applyRbac() {
  const userChip = document.querySelector(".user-chip");
  if (userChip && currentUser) {
    userChip.textContent = `${currentUser.name || currentUser.email} · ${currentUser.role}`;
  }
  document.querySelectorAll("[data-requires-permission]").forEach((element) => {
    const allowed = hasPermission(element.dataset.requiresPermission);
    element.classList.toggle("hidden", !allowed);
  });
}

function applyReport(report) {
  latestReport = report || null;
  findings = (latestReport?.findings || []).map(normalizeFinding);
  renderDashboard();
  renderResults();
  renderDetail();
  renderReportStatus();
}

async function loadState() {
  try {
    const selectedScanId = document.querySelector("[data-results-page]")?.dataset.scanId || "";
    if (selectedScanId) {
      const payload = await apiGet(`/api/scan/${encodeURIComponent(selectedScanId)}`);
      currentUser = payload.current_user || currentUser;
      applyReport(payload.scan || null);
      return;
    }
    const state = await apiGet("/api/state");
    currentUser = state.current_user || null;
    scanHistory = state.history || [];
    applyRbac();
    applyReport(state.latest_scan || scanHistory[0]?.report || null);
  } catch {
    renderDashboard();
    renderResults();
  }
}

async function loadEmailSettings() {
  const form = document.querySelector("[data-settings-form]");
  if (!form) return;
  try {
    const settings = await apiGet("/api/settings/email");
    if (!form.smtp_host) return;
    form.smtp_host.value = settings.smtp_host || "smtp.gmail.com";
    form.smtp_port.value = settings.smtp_port || 587;
    form.smtp_username.value = settings.smtp_username || "";
    form.smtp_from.value = settings.smtp_from || settings.smtp_username || "";
    form.smtp_use_tls.checked = settings.smtp_use_tls !== false;
    form.smtp_use_ssl.checked = settings.smtp_use_ssl === true;
  } catch {
    // Settings is server-protected; ignore if this user cannot load SMTP settings.
  }
}

function renderDashboard() {
  const summary = latestReport?.summary || {};
  const analysis = latestReport?.analysis || {};
  const set = (selector, value) => {
    const el = document.querySelector(selector);
    if (el) el.textContent = value;
  };
  set("[data-total-scans]", scanHistory.length);
  set("[data-critical-count]", summary.Critical || summary.critical || 0);
  set("[data-high-count]", summary.High || summary.high || 0);
  set("[data-medium-count]", summary.Medium || summary.medium || 0);
  set("[data-low-count]", summary.Low || summary.low || 0);
  set("[data-last-status]", scanHistory[0]?.status || "Ready");
  set("[data-last-target]", latestReport?.target || "No scan loaded");
  set("[data-risk-critical]", summary.Critical || summary.critical || 0);
  set("[data-risk-high]", summary.High || summary.high || 0);
  set("[data-risk-medium]", summary.Medium || summary.medium || 0);
  set("[data-risk-low]", summary.Low || summary.low || 0);
  set("[data-risk-info]", summary.Info || summary.info || 0);
  set("[data-risk-score]", latestReport ? `${analysis.risk_score || 0}/100` : "0/100");
  set("[data-risk-verdict]", analysis.verdict || "No Findings");
  const bar = document.querySelector("[data-risk-bar]");
  if (bar) bar.style.width = `${Math.min(Number(analysis.risk_score || 0), 100)}%`;
  const recent = document.querySelector("[data-recent-scans]");
  document.querySelector("[data-recent-empty]")?.classList.toggle("hidden", scanHistory.length > 0);
  if (recent) {
    recent.innerHTML = scanHistory.length ? scanHistory.slice(0, 8).map((entry) => `
      <tr><td>${escapeHtml(entry.scan_name || "CyberScan run")}</td><td>${escapeHtml(entry.target || "-")}</td><td>${escapeHtml(entry.type || "-")}</td><td>${escapeHtml(formatDate(entry.started))}</td><td>${escapeHtml(entry.findings_count ?? 0)}</td></tr>
    `).join("") : "";
  }
}

function renderResults() {
  const table = document.querySelector("[data-findings-table]");
  if (!table) return;
  const summary = document.querySelector("[data-results-summary]");
  const empty = document.querySelector("[data-findings-empty]");
  const selectedSeverity = document.querySelector("[data-severity-filters] .active")?.dataset.severityFilter || "all";
  const query = document.querySelector("[data-findings-search]")?.value.trim().toLowerCase() || "";
  if (summary) {
    summary.textContent = findings.length
      ? `CyberScan found ${findings.length} possible issue${findings.length === 1 ? "" : "s"}. Review each finding and apply the recommended fixes.`
      : "No findings detected in this safe scan.";
  }
  const visibleFindings = findings.filter((finding) => {
    const matchesSeverity = selectedSeverity === "all" || severityClass(finding.severity) === selectedSeverity;
    const haystack = [finding.severity, finding.vulnerability, finding.url, finding.evidence, finding.impact, finding.recommendation].join(" ").toLowerCase();
    return matchesSeverity && (!query || haystack.includes(query));
  });
  empty?.classList.toggle("hidden", visibleFindings.length > 0);
  if (!visibleFindings.length) {
    table.innerHTML = "";
    return;
  }
  table.innerHTML = visibleFindings.map((finding) => {
    const index = findings.indexOf(finding);
    return `
    <tr data-finding-index="${index}">
      <td><span class="badge ${severityClass(finding.severity)}">${escapeHtml(finding.severity)} - ${escapeHtml(severityMeaning(finding.severity))}</span></td>
      <td><strong>${escapeHtml(finding.vulnerability)}</strong></td>
      <td>${escapeHtml(finding.url)}</td>
      <td>${escapeHtml(finding.evidence)}</td>
      <td>${escapeHtml(finding.impact)}</td>
      <td>${escapeHtml(finding.recommendation)}</td>
      <td><span class="badge ${statusClass(finding.status)}">${escapeHtml(finding.status)}</span></td>
      <td><button class="btn" type="button">View Details</button></td>
    </tr>
  `; }).join("");
  table.querySelectorAll("[data-finding-index]").forEach((row) => {
    row.addEventListener("click", () => {
      localStorage.setItem("cyberscan.selectedFinding", row.dataset.findingIndex);
      window.location.href = "/finding-details";
    });
  });
}

function renderDetail() {
  const title = document.querySelector("[data-detail-title]");
  if (!title) return;
  const index = Number(localStorage.getItem("cyberscan.selectedFinding") || 0);
  const finding = findings[index];
  if (!finding) return;
  title.textContent = finding.vulnerability;
  const severity = document.querySelector("[data-detail-severity]");
  severity.textContent = finding.severity;
  severity.className = `badge ${severityClass(finding.severity)}`;
  document.querySelector("[data-detail-description]").textContent = finding.description;
  document.querySelector("[data-detail-found]").textContent = finding.vulnerability;
  document.querySelector("[data-detail-evidence]").textContent = finding.evidence;
  document.querySelector("[data-detail-impact]").textContent = finding.impact;
  document.querySelector("[data-detail-recommendation]").textContent = finding.recommendation;
  document.querySelector("[data-detail-url]").textContent = finding.url;
  const status = document.querySelector("[data-detail-status]");
  status.value = finding.status;
  status.addEventListener("change", async () => {
    finding.status = status.value;
    if (!finding.fingerprint) return;
    await apiPost("/api/findings/triage", { updates: [{ fingerprint: finding.fingerprint, status: finding.status }] });
  });
}

function renderReportStatus() {
  const message = document.querySelector("[data-report-message]");
  if (!message) return;
  const files = latestReport?.report_files || {};
  const available = ["html", "json", "csv"].filter((key) => files[key]).map((key) => key.toUpperCase()).join(", ");
  message.textContent = available ? `Available report exports: ${available}.` : "Run a scan to create report exports.";
}

document.querySelector("[data-findings-search]")?.addEventListener("input", renderResults);
document.querySelectorAll("[data-severity-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll("[data-severity-filter]").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    renderResults();
  });
});

document.querySelectorAll("[data-admin-table-filter]").forEach((input) => {
  input.addEventListener("input", () => {
    const table = input.closest(".card")?.querySelector("[data-admin-table]");
    const query = input.value.trim().toLowerCase();
    table?.querySelectorAll("tbody tr").forEach((row) => {
      row.classList.toggle("hidden", query && !row.textContent.toLowerCase().includes(query));
    });
  });
});

document.querySelector("[data-login-form]")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const message = document.querySelector("[data-login-message]");
  const submitButton = form.querySelector('button[type="submit"]');
  if (!form.password.value) {
    message.textContent = "Invalid username/email or password. Please try again.";
    return;
  }
  message.textContent = "Checking credentials...";
  setLoading(submitButton, true, "Logging in...");
  try {
    const payload = await apiPost("/api/login", {
      email: form.email.value,
      password: form.password.value
    });
    form.password.value = "";
    if (!payload.otp_required) {
      message.textContent = payload.message || "Login successful.";
      window.location.href = payload.redirect || "/dashboard";
      return;
    }
    pendingChallengeId = payload.challenge_id;
    form.classList.add("hidden");
    setLoading(submitButton, false);
    const otpForm = document.querySelector("[data-otp-form]");
    otpForm.classList.remove("hidden");
    otpForm.code.value = "";
    document.querySelector("[data-otp-message]").textContent = payload.message || "Enter the verification code.";
  } catch (error) {
    message.textContent = friendlyErrorMessage(error);
    if (error.message.includes("Real email OTP is not configured")) {
      message.textContent = "Login verification is not configured. Please use the local account flow.";
    }
    setLoading(submitButton, false);
  }
});

document.querySelector("[data-show-reset]")?.addEventListener("click", () => {
  document.querySelector("[data-login-form]").classList.add("hidden");
  document.querySelector("[data-otp-form]")?.classList.add("hidden");
  document.querySelector("[data-reset-request-form]").classList.remove("hidden");
});

document.querySelector("[data-back-login]")?.addEventListener("click", () => {
  document.querySelector("[data-reset-request-form]").classList.add("hidden");
  document.querySelector("[data-reset-confirm-form]").classList.add("hidden");
  document.querySelector("[data-login-form]").classList.remove("hidden");
});

document.querySelector("[data-reset-request-form]")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const message = document.querySelector("[data-reset-request-message]");
  const submitButton = form.querySelector('button[type="submit"]');
  message.textContent = "Sending verification email...";
  setLoading(submitButton, true, "Sending...");
  try {
    const payload = await apiPost("/api/password-reset/request", {
      email: form.email.value
    });
    pendingChallengeId = payload.challenge_id || "";
    message.textContent = payload.message || "Reset code sent to your email.";
    if (payload.challenge_id) {
      document.querySelector("[data-reset-confirm-form]").classList.remove("hidden");
    }
  } catch (error) {
    message.textContent = friendlyErrorMessage(error);
  } finally {
    setLoading(submitButton, false);
  }
});

document.querySelector("[data-reset-confirm-form]")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const message = document.querySelector("[data-reset-confirm-message]");
  const submitButton = form.querySelector('button[type="submit"]');
  message.textContent = "Resetting password...";
  setLoading(submitButton, true, "Resetting...");
  try {
    const payload = await apiPost("/api/password-reset/confirm", {
      challenge_id: pendingChallengeId,
      code: form.code.value,
      new_password: form.new_password.value
    });
    form.code.value = "";
    form.new_password.value = "";
    message.textContent = payload.message;
    document.querySelector("[data-reset-request-form]").classList.add("hidden");
    setTimeout(() => {
      document.querySelector("[data-reset-confirm-form]").classList.add("hidden");
      document.querySelector("[data-login-form]").classList.remove("hidden");
    }, 1000);
  } catch (error) {
    message.textContent = friendlyErrorMessage(error);
    setLoading(submitButton, false);
  }
});

document.querySelector("[data-otp-form]")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = document.querySelector("[data-otp-message]");
  const submitButton = event.currentTarget.querySelector('button[type="submit"]');
  setLoading(submitButton, true, "Verifying...");
  try {
    await apiPost("/api/verify-otp", {
      challenge_id: pendingChallengeId,
      code: event.currentTarget.code.value
    });
    window.location.href = "/dashboard";
  } catch (error) {
    message.textContent = friendlyErrorMessage(error);
    setLoading(submitButton, false);
  }
});

document.querySelector("[data-scan-form]")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const message = document.querySelector("[data-scan-message]");
  const submitButton = form.querySelector('button[type="submit"]');
  const headers = form.auth_headers.value.split(/\n+/).map((line) => line.trim()).filter(Boolean);
  const cookies = form.session_cookies.value.split(/\n+/).map((line) => line.trim()).filter(Boolean);
  const passwordAuditEnabled = form.password_audit_enabled.checked;
  if (!form.target.value.trim()) {
    message.textContent = "Please enter a target URL before starting the scan.";
    form.target.focus();
    return;
  }
  if (!isValidTarget(form.target.value)) {
    message.textContent = "Please enter a valid URL, example: https://example.com";
    form.target.focus();
    return;
  }
  if (!form.authorization_attested.checked) {
    message.textContent = "Please confirm that you have permission to scan this target.";
    return;
  }
  if (passwordAuditEnabled && !form.password_audit_authorized.checked) {
    message.textContent = "Password audit requires explicit authorization confirmation before it can run.";
    return;
  }
  const selectedTool = form.selected_tool?.value || form.dataset.selectedTool || "website_scanner";
  const activeTab = form.querySelector(".scan-tab.active")?.textContent || "Light Scan";
  const hostTarget = form.target_host?.value || form.target.value;
  const toolTarget = ["port_scanner", "network_scanner", "subdomain_finder"].includes(selectedTool) ? hostTarget : form.target.value;
  message.textContent = "Starting safe scan...";
  setLoading(submitButton, true, "Starting Scan...");
  if (form.selected_tool) {
    try {
      const payload = await apiPost("/api/run-tool", {
        tool: selectedTool,
        target: toolTarget,
        scan_type: activeTab.toLowerCase().replace(/\s+/g, "_"),
        authorization_confirmed: form.authorization_attested.checked,
        options: {
          ports: form.tool_ports?.value || "",
          wordlist: form.tool_wordlist?.value || "",
          subdomains: form.tool_wordlist?.value || "",
          max_requests: Number(form.tool_max_requests?.value || 10),
          delay: Number(form.tool_delay?.value || 0.5),
          timeout: 1,
          login_url: form.password_audit_login_url.value || form.login_url.value || form.target.value,
          username: form.password_audit_username.value || form.login_username.value,
          password_list: form.password_audit_password_list.value,
          max_attempts: Number(form.password_audit_max_attempts.value || 5),
          stop_on_success: form.password_audit_stop_on_success.checked,
          scan_id: localStorage.getItem("cyberscan.latestToolScanId") || ""
        }
      });
      message.textContent = payload.message || "Scan completed successfully.";
      localStorage.setItem("cyberscan.latestToolScanId", payload.scan_id || "");
      localStorage.setItem("cyberscan.progressScanId", payload.scan_id || "");
      localStorage.setItem("cyberscan.progressTarget", toolTarget || "Active target");
      localStorage.setItem("cyberscan.progressTool", selectedTool.replace(/_/g, " "));
      localStorage.setItem("cyberscan.progressType", activeTab);
      setTimeout(() => {
        const scanId = encodeURIComponent(payload.scan_id || "");
        window.location.href = payload.scan_id ? `/scan-progress?scan_id=${scanId}&result_url=${encodeURIComponent(`/results/${payload.scan_id}`)}` : "/scan-progress";
      }, 700);
    } catch (error) {
      message.textContent = friendlyErrorMessage(error);
      setLoading(submitButton, false);
    }
    return;
  }
  try {
    const payload = await apiPost("/api/scan", {
      target: form.target.value,
      targets: [form.target.value],
      scan_name: form.scan_name.value || "CyberScan Assessment",
      max_pages: Number(form.max_pages.value || 50),
      rate_limit: Number(form.rate_limit.value || 5),
      include_paths: form.include_paths.value,
      exclude_paths: form.exclude_paths.value,
      auth_headers: headers,
      session_cookies: cookies,
      scan_type: headers.length || cookies.length ? "Authenticated" : "Full",
      port_scan: Boolean(document.querySelector('[data-tool="port"]')?.checked),
      ports: "80,443,8080,8443",
      authorization: {
        organization: form.authorization_organization.value,
        contact: form.authorization_contact.value,
        scope: form.authorization_scope.value || form.target.value,
        attested: form.authorization_attested.checked
      },
      password_audit: {
        enabled: passwordAuditEnabled,
        login_url: form.password_audit_login_url.value || form.login_url.value,
        username: form.password_audit_username.value || form.login_username.value,
        password_list: form.password_audit_password_list.value,
        max_attempts: Number(form.password_audit_max_attempts.value || 5),
        delay_seconds: Number(form.password_audit_delay_seconds.value || 1),
        stop_on_success: form.password_audit_stop_on_success.checked,
        authorization_confirmed: form.password_audit_authorized.checked
      },
      authorized: true,
      background: true
    });
    activeScanId = payload.scan_id;
    localStorage.setItem("cyberscan.activeScanId", activeScanId);
    localStorage.setItem("cyberscan.progressScanId", activeScanId);
    localStorage.setItem("cyberscan.activeTarget", form.target.value);
    localStorage.setItem("cyberscan.progressTarget", form.target.value);
    localStorage.setItem("cyberscan.progressTool", "Website Scanner");
    localStorage.setItem("cyberscan.progressType", headers.length || cookies.length ? "Authenticated" : "Full");
    window.location.href = `/scan-progress?scan_id=${encodeURIComponent(activeScanId)}`;
  } catch (error) {
    message.textContent = friendlyErrorMessage(error);
    setLoading(submitButton, false);
  }
});

const auditEnabled = document.querySelector('[name="password_audit_enabled"]');
const auditAuthorized = document.querySelector('[name="password_audit_authorized"]');
auditEnabled?.addEventListener("change", () => {
  if (auditEnabled.checked && !auditAuthorized.checked) {
    document.querySelector("[data-scan-message]").textContent = "Confirm authorization before enabling the password audit module.";
    auditEnabled.checked = false;
  }
});

document.querySelector("[data-cancel-scan]")?.addEventListener("click", async () => {
  if (!activeScanId) return;
  await apiPost("/api/scan/cancel", { scan_id: activeScanId });
  localStorage.removeItem("cyberscan.activeScanId");
});

const SCAN_STEPS = [
  "Initializing scan engine",
  "Validating target permission",
  "Checking website security headers",
  "Checking SSL/TLS protection",
  "Looking for insecure cookies",
  "Checking website areas",
  "Inspecting website forms",
  "Checking common exposed paths",
  "Running selected safe tool checks",
  "Organizing finding results",
  "Preparing your report",
  "Scan completed"
];

const SCAN_LOG_MESSAGES = [
  "Checking website security headers...",
  "Looking for insecure cookies...",
  "Inspecting website forms...",
  "Checking common exposed paths safely...",
  "Reviewing website areas checked...",
  "Organizing finding results...",
  "Preparing your report...",
  "Scan is almost complete..."
];

function setText(selector, value) {
  const element = document.querySelector(selector);
  if (element) element.textContent = value;
}

function updateScanStep(stepIndex) {
  document.querySelectorAll(".scan-step").forEach((step, index) => {
    step.classList.toggle("completed", index < stepIndex);
    step.classList.toggle("active", index === stepIndex);
    const badge = step.querySelector("span");
    if (badge) badge.textContent = index < stepIndex ? "OK" : String(index + 1);
  });
  setText("[data-current-task]", SCAN_STEPS[Math.min(stepIndex, SCAN_STEPS.length - 1)]);
}

function appendScanLog(message) {
  const log = document.querySelector("[data-scan-log]");
  if (!log) return;
  const stamp = new Date().toLocaleTimeString();
  const item = document.createElement("div");
  item.className = "scan-log-item";
  item.innerHTML = `<small>[${escapeHtml(stamp)}]</small>${escapeHtml(message)}`;
  log.prepend(item);
  while (log.children.length > 12) log.removeChild(log.lastElementChild);
}

function setProgressUI(value) {
  progress = Math.max(0, Math.min(100, Math.round(value)));
  setText("[data-progress-percent]", `${progress}%`);
  const bar = document.querySelector("[data-progress-bar]");
  if (bar) bar.style.width = `${progress}%`;
  setText("[data-pages-crawled]", Math.max(0, Math.floor(progress / 9)));
  setText("[data-findings-detected]", Math.max(0, Math.floor(progress / 28)));
  setText("[data-estimated-completion]", progress < 100 ? "Estimated completion: a few seconds remaining" : "Estimated completion: complete");
  updateScanStep(Math.min(SCAN_STEPS.length - 1, Math.floor(progress / (100 / SCAN_STEPS.length))));
}

function completeScan(scanId, redirectUrl) {
  setProgressUI(100);
  setText("[data-scan-status]", "Completed");
  setText("[data-progress-status]", "Completed");
  setText("[data-status-label]", "Completed");
  setText("[data-current-task]", "Scan completed successfully. You can now review the results.");
  setText("[data-estimated-completion]", "Scan completed successfully. You can now review the results.");
  document.querySelector("[data-scan-status]")?.classList.remove("status-running", "status-failed");
  document.querySelector("[data-scan-status]")?.classList.add("status-completed");
  document.querySelector("[data-scan-complete-actions]")?.removeAttribute("hidden");
  appendScanLog("Scan completed successfully. You can now review the results.");
  localStorage.removeItem("cyberscan.activeScanId");
  setTimeout(() => {
    window.location.href = redirectUrl || (scanId ? `/results/${encodeURIComponent(scanId)}` : "/results");
  }, 2200);
}

function showNoActiveScan() {
  clearInterval(pollTimer);
  setProgressUI(0);
  setText("[data-current-task]", "No active scan is running.");
  setText("[data-active-tool]", "CyberScan Tool");
  setText("[data-progress-target]", "No active target");
  setText("[data-scan-type]", "Not started");
  setText("[data-pages-crawled]", "0");
  setText("[data-findings-detected]", "0");
  setText("[data-estimated-completion]", "Start a new scan to view live progress.");
  setText("[data-scan-status]", "Idle");
  setText("[data-progress-status]", "Idle");
  setText("[data-status-label]", "Idle");
  const status = document.querySelector("[data-scan-status]");
  status?.classList.remove("status-running", "status-completed", "status-failed");
  document.querySelector("[data-scan-log]")?.replaceChildren();
  document.querySelector("[data-scan-complete-actions]")?.setAttribute("hidden", "");
}

async function pollScanStatus(scanId) {
  if (!scanId) return null;
  try {
    const job = await apiGet(`/api/scan/jobs/${encodeURIComponent(scanId)}`);
    return {
      status: job.status,
      report: job.report,
      findings: job.report?.findings || [],
      pages: job.report?.coverage?.urls_scanned,
      redirect_url: job.report?.scan_id ? `/results/${job.report.scan_id}` : "/results"
    };
  } catch {
    try {
      const payload = await apiGet(`/api/scan/${encodeURIComponent(scanId)}`);
      return {
        status: payload.scan ? "completed" : "running",
        report: payload.scan,
        findings: payload.scan?.findings || [],
        pages: payload.scan?.coverage?.urls_scanned,
        redirect_url: `/results/${scanId}`
      };
    } catch {
      return null;
    }
  }
}

function startScanAnimation() {
  if (page !== "scan-progress") return;
  const holder = document.querySelector("[data-scan-progress-page]");
  const params = new URLSearchParams(window.location.search);
  const scanId = params.get("scan_id") || holder?.dataset.scanId || "";
  if (!scanId) {
    showNoActiveScan();
    return;
  }
  const resultUrl = params.get("result_url") || holder?.dataset.resultUrl || (scanId ? `/results/${scanId}` : "/results");
  setText("[data-active-tool]", localStorage.getItem("cyberscan.progressTool") || "CyberScan Tool");
  setText("[data-progress-target]", localStorage.getItem("cyberscan.progressTarget") || localStorage.getItem("cyberscan.activeTarget") || "Active target");
  setText("[data-scan-type]", localStorage.getItem("cyberscan.progressType") || "Safe scan");
  setText("[data-progress-status]", "Running");
  setText("[data-status-label]", "Running");
  setProgressUI(0);
  appendScanLog("Initializing scan engine...");
  let logIndex = 0;
  let ticks = 0;
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    ticks += 1;
    const next = progress + (progress < 80 ? 7 : 3);
    setProgressUI(Math.min(next, 96));
    if (ticks % 2 === 0) {
      appendScanLog(SCAN_LOG_MESSAGES[logIndex % SCAN_LOG_MESSAGES.length]);
      logIndex += 1;
    }
    const backend = ticks % 2 === 0 ? await pollScanStatus(scanId) : null;
    if (backend?.status === "failed" || backend?.status === "cancelled") {
      clearInterval(pollTimer);
      setText("[data-scan-status]", backend.status);
      setText("[data-progress-status]", backend.status);
      setText("[data-status-label]", backend.status);
      document.querySelector("[data-scan-status]")?.classList.remove("status-running");
      document.querySelector("[data-scan-status]")?.classList.add("status-failed");
      appendScanLog(`Scan ${backend.status}.`);
      return;
    }
    if ((backend?.status === "complete" || backend?.status === "completed") && ticks >= 4) {
      clearInterval(pollTimer);
      if (backend.report) applyReport(backend.report);
      if (backend.pages !== undefined) setText("[data-pages-crawled]", backend.pages);
      setText("[data-findings-detected]", backend.findings?.length || 0);
      completeScan(scanId, backend.redirect_url || resultUrl);
      return;
    }
    if (progress >= 96 && ticks >= 8) {
      clearInterval(pollTimer);
      completeScan(scanId, resultUrl);
    }
  }, 650);
}

async function pollScan() {
  startScanAnimation();
}

document.querySelectorAll("[data-download-report]").forEach((button) => {
  button.addEventListener("click", () => {
    const format = button.dataset.downloadReport;
    const url = latestReport?.report_files?.[format] || (latestReport?.scan_id ? `/reports/${format}/${encodeURIComponent(latestReport.scan_id)}` : "");
    if (!url) {
      alert("Run a scan first to create this report.");
      return;
    }
    setLoading(button, true, "Downloading...");
    window.location.href = url;
  });
});

document.querySelectorAll("[data-generate-report]").forEach((button) => {
  button.addEventListener("click", async () => {
    const message = document.querySelector("[data-report-message]");
    setLoading(button, true, "Generating...");
    if (message) message.textContent = "Generating report...";
    try {
      const payload = await apiPost("/api/report/generate", { template: "Full Technical Report" });
      if (message) message.textContent = "Full Technical Report generated.";
      if (payload.report?.report_files?.html) window.location.href = payload.report.report_files.html;
    } catch (error) {
      if (message) message.textContent = friendlyErrorMessage(error);
      setLoading(button, false);
    }
  });
});

document.querySelector("[data-share-report]")?.addEventListener("click", async () => {
  const message = document.querySelector("[data-share-message]");
  const button = document.querySelector("[data-share-report]");
  setLoading(button, true, "Creating Link...");
  try {
    const latestHtml = latestReport?.report_files?.html || "";
    const payload = await apiPost("/api/report/share", { report_file: latestHtml });
    const absoluteUrl = `${window.location.origin}${payload.url}`;
    message.innerHTML = `Secure share link created: <a class="link" href="${escapeHtml(payload.url)}" target="_blank" rel="noreferrer">${escapeHtml(absoluteUrl)}</a>`;
  } catch (error) {
    message.textContent = friendlyErrorMessage(error);
  } finally {
    setLoading(button, false);
  }
});

document.querySelector("[data-settings-form]")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  localStorage.setItem("cyberscan.settings", JSON.stringify({
    defaultMaxPages: form.default_max_pages.value,
    defaultRateLimit: form.default_rate_limit.value,
    reportFolder: form.report_folder.value,
    defaultScanType: form.default_scan_type.value,
    emailVerification: form.email_verification.checked,
    authorized: form.authorized.checked,
    workspaceName: form.workspace_name.value,
    licenseMode: form.license_mode.value,
    ownerAccount: form.owner_account.value,
    auditLogging: form.audit_logging.checked,
    secureReports: form.secure_reports.checked,
    deploymentSecurity: form.deployment_security.checked
  }));
  const message = document.querySelector("[data-settings-message]");
  if (!form.smtp_host) {
    message.textContent = "Settings saved in this browser.";
    return;
  }
  message.textContent = "Saving settings...";
  apiPost("/api/settings/email", {
    smtp_host: form.smtp_host.value,
    smtp_port: form.smtp_port.value,
    smtp_username: form.smtp_username.value,
    smtp_password: form.smtp_password.value,
    smtp_from: form.smtp_from.value,
    smtp_use_tls: form.smtp_use_tls.checked,
    smtp_use_ssl: form.smtp_use_ssl.checked
  }).then((payload) => {
    form.smtp_password.value = "";
    message.textContent = `${payload.message} Other settings saved in this browser.`;
  }).catch((error) => {
    message.textContent = error.message;
  });
});

loadState().then(() => {
  loadEmailSettings();
  pollScan();
});
