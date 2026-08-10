const state = {
  email: "",
  dashboard: null,
  activeReport: null,
  activeScanId: null,
  assessmentMode: "vulnerability_assessment",
  scanTier: "full_scan",
  refreshTimer: null,
  verificationTimer: null,
  verificationExpiresAt: null,
};

document.addEventListener("DOMContentLoaded", () => {
  document
    .getElementById("verify-code-form")
    .addEventListener("submit", handleVerifyCode);
  document.getElementById("resend-code-button").addEventListener("click", handleResendVerificationCode);
  document.getElementById("registration-form").addEventListener("submit", handleRegister);
  document.getElementById("register-show-password-input").addEventListener("change", toggleRegistrationPasswordVisibility);
  document.getElementById("login-form").addEventListener("submit", handleLogin);
  document.getElementById("login-show-password-input").addEventListener("change", toggleLoginPasswordVisibility);
  document.getElementById("forgot-password-button").addEventListener("click", showPasswordResetPage);
  document.getElementById("back-to-login-button").addEventListener("click", () => showOnly("landing-page"));
  document.getElementById("password-reset-request-form").addEventListener("submit", handlePasswordResetRequest);
  document.getElementById("password-reset-confirm-form").addEventListener("submit", handlePasswordResetConfirm);
  document.getElementById("scan-form").addEventListener("submit", handleCreateScan);
  document.getElementById("manual-finding-form").addEventListener("submit", handleAddManualFinding);
  document.querySelectorAll("[data-plan]").forEach((button) => {
    button.addEventListener("click", () => handleCheckoutPlan(button.dataset.plan));
  });
  document.getElementById("logout-button").addEventListener("click", handleLogout);
  document.getElementById("choice-logout-button").addEventListener("click", handleLogout);
  document.getElementById("report-download-button").addEventListener("click", () => {
    if (state.activeScanId) downloadReport(state.activeScanId);
  });
  document.getElementById("report-email-button").addEventListener("click", () => {
    if (state.activeScanId) emailReport(state.activeScanId);
  });
  document.querySelectorAll("[data-assessment-mode]").forEach((button) => {
    button.addEventListener("click", () => selectAssessmentMode(button.dataset.assessmentMode));
  });
  document.querySelectorAll("[data-choice-mode]").forEach((button) => {
    button.addEventListener("click", () => openSelectedTool(button.dataset.choiceMode));
  });
  ensureCsrfCookie().then(() => loadDashboard(false, { showChoiceWhenAuthenticated: true }));
});

function getCookie(name) {
  return document.cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${name}=`))
    ?.split("=")
    .slice(1)
    .join("=") || "";
}

function csrfHeaders() {
  const token = decodeURIComponent(getCookie("kryptnet_csrf"));
  return token ? { "X-CSRF-Token": token } : {};
}

function jsonHeaders() {
  return { "Content-Type": "application/json", ...csrfHeaders() };
}

async function ensureCsrfCookie() {
  if (getCookie("kryptnet_csrf")) return;
  await fetch("/", { method: "GET", cache: "no-store" });
}

async function fetchJson(url, options = {}, retryOnCsrf = true) {
  await ensureCsrfCookie();
  const response = await fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
      ...jsonHeaders(),
    },
  });
  let payload = {};
  try {
    payload = await response.json();
  } catch (_error) {
    payload = {};
  }
  if (
    retryOnCsrf &&
    response.status === 403 &&
    String(payload.detail || "").toLowerCase().includes("csrf")
  ) {
    await fetch("/", { method: "GET", cache: "reload" });
    return fetchJson(url, options, false);
  }
  return { response, payload };
}

function showOnly(sectionId) {
  ["landing-page", "verification-page", "password-reset-page", "tool-choice-page", "dashboard"].forEach((id) => {
    const element = document.getElementById(id);
    if (element) element.classList.toggle("hidden", id !== sectionId);
  });
}

function showVerificationPage() {
  showOnly("verification-page");
  window.location.hash = "verify-code";
}

function showToolChoicePage() {
  showOnly("tool-choice-page");
  window.location.hash = "choose-tool";
}

function showPasswordResetPage() {
  showOnly("password-reset-page");
  window.location.hash = "reset-password";
}

function showDashboardPage() {
  showOnly("dashboard");
  window.location.hash = "dashboard";
}

function openSelectedTool(mode) {
  selectAssessmentMode(mode);
  showDashboardPage();
}

function toggleRegistrationPasswordVisibility() {
  const visible = document.getElementById("register-show-password-input").checked;
  ["register-password-input", "register-password-confirm-input"].forEach((id) => {
    const input = document.getElementById(id);
    if (input) input.type = visible ? "text" : "password";
  });
}

function toggleLoginPasswordVisibility() {
  const input = document.getElementById("login-password-input");
  const visible = document.getElementById("login-show-password-input").checked;
  if (input) input.type = visible ? "text" : "password";
}

function setButtonBusy(buttonId, busy, busyText) {
  const button = document.getElementById(buttonId);
  if (!button) return;
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyText;
    button.disabled = true;
    return;
  }
  button.textContent = button.dataset.originalText || button.textContent;
  button.disabled = false;
}

function selectAssessmentMode(mode) {
  state.assessmentMode = mode;
  const clientOnly = state.dashboard?.user?.role === "client_viewer";
  document.getElementById("assessment-mode-input").value = mode;
  document.querySelectorAll("[data-assessment-mode]").forEach((button) => {
    button.classList.toggle("active", button.dataset.assessmentMode === mode);
  });
  const submit = document.getElementById("scan-submit-button");
  const ethicalFields = document.getElementById("ethical-pentest-fields");
  if (ethicalFields) {
    ethicalFields.classList.toggle("hidden", clientOnly || mode !== "ethical_pentesting");
  }
  if (mode === "ethical_pentesting") {
    selectScanTier("full_scan", { silent: true });
  } else {
    selectScanTier("full_scan", { silent: true });
  }
  updateReportIntakeVisibility();
  updateScanSubmitText();
  const subtitle = document.getElementById("dashboard-subtitle");
  if (subtitle && state.dashboard) {
    subtitle.textContent =
      mode === "ethical_pentesting"
        ? `${state.dashboard.user.email} verified for ${state.dashboard.organization.domain}. Ethical Pen-Testing is paid-only and uses the approved target and full-stack testing tools.`
        : `${state.dashboard.user.email} verified for ${state.dashboard.organization.domain}. Run a full vulnerability assessment for an authorized asset and receive a PDF report.`;
  }
  if (state.dashboard) {
    renderCommercialReadiness(state.dashboard);
  }
}

function selectScanTier(tier, options = {}) {
  state.scanTier = "full_scan";
  document.getElementById("scan-tier-input").value = "full_scan";
  updateReportIntakeVisibility();
  updateScanSubmitText();
  if (!options.silent && state.dashboard) {
    renderCommercialReadiness(state.dashboard);
  }
}

function updateReportIntakeVisibility() {
  const panel = document.getElementById("report-intake-fields");
  if (!panel) return;
  const required = true;
  panel.classList.toggle("hidden", !required);
  [
    "report-company-name-input",
    "report-company-address-input",
    "report-contact-name-input",
    "report-contact-email-input",
    "report-contact-phone-input",
    "report-authorization-reference-input",
    "report-scope-notes-input",
    "report-testing-window-input",
    "report-emergency-contact-input",
  ].forEach((id) => {
    const field = document.getElementById(id);
    if (field) field.required = required;
  });
}

function updateScanSubmitText() {
  const submit = document.getElementById("scan-submit-button");
  if (!submit) return;
  if (state.assessmentMode === "ethical_pentesting") {
    submit.textContent = "Run Ethical Pen-Testing";
  } else {
    submit.textContent = "Run Vulnerability Assessment";
  }
}

function startVerificationTimer(seconds) {
  state.verificationExpiresAt = Date.now() + Number(seconds || 600) * 1000;
  const timer = document.getElementById("verification-timer");
  const verifyButton = document.querySelector("#verify-code-form button[type='submit']");
  const render = () => {
    const remaining = Math.max(0, Math.ceil((state.verificationExpiresAt - Date.now()) / 1000));
    const minutes = String(Math.floor(remaining / 60)).padStart(2, "0");
    const secs = String(remaining % 60).padStart(2, "0");
    if (timer) {
      timer.textContent =
        remaining > 0
          ? `Verification code expires in ${minutes}:${secs}.`
          : "Verification code expired. Request a new code to continue.";
      timer.classList.toggle("expired", remaining === 0);
    }
    if (verifyButton) verifyButton.disabled = remaining === 0;
    if (remaining === 0 && state.verificationTimer) {
      window.clearInterval(state.verificationTimer);
      state.verificationTimer = null;
    }
  };
  if (state.verificationTimer) window.clearInterval(state.verificationTimer);
  if (verifyButton) verifyButton.disabled = false;
  render();
  state.verificationTimer = window.setInterval(render, 1000);
}

function clearVerificationTimer() {
  if (state.verificationTimer) {
    window.clearInterval(state.verificationTimer);
    state.verificationTimer = null;
  }
}

async function handleCheckoutPlan(plan) {
  const response = await fetch("/api/payments/checkout", {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({ plan }),
  });
  const payload = await response.json();
  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Unable to prepare checkout.", "error");
    return;
  }
  const planName = payload.plan?.name || plan;
  const accessActive = payload.payment_access_status === "active";
  setStatus(
    "dashboard-status",
    accessActive
      ? `${planName} KryptNet debit/credit checkout link created. Paid access is active.`
      : `${planName} KryptNet debit/credit checkout link created. Complete checkout to activate paid access.`,
    accessActive ? "success" : "neutral"
  );
  if (payload.checkout_url) {
    window.open(payload.checkout_url, "_blank", "noopener");
  }
  await loadDashboard();
}

async function handleRequestCode(event) {
  event.preventDefault();
  const email = document.getElementById("register-email-input").value.trim();
  state.email = email;

  const { response, payload } = await fetchJson("/api/auth/request-code", {
    method: "POST",
    body: JSON.stringify({ email }),
  });

  if (!response.ok) {
    setStatus("auth-status", payload.detail || "Unable to send verification code.", "error");
    return;
  }

  const isConsoleDelivery = payload.delivery === "console";
  const message = isConsoleDelivery
    ? `Verification code generated for ${payload.email}. Local testing mode is active, so read the code from the server terminal to continue.`
    : `Verification code sent to ${payload.email}. Check your inbox and spam folder. It expires in 10 minutes.`;
  setStatus("verify-status", message, "success");
  startVerificationTimer(payload.expires_in_seconds || 600);
  showVerificationPage();
}

async function handleResendVerificationCode() {
  const email =
    state.email ||
    document.getElementById("register-email-input").value.trim() ||
    document.getElementById("login-email-input").value.trim();
  if (!email) {
    setStatus("verify-status", "Enter your email on the registration or login form, then request a new code.", "error");
    showOnly("landing-page");
    return;
  }
  state.email = email;
  const { response, payload } = await fetchJson("/api/auth/request-code", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  if (!response.ok) {
    setStatus("verify-status", payload.detail || "Unable to resend verification code.", "error");
    return;
  }
  const isConsoleDelivery = payload.delivery === "console";
  setStatus(
    "verify-status",
    isConsoleDelivery
      ? `New verification code generated for ${payload.email}. Local testing mode is active, so read the code from the server terminal.`
      : `New verification code sent to ${payload.email}. Check inbox and spam. It expires in 10 minutes.`,
    "success"
  );
  document.getElementById("code-input").value = "";
  startVerificationTimer(payload.expires_in_seconds || 600);
}

async function handleRegister(event) {
  event.preventDefault();
  setButtonBusy("registration-submit-button", true, "Submitting...");
  const password = document.getElementById("register-password-input").value;
  const confirmPassword = document.getElementById("register-password-confirm-input").value;
  const email = document.getElementById("register-email-input").value.trim();
  state.email = email;
  if (password !== confirmPassword) {
    setStatus("auth-status", "Passwords do not match.", "error");
    setButtonBusy("registration-submit-button", false);
    return;
  }

  try {
    const { response, payload } = await fetchJson("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        email,
        password,
        full_name: document.getElementById("register-name-input").value.trim(),
        job_title: document.getElementById("register-title-input").value.trim(),
        professional_role: document.getElementById("register-role-input").value.trim(),
        company_name: document.getElementById("register-company-input").value.trim(),
        company_address: document.getElementById("register-address-input").value.trim(),
        phone_number: document.getElementById("register-phone-input").value.trim(),
        date_of_birth: document.getElementById("register-dob-input").value || null,
        testing_reason: document.getElementById("register-reason-input").value.trim(),
        data_protection_accepted: document.getElementById("register-data-protection-input").checked,
        safe_use_accepted: document.getElementById("register-safe-use-input").checked,
      }),
    });
    if (!response.ok) {
      setStatus("auth-status", payload.detail || "Unable to complete registration.", "error");
      return;
    }
    setStatus(
      "verify-status",
      `Registration received. Verification code sent to ${payload.email}. It expires in 10 minutes.`,
      "success"
    );
    startVerificationTimer(payload.expires_in_seconds || 600);
    showVerificationPage();
  } finally {
    setButtonBusy("registration-submit-button", false);
  }
}

async function handleLogin(event) {
  event.preventDefault();
  setButtonBusy("login-submit-button", true, "Logging in...");
  const email = document.getElementById("login-email-input").value.trim();
  state.email = email;
  try {
    const { response, payload } = await fetchJson("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email,
        password: document.getElementById("login-password-input").value,
      }),
    });
    if (!response.ok) {
      const detail = String(payload.detail || "");
      if (response.status === 403 && detail.toLowerCase().includes("verification")) {
        setStatus("verify-status", detail, "neutral");
        startVerificationTimer(payload.expires_in_seconds || 600);
        showVerificationPage();
        return;
      }
      if (detail.toLowerCase().includes("locked")) {
        setStatus("auth-status", `${detail} Use Reset Password to unlock the account immediately.`, "error");
        return;
      }
      setStatus("auth-status", detail || "Unable to log in.", "error");
      return;
    }
    setStatus("auth-status", "Login successful.", "success");
    await loadDashboard(false, { showChoiceWhenAuthenticated: true });
  } finally {
    setButtonBusy("login-submit-button", false);
  }
}

async function handleVerifyCode(event) {
  event.preventDefault();
  const code = document.getElementById("code-input").value.trim();
  const email = state.email || document.getElementById("register-email-input").value.trim() || document.getElementById("login-email-input").value.trim();

  const { response, payload } = await fetchJson("/api/auth/verify", {
    method: "POST",
    body: JSON.stringify({ email, code }),
  });

  if (!response.ok) {
    setStatus("verify-status", payload.detail || "Verification failed.", "error");
    return;
  }

  clearVerificationTimer();
  setStatus(
    "verify-status",
    "Email verified. Choose a testing option to continue.",
    "success"
  );
  await loadDashboard(false, { showChoiceWhenAuthenticated: true });
}

async function handleCompleteRegistration(event) {
  event.preventDefault();
  const { response, payload } = await fetchJson("/api/auth/complete-registration", {
    method: "POST",
    body: JSON.stringify({
      full_name: document.getElementById("register-name-input").value.trim(),
      job_title: document.getElementById("register-title-input").value.trim(),
      professional_role: document.getElementById("register-role-input").value.trim(),
      company_name: document.getElementById("register-company-input").value.trim(),
      company_address: document.getElementById("register-address-input").value.trim(),
      phone_number: document.getElementById("register-phone-input").value.trim(),
      date_of_birth: document.getElementById("register-dob-input").value || null,
      testing_reason: document.getElementById("register-reason-input").value.trim(),
      data_protection_accepted: document.getElementById("register-data-protection-input").checked,
      safe_use_accepted: document.getElementById("register-safe-use-input").checked,
    }),
  });
  if (!response.ok) {
    setStatus("registration-status", payload.detail || "Unable to complete registration.", "error");
    return;
  }
  setStatus("registration-status", "Registration completed. Choose a service to continue.", "success");
  await loadDashboard(false, { showChoiceWhenAuthenticated: true });
}

async function handlePasswordResetRequest(event) {
  event.preventDefault();
  const email = document.getElementById("reset-email-input").value.trim();
  state.email = email;
  const { response, payload } = await fetchJson("/api/auth/password-reset/request", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  if (!response.ok) {
    setStatus("password-reset-status", payload.detail || "Unable to send reset code.", "error");
    return;
  }
  setStatus("password-reset-status", "If the account exists, a reset code has been sent. The code expires in 10 minutes.", "success");
}

async function handlePasswordResetConfirm(event) {
  event.preventDefault();
  const { response, payload } = await fetchJson("/api/auth/password-reset/confirm", {
    method: "POST",
    body: JSON.stringify({
      email: document.getElementById("reset-email-input").value.trim() || state.email,
      code: document.getElementById("reset-code-input").value.trim(),
      new_password: document.getElementById("reset-password-input").value,
    }),
  });
  if (!response.ok) {
    setStatus("password-reset-status", payload.detail || "Unable to reset password.", "error");
    return;
  }
  setStatus("password-reset-status", "Password reset successful. Choose a testing option to continue.", "success");
  await loadDashboard(false, { showChoiceWhenAuthenticated: true });
}

async function handleCreateScan(event) {
  event.preventDefault();
  const target = document.getElementById("target-input").value.trim();
  const assessment_mode = document.getElementById("assessment-mode-input").value;
  const scan_tier = "full_scan";
  const body = { target, assessment_mode, scan_tier };
  const needsReportIntake = true;
  if (needsReportIntake) {
    body.report_company_name = document.getElementById("report-company-name-input").value.trim();
    body.report_company_address = document.getElementById("report-company-address-input").value.trim();
    body.report_contact_name = document.getElementById("report-contact-name-input").value.trim();
    body.report_contact_email = document.getElementById("report-contact-email-input").value.trim();
    body.report_contact_phone = document.getElementById("report-contact-phone-input").value.trim();
    body.report_authorization_reference = document.getElementById("report-authorization-reference-input").value.trim();
    body.report_scope_notes = document.getElementById("report-scope-notes-input").value.trim();
    body.report_testing_window = document.getElementById("report-testing-window-input").value.trim();
    body.report_emergency_contact = document.getElementById("report-emergency-contact-input").value.trim();
  }
  if (assessment_mode === "ethical_pentesting") {
    body.pentest_depth = document.getElementById("pentest-depth-input").value;
    body.validation_mode = document.getElementById("validation-mode-input").value;
    body.vulnerability_focus = document
      .getElementById("vulnerability-focus-input")
      .value.split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    body.known_vulnerabilities = document.getElementById("known-vulnerabilities-input").value.trim() || null;
  }

  const { response, payload } = await fetchJson("/api/scans", {
    method: "POST",
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Unable to launch assessment.", "error");
    return;
  }

  let deliveryNote = "";
  if (payload.status === "completed") {
    if (payload.report_email_sent_at) {
      deliveryNote = " PDF report emailed to your verified work address.";
    } else if (payload.report_email_error) {
      deliveryNote = ` Report created, but email delivery failed: ${payload.report_email_error}.`;
    } else if (payload.report_pdf_available) {
      deliveryNote = " PDF report is ready in the dashboard.";
    }
  } else if (payload.status === "queued") {
    deliveryNote = " The scan is queued and will run in the background.";
  } else if (payload.status === "running") {
    deliveryNote = " The scan is running in the background.";
  }

  setStatus(
    "dashboard-status",
    `${formatMode(payload.assessment_mode)} created for ${payload.target}. Current status: ${payload.status}.${deliveryNote}`,
    "success"
  );
  document.getElementById("scan-form").reset();
  selectAssessmentMode(state.assessmentMode);
  selectScanTier("full_scan", { silent: true });
  await loadDashboard(true);
  if (payload.status === "completed") {
    await loadReport(payload.id);
  }
}

async function handleLogout() {
  await fetch("/api/auth/logout", { method: "POST", headers: csrfHeaders() });
  if (state.refreshTimer) {
    window.clearTimeout(state.refreshTimer);
    state.refreshTimer = null;
  }
  state.dashboard = null;
  state.activeReport = null;
  state.activeScanId = null;
  showOnly("landing-page");
  setStatus("auth-status", "You have been logged out.", "neutral");
}

async function loadDashboard(showStatus = false, options = {}) {
  const response = await fetch("/api/dashboard");
  if (!response.ok) {
    showOnly("landing-page");
    return;
  }

  const payload = await response.json();
  state.dashboard = payload;
  renderDashboard(payload);
  await loadScannerHealth();
  if (payload.user?.role === "client_viewer") {
    showDashboardPage();
    await loadClientPortal();
  } else if (!payload.user?.profile_complete) {
    showOnly("landing-page");
  } else if (options.showChoiceWhenAuthenticated) {
    showToolChoicePage();
  } else {
    showDashboardPage();
  }

  if (showStatus) {
    setStatus(
      "dashboard-status",
      `Connected to ${payload.organization.name} (${payload.organization.domain}).`,
      "neutral"
    );
  }

  const latestReport = payload.scans.find((scan) => scan.status === "completed");
  if (latestReport) {
    await loadReport(latestReport.id);
  }
  scheduleDashboardRefresh(payload);
}

function scheduleDashboardRefresh(payload) {
  if (state.refreshTimer) {
    window.clearTimeout(state.refreshTimer);
    state.refreshTimer = null;
  }
  const hasActiveScan = (payload.scans || []).some((scan) => ["queued", "running"].includes(scan.status));
  if (hasActiveScan) {
    state.refreshTimer = window.setTimeout(() => loadDashboard(false), 5000);
  }
}

async function loadScannerHealth() {
  const response = await fetch("/api/scanner-health");
  if (!response.ok) return;
  const payload = await response.json();
  renderScannerHealth(payload);
}

async function loadClientPortal() {
  const response = await fetch("/api/client-portal");
  const payload = await response.json();
  if (!response.ok) return;
  renderClientPortal(payload);
}

async function loadReport(scanId) {
  const response = await fetch(`/api/reports/${scanId}`);
  const payload = await response.json();
  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Report not ready yet.", "neutral");
    return;
  }

  state.activeReport = payload;
  state.activeScanId = scanId;
  document.getElementById("manual-finding-form").classList.remove("hidden");
  renderReport(payload);
}

async function handleAddManualFinding(event) {
  event.preventDefault();
  if (!state.activeScanId) {
    setStatus("dashboard-status", "Select a completed report before adding manual evidence.", "error");
    return;
  }
  const response = await fetch(`/api/scans/${state.activeScanId}/manual-findings`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      title: document.getElementById("manual-title-input").value.trim(),
      severity: document.getElementById("manual-severity-input").value,
      category: document.getElementById("manual-category-input").value.trim(),
      evidence: document.getElementById("manual-evidence-input").value.trim(),
      remediation: document.getElementById("manual-remediation-input").value.trim(),
    }),
  });
  const payload = await response.json();
  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Unable to add manual finding.", "error");
    return;
  }
  document.getElementById("manual-finding-form").reset();
  document.getElementById("manual-severity-input").value = "medium";
  setStatus("dashboard-status", `Manual finding added: ${payload.title}. Report regenerated.`, "success");
  await loadDashboard();
  await loadReport(state.activeScanId);
}

async function refreshScan(scanId) {
  const response = await fetch(`/api/scans/${scanId}/refresh`, { method: "POST", headers: csrfHeaders() });
  const payload = await response.json();

  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Unable to refresh scan.", "error");
    return;
  }

  setStatus(
    "dashboard-status",
    `Scan ${payload.id} refreshed. Current status: ${payload.status}.`,
    "neutral"
  );
  await loadDashboard();
  if (payload.status === "completed") {
    await loadReport(payload.id);
  }
}

function renderDashboard(payload) {
  document.getElementById("dashboard").classList.remove("hidden");
  document.getElementById(
    "dashboard-title"
  ).textContent = `${payload.organization.name} Security Command`;
  const clientOnly = payload.user?.role === "client_viewer";
  document.getElementById("payment-panel").classList.toggle("hidden", payload.user?.role !== "owner");
  document.getElementById("scan-form").classList.toggle("hidden", clientOnly);
  document.getElementById("manual-finding-form").classList.toggle("hidden", clientOnly || !state.activeScanId);
  document.getElementById("client-portal-panel").classList.toggle("hidden", !clientOnly);
  selectAssessmentMode(state.assessmentMode);
  renderProfiles(payload.profiles || []);
  renderCommercialReadiness(payload);
  renderMembers(payload.members || []);
  renderPayments(payload.payments || []);
  renderAudit(payload.audit_events || []);

  const statsGrid = document.getElementById("stats-grid");
  const toolchainGrid = document.getElementById("toolchain-grid");
  if (toolchainGrid) {
    toolchainGrid.innerHTML = (payload.toolchain || [])
      .map(
        (item) => `
          <article class="tool-card">
            <strong>${escapeHtml(item.category)}</strong>
            <div class="meta-line">${escapeHtml((item.tools || []).join(" - "))}</div>
            <p>${escapeHtml(item.purpose)}</p>
          </article>
        `
      )
      .join("");
  }
  const severity = payload.stats.latest_severity_counts || {};
  const cards = [
    ["Authorized Assets", payload.stats.authorized_assets ?? 0],
    ["Total Scans", payload.stats.total_scans ?? 0],
    ["Active Scans", payload.stats.active_scans ?? 0],
    ["Latest Risk Score", payload.stats.latest_risk_score ?? "N/A"],
    ["Critical Findings", severity.critical ?? 0],
    ["High Findings", severity.high ?? 0],
  ];
  statsGrid.innerHTML = cards
    .map(
      ([label, value]) => `
        <article class="stat-card">
          <div class="label">${label}</div>
          <div class="value">${value}</div>
        </article>
      `
    )
    .join("");

  const scanList = document.getElementById("scan-list");
  if (!payload.scans.length) {
    scanList.innerHTML =
      '<div class="check-card">No scans yet. Verify your domain email and launch the first assessment.</div>';
    return;
  }

  scanList.innerHTML = payload.scans
    .map(
      (scan) => `
        <article class="scan-card">
          <header>
            <div>
              <strong>${escapeHtml(scan.target)}</strong>
          <div class="meta-line">
            <span>${escapeHtml(scan.asset_type)}</span>
            <span>${escapeHtml(formatMode(scan.assessment_mode))}</span>
            <span>${escapeHtml(formatTier(scan.scan_tier))}</span>
            <span>${new Date(scan.created_at).toLocaleString()}</span>
          </div>
            </div>
            <span class="pill ${scan.status}">${scan.status}</span>
          </header>
          <div class="meta-line">
            <span>Risk score: ${scan.risk_score ?? "Pending"}</span>
            <span>Manual findings: ${scan.manual_finding_count ?? 0}</span>
            <span>${severityText(scan.severity_counts)}</span>
          </div>
          <div class="scan-progress" aria-label="Scan progress">
            <div class="bar-track">
              <div class="bar-fill" style="width: ${Math.max(5, Number(scan.progress_percent || 0))}%;"></div>
            </div>
            <div class="meta-line">
              <span>${Number(scan.progress_percent || 0)}% complete</span>
              <span>${escapeHtml(scan.progress_message || statusProgressText(scan.status))}</span>
            </div>
          </div>
          <div class="meta-line">
            <span>${escapeHtml(deliveryText(scan))}</span>
          </div>
          <div class="scan-actions">
            <button type="button" onclick="refreshScan(${scan.id})">Refresh</button>
            <button type="button" class="ghost" onclick="loadReport(${scan.id})">View Report</button>
            ${
              scan.report_pdf_available
                ? `<button type="button" class="ghost" onclick="downloadReport(${scan.id})">Download PDF</button>`
                : ""
            }
          </div>
        </article>
      `
    )
    .join("");
}

function renderScannerHealth(payload) {
  const element = document.getElementById("scanner-health-grid");
  if (!element) return;
  const tools = payload.tools || [];
  element.innerHTML = `
    <article class="tool-card">
      <strong>Scanner Health</strong>
      <div class="meta-line">
        <span>${payload.available ?? 0} available</span>
        <span>${payload.missing ?? 0} missing</span>
      </div>
      <p>Install missing tools on the scanner server before relying on full production coverage.</p>
    </article>
    ${tools
      .map(
        (tool) => `
          <article class="tool-card">
            <strong>${escapeHtml(tool.name)}</strong>
            <div class="meta-line">
              <span>${escapeHtml(tool.category)}</span>
              <span class="pill ${tool.available ? "completed" : "warn"}">${tool.available ? "available" : "missing"}</span>
            </div>
            <p>${escapeHtml(tool.resolved_path || tool.configured_path || "Not configured")}</p>
          </article>
        `
      )
      .join("")}
  `;
}

function renderMembers(members) {
  const element = document.getElementById("member-list");
  if (!element) return;
  element.innerHTML = members.length
    ? members
        .map(
          (member) => `
            <article class="readiness-card">
              <strong>${escapeHtml(member.email)}</strong>
              <span class="pill completed">${escapeHtml(member.role)}</span>
              <p>${escapeHtml(member.full_name || "No display name")} - ${member.is_verified ? "verified" : "pending"}</p>
            </article>
          `
        )
        .join("")
    : "";
}

function renderClientPortal(payload) {
  const reportList = document.getElementById("client-report-list");
  const remediationList = document.getElementById("client-remediation-list");
  if (!reportList || !remediationList) return;
  reportList.innerHTML = payload.reports.length
    ? payload.reports
        .map(
          (report) => `
            <article class="scan-card">
              <header>
                <div>
                  <strong>${escapeHtml(report.target)}</strong>
                  <div class="meta-line">
                    <span>${escapeHtml(formatMode(report.assessment_mode))}</span>
                    <span>${escapeHtml(report.risk_band)} risk</span>
                    <span>Score ${report.risk_score}</span>
                  </div>
                </div>
                ${report.pdf_available ? `<button type="button" onclick="downloadReport(${report.scan_id})">PDF</button>` : ""}
              </header>
            </article>
          `
        )
        .join("")
    : `<div class="check-card">No completed reports yet.</div>`;
  remediationList.innerHTML = payload.remediation_queue.length
    ? payload.remediation_queue
        .map(
          (item) => `
            <article class="check-card">
              <div class="meta-line">
                <strong>${escapeHtml(item.title)}</strong>
                <span class="pill ${String(item.priority).toLowerCase()}">${escapeHtml(item.priority)}</span>
              </div>
              <p>${escapeHtml(item.target)}: ${escapeHtml(item.action)}</p>
            </article>
          `
        )
        .join("")
    : `<div class="check-card">No remediation items yet.</div>`;
}

function renderCommercialReadiness(payload) {
  const element = document.getElementById("commercial-readiness");
  if (!element || !payload) return;
  const paymentActive = payload.entitlement?.status === "active";
  element.innerHTML = `
    <article class="readiness-card">
      <strong>Payment</strong>
      <span class="pill ${paymentActive ? "completed" : "warn"}">${paymentActive ? "paid" : "required"}</span>
      <p>${
        paymentActive
            ? `Paid package ${escapeHtml(payload.entitlement.plan)} access is valid until ${new Date(payload.entitlement.expires_at).toLocaleDateString()}.`
            : "Complete a one-time payment before launching full vulnerability scans or ethical pen-testing."
      }</p>
      ${paymentActive ? "" : `<p>Choose one service package. Debit and credit card details stay inside KryptNet checkout.</p>`}
    </article>
  `;
}

function renderPayments(payments) {
  const element = document.getElementById("payment-list");
  if (!element) return;
  element.innerHTML = payments.length
    ? payments
        .map(
          (payment) => `
            <article class="readiness-card">
              <strong>${escapeHtml(payment.plan)} - ${(payment.amount_cents / 100).toLocaleString(undefined, { style: "currency", currency: payment.currency })}</strong>
              <span class="pill completed">${escapeHtml(payment.status)}</span>
              <p>${escapeHtml(payment.payment_method)} - ${escapeHtml(payment.provider_reference)}</p>
            </article>
          `
        )
        .join("")
    : "";
}

function renderProfiles(profiles) {
  const element = document.getElementById("profile-grid");
  if (!element) return;
  element.innerHTML = profiles
    .map(
      (profile) => `
        <article class="profile-card">
          <strong>${escapeHtml(profile.name)}</strong>
          <div class="meta-line">${escapeHtml((profile.categories || []).join(" - "))}</div>
          <p>${escapeHtml(profile.summary)}</p>
        </article>
      `
    )
    .join("");
}

function renderAudit(events) {
  const element = document.getElementById("audit-list");
  if (!element) return;
  element.innerHTML = events.length
    ? events
        .map(
          (event) => `
            <article class="check-card">
              <div class="meta-line">
                <strong>${escapeHtml(event.action)}</strong>
                <span>${new Date(event.created_at).toLocaleString()}</span>
              </div>
              <p>${escapeHtml(JSON.stringify(event.details || {}))}</p>
            </article>
          `
        )
        .join("")
    : `<div class="check-card">No audit events yet.</div>`;
}

function renderReport(report) {
  const riskBand = document.getElementById("report-risk-band");
  riskBand.textContent = `${report.risk_band} Risk`;
  riskBand.className = `risk-band ${String(report.risk_band).toLowerCase()}`;
  const activeScan = state.dashboard?.scans?.find((scan) => scan.id === state.activeScanId);
  document
    .getElementById("report-download-button")
    .classList.toggle("hidden", !activeScan?.report_pdf_available);
  document
    .getElementById("report-email-button")
    .classList.toggle("hidden", !activeScan?.report_pdf_available);
  renderReportCockpit(report, activeScan);

  renderBars("severity-chart", [
    { label: "Critical", value: report.severity_counts.critical, color: "#d94b37" },
    { label: "High", value: report.severity_counts.high, color: "#ff7a45" },
    { label: "Medium", value: report.severity_counts.medium, color: "#efb53d" },
    { label: "Low", value: report.severity_counts.low, color: "#2ab57f" },
    { label: "Info", value: report.severity_counts.info, color: "#2f63ff" },
  ]);
  renderBars(
    "services-chart",
    report.top_services.map((item) => ({ ...item, color: "#2f63ff" }))
  );
  renderBars(
    "categories-chart",
    report.top_categories.map((item) => ({ ...item, color: "#ff7a45" }))
  );
  renderTrend("trend-chart", report.trend);

  document.getElementById("checks-list").innerHTML = report.compliance_checks
    .map(
      (check) => `
        <article class="check-card report-check-card">
          <div class="meta-line">
            <strong>${escapeHtml(check.name)}</strong>
            <span class="pill ${check.status}">${check.status}</span>
          </div>
          <p>${escapeHtml(check.detail)}</p>
        </article>
      `
    )
    .join("");

  document.getElementById("remediation-list").innerHTML = report.remediation_plan
    .map(
      (item, index) => `
        <article class="check-card remediation-card">
          <div class="meta-line">
            <strong><span class="priority-index">${index + 1}</span>${escapeHtml(item.title)}</strong>
            <span class="pill ${item.priority.toLowerCase()}">${escapeHtml(item.priority)}</span>
          </div>
          <p>${escapeHtml(item.action)}</p>
          <small>Owner: ${escapeHtml(item.owner || "Security team")}</small>
        </article>
      `
    )
    .join("");

  document.getElementById("findings-list").innerHTML = report.findings
    .map(
      (finding) => `
        <article class="finding-card">
          <header>
            <div>
              <strong>${escapeHtml(finding.title)}</strong>
              <div class="meta-line">
                <span>${escapeHtml(finding.category)}</span>
                <span>${escapeHtml(finding.host)}</span>
                <span>${escapeHtml(finding.service || "service n/a")}</span>
                <span>${escapeHtml(finding.port || "port n/a")}</span>
              </div>
            </div>
            <span class="pill ${finding.severity}">${escapeHtml(finding.severity)}</span>
          </header>
          <div class="finding-meter" aria-label="Finding severity score">
            <span style="width: ${Math.min(100, Math.max(0, Number(finding.cvss || 0) * 10))}%;"></span>
          </div>
          <div class="meta-line finding-meta">
            <span>CVSS ${Number(finding.cvss || 0).toFixed(1)}</span>
            <span>${escapeHtml(finding.cve || "No CVE supplied")}</span>
          </div>
          <p>${escapeHtml(finding.description)}</p>
          <div class="remediation-note"><strong>Action:</strong> ${escapeHtml(finding.remediation)}</div>
          ${finding.evidence ? `<details><summary>Evidence</summary><pre>${escapeHtml(finding.evidence)}</pre></details>` : ""}
        </article>
      `
    )
    .join("");
}

function renderReportCockpit(report, activeScan) {
  const counts = report.severity_counts || {};
  const totalFindings = ["critical", "high", "medium", "low", "info"].reduce(
    (sum, key) => sum + Number(counts[key] || 0),
    0
  );
  const riskScore = Number(report.risk_score || 0);
  const criticalHigh = Number(counts.critical || 0) + Number(counts.high || 0);
  const riskAngle = Math.max(0, Math.min(100, riskScore)) * 3.6;
  const targetLabel = activeScan?.target || report.findings?.[0]?.host || "Completed assessment";

  document.getElementById("report-target-title").textContent = targetLabel;
  document.getElementById("executive-summary").textContent = report.executive_summary;
  document.getElementById("report-risk-score").textContent = riskScore;
  document.querySelector(".risk-orbit").style.setProperty("--risk-angle", `${riskAngle}deg`);
  document.getElementById("report-scope").textContent =
    report.scope_summary || "Scope details were not supplied for this report.";

  const kpis = [
    ["Risk Score", `${riskScore}/100`, report.risk_band || "N/A"],
    ["Findings", totalFindings, "Total observations"],
    ["Critical + High", criticalHigh, "Immediate focus"],
    ["Report Type", activeScan ? formatMode(activeScan.assessment_mode) : "Assessment", activeScan ? formatTier(activeScan.scan_tier) : "Completed"],
  ];
  document.getElementById("report-kpi-grid").innerHTML = kpis
    .map(
      ([label, value, helper]) => `
        <article class="report-kpi">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(value)}</strong>
          <small>${escapeHtml(helper)}</small>
        </article>
      `
    )
    .join("");

  renderCompactList("report-methodology", report.methodology || report.scan_protocols || []);
  renderCompactList("report-limitations", report.limitations || []);
}

function renderCompactList(elementId, items) {
  const element = document.getElementById(elementId);
  const normalized = (items || []).filter(Boolean).slice(0, 5);
  element.innerHTML = normalized.length
    ? normalized.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
    : "<li>No additional detail supplied.</li>";
}

function renderBars(elementId, items) {
  const element = document.getElementById(elementId);
  const max = Math.max(...items.map((item) => Number(item.value || 0)), 1);
  element.innerHTML = items
    .map((item) => {
      const width = Math.max(8, (Number(item.value || 0) / max) * 100);
      return `
        <div class="bar-row">
          <div class="bar-meta">
            <span>${escapeHtml(item.label)}</span>
            <span>${item.value}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width: ${width}%; background: ${item.color || "#4fd1c5"};"></div>
          </div>
        </div>
      `;
    })
    .join("");
}

function renderTrend(elementId, points) {
  const element = document.getElementById(elementId);
  const values = points.map((point) => Number(point.value || 0));
  const max = Math.max(...values, 1);
  const width = 360;
  const height = 160;
  const padding = 20;
  const step = (width - padding * 2) / Math.max(points.length - 1, 1);

  const polyline = points
    .map((point, index) => {
      const x = padding + step * index;
      const y = height - padding - ((Number(point.value || 0) / max) * (height - padding * 2));
      return `${x},${y}`;
    })
    .join(" ");

  element.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" fill="none" aria-label="Risk trend">
      <path d="M ${padding} ${height - padding} H ${width - padding}" stroke="rgba(20,32,51,0.12)" />
      <polyline points="${polyline}" stroke="#2f63ff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" />
      ${points
        .map((point, index) => {
          const x = padding + step * index;
          const y = height - padding - ((Number(point.value || 0) / max) * (height - padding * 2));
          return `<circle cx="${x}" cy="${y}" r="5" fill="#ff7a45" />`;
        })
        .join("")}
    </svg>
    <div class="trend-labels">
      ${points.map((point) => `<span>${escapeHtml(point.label)}</span>`).join("")}
    </div>
  `;
}

function setStatus(elementId, message, tone = "neutral") {
  const element = document.getElementById(elementId);
  element.textContent = message;
  element.className = `status-card ${tone}`;
  element.classList.remove("hidden");
}

function severityText(counts) {
  if (!counts) {
    return "Report pending";
  }
  return `C:${counts.critical} H:${counts.high} M:${counts.medium} L:${counts.low}`;
}

function deliveryText(scan) {
  if (scan.report_email_sent_at) {
    return `PDF emailed ${new Date(scan.report_email_sent_at).toLocaleString()}`;
  }
  if (scan.report_email_error) {
    return `Email delivery error: ${scan.report_email_error}`;
  }
  if (scan.report_pdf_available) {
    return "PDF ready for download";
  }
  return "PDF pending";
}

function statusProgressText(status) {
  if (status === "queued") return "Queued for scanner worker.";
  if (status === "running") return "Scanner toolchain is running.";
  if (status === "completed") return "Scan complete successfully.";
  if (status === "failed") return "Scan failed. Review the error details.";
  return "Preparing scan.";
}

function formatMode(mode) {
  return mode === "ethical_pentesting" || mode === "authorized_pentest" ? "Ethical Pen-Testing" : "Vulnerability Assessment";
}

function formatTier(tier) {
  return "Full Scan";
}

function downloadReport(scanId) {
  window.location.assign(`/api/reports/${scanId}/pdf`);
}

async function emailReport(scanId) {
  const response = await fetch(`/api/reports/${scanId}/email`, {
    method: "POST",
    headers: csrfHeaders(),
  });
  const payload = await response.json();
  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Unable to email PDF report.", "error");
    return;
  }
  setStatus(
    "dashboard-status",
    payload.report_email_error
      ? `PDF generated, but email delivery failed: ${payload.report_email_error}`
      : "PDF report sent to your verified email address.",
    payload.report_email_error ? "error" : "success"
  );
  await loadDashboard();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

window.refreshScan = refreshScan;
window.loadReport = loadReport;
window.downloadReport = downloadReport;
window.emailReport = emailReport;
