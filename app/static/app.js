const state = {
  email: "",
  dashboard: null,
  activeReport: null,
  activeScanId: null,
  assessmentMode: "vulnerability_assessment",
  scanTier: "full_scan",
  reportIntakeEnabled: false,
  refreshTimer: null,
  verificationTimer: null,
  verificationExpiresAt: null,
};

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-auth-mode]").forEach((button) => {
    button.addEventListener("click", () => openAuthModal(button.dataset.authMode || "signup"));
  });
  document.querySelectorAll("[data-auth-close]").forEach((button) => {
    button.addEventListener("click", closeAuthModal);
  });
  document.getElementById("auth-close-button")?.addEventListener("click", closeAuthModal);
  document.getElementById("switch-to-signin-button")?.addEventListener("click", () => openAuthModal("signin"));
  document.getElementById("switch-to-signup-button")?.addEventListener("click", () => openAuthModal("signup"));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeAuthModal();
  });
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
  document.getElementById("report-intake-toggle-button").addEventListener("click", toggleReportIntake);
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

function fieldLabel(path) {
  const field = String(path || "").split(".").pop();
  const labels = {
    company_address: "Company address",
    company_name: "Company",
    confirm_password: "Confirm password",
    data_protection_accepted: "Data protection agreement",
    date_of_birth: "Date of birth",
    email: "Email",
    full_name: "Full name",
    job_title: "Title",
    password: "Password",
    phone_number: "Phone number",
    professional_role: "Role",
    safe_use_accepted: "Authorized testing confirmation",
    testing_reason: "Reason for testing",
  };
  return labels[field] || field.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatApiError(payload, fallback) {
  const detail = payload?.detail;
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === "string") return item;
        const location = Array.isArray(item.loc) ? item.loc.filter((part) => part !== "body").join(".") : "";
        const label = fieldLabel(location);
        const message = item.msg || "is invalid";
        return label ? `${label}: ${message}.` : `${message}.`;
      })
      .join(" ");
  }
  if (typeof detail === "object") {
    return detail.message || detail.error || fallback;
  }
  return String(detail);
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
  if (sectionId !== "landing-page") closeAuthModal();
  ["landing-page", "verification-page", "password-reset-page", "tool-choice-page", "dashboard"].forEach((id) => {
    const element = document.getElementById(id);
    if (element) element.classList.toggle("hidden", id !== sectionId);
  });
}

function openAuthModal(mode = "signup") {
  const modal = document.getElementById("auth-modal");
  const signupPanel = document.getElementById("signup-panel");
  const signinPanel = document.getElementById("signin-panel");
  if (!modal || !signupPanel || !signinPanel) return;

  const signinMode = mode === "signin";
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");
  signupPanel.classList.toggle("hidden", signinMode);
  signinPanel.classList.toggle("hidden", !signinMode);
  setStatus("auth-status", signinMode ? "Sign in to continue to your KryptScan workspace." : "Create an account to start authorized security testing.", "neutral");

  const firstInput = signinMode
    ? document.getElementById("login-email-input")
    : document.getElementById("register-name-input");
  window.setTimeout(() => firstInput?.focus(), 50);
}

function closeAuthModal() {
  const modal = document.getElementById("auth-modal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
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
  const required = Boolean(state.reportIntakeEnabled);
  panel.classList.toggle("hidden", !state.reportIntakeEnabled);
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
  const toggle = document.getElementById("report-intake-toggle-button");
  if (toggle) {
    toggle.textContent = state.reportIntakeEnabled ? "Hide Report Details" : "Submit Report";
    toggle.classList.toggle("active", state.reportIntakeEnabled);
  }
}

function toggleReportIntake() {
  state.reportIntakeEnabled = !state.reportIntakeEnabled;
  updateReportIntakeVisibility();
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
    setStatus("dashboard-status", formatApiError(payload, "Unable to prepare checkout."), "error");
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
    setStatus("auth-status", formatApiError(payload, "Unable to send verification code."), "error");
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
    setStatus("verify-status", formatApiError(payload, "Unable to resend verification code."), "error");
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
  const testingReason = document.getElementById("register-reason-input").value.trim();
  state.email = email;
  if (password !== confirmPassword) {
    setStatus("auth-status", "Passwords do not match.", "error");
    setButtonBusy("registration-submit-button", false);
    return;
  }
  if (testingReason.length < 10) {
    setStatus("auth-status", "Reason for testing must be at least 10 characters. Example: Company routine security testing.", "error");
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
        testing_reason: testingReason,
        data_protection_accepted: document.getElementById("register-data-protection-input").checked,
        safe_use_accepted: document.getElementById("register-safe-use-input").checked,
      }),
    });
    if (!response.ok) {
      setStatus("auth-status", formatApiError(payload, "Unable to complete registration."), "error");
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
      const detail = formatApiError(payload, "Unable to log in.");
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
    setStatus("verify-status", formatApiError(payload, "Verification failed."), "error");
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
    setStatus("registration-status", formatApiError(payload, "Unable to complete registration."), "error");
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
    setStatus("password-reset-status", formatApiError(payload, "Unable to send reset code."), "error");
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
    setStatus("password-reset-status", formatApiError(payload, "Unable to reset password."), "error");
    return;
  }
  setStatus("password-reset-status", "Password reset successful. Choose a testing option to continue.", "success");
  await loadDashboard(false, { showChoiceWhenAuthenticated: true });
}

async function handleCreateScan(event) {
  event.preventDefault();
  setButtonBusy("scan-submit-button", true, "Launching...");
  setStatus("dashboard-status", "Preparing scan request and contacting the scanner service...", "neutral");
  const target = document.getElementById("target-input").value.trim();
  if (!target) {
    setStatus("dashboard-status", "Enter a domain name or IP address before launching the assessment.", "error");
    setButtonBusy("scan-submit-button", false);
    return;
  }
  const assessment_mode = document.getElementById("assessment-mode-input").value;
  const scan_tier = "full_scan";
  const targetAuthorizationAccepted = document.getElementById("target-authorization-input").checked;
  if (!targetAuthorizationAccepted) {
    setStatus("dashboard-status", "Confirm target ownership or written authorization before launching the assessment.", "error");
    setButtonBusy("scan-submit-button", false);
    return;
  }
  const body = {
    target,
    assessment_mode,
    scan_tier,
    target_authorization_accepted: targetAuthorizationAccepted,
  };
  if (state.reportIntakeEnabled) {
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
    body.api_base_url = document.getElementById("api-base-url-input").value.trim() || null;
    body.authenticated_testing_allowed = document.getElementById("authenticated-testing-input").checked;
    body.test_account_username = document.getElementById("test-account-username-input").value.trim() || null;
    body.test_account_role = document.getElementById("test-account-role-input").value.trim() || null;
    body.access_notes = document.getElementById("access-notes-input").value.trim() || null;
    body.out_of_scope = document.getElementById("out-of-scope-input").value.trim() || null;
    body.critical_workflows = document.getElementById("critical-workflows-input").value.trim() || null;
    body.emergency_stop = document.getElementById("emergency-stop-input").value.trim() || null;
  }

  try {
    const { response, payload } = await fetchJson("/api/scans", {
      method: "POST",
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      setStatus("dashboard-status", formatApiError(payload, "Unable to launch assessment."), "error");
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
    state.activeScanId = payload.id;
    selectAssessmentMode(state.assessmentMode);
    selectScanTier("full_scan", { silent: true });
    await loadDashboard(false);
    setStatus(
      "dashboard-status",
      `${formatMode(payload.assessment_mode)} created for ${payload.target}. Current status: ${payload.status}.${deliveryNote}`,
      "success"
    );
    if (payload.status === "completed") {
      await loadReport(payload.id);
    }
  } catch (error) {
    setStatus(
      "dashboard-status",
      `Unable to contact the scanning API. Refresh the page and try again. Technical detail: ${error.message || error}`,
      "error"
    );
  } finally {
    setButtonBusy("scan-submit-button", false);
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
    setStatus("dashboard-status", formatApiError(payload, "Report not ready yet."), "neutral");
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
    setStatus("dashboard-status", formatApiError(payload, "Unable to add manual finding."), "error");
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
    setStatus("dashboard-status", formatApiError(payload, "Unable to refresh scan."), "error");
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
  const paymentRequired = Boolean(payload.stats?.payment_required && !payload.stats?.payment_demo_mode);
  document.getElementById("payment-panel").classList.toggle("hidden", payload.user?.role !== "owner" || !paymentRequired);
  document.getElementById("scan-form").classList.toggle("hidden", clientOnly);
  document.getElementById("manual-finding-form").classList.toggle("hidden", clientOnly || !state.activeScanId);
  document.getElementById("client-portal-panel").classList.toggle("hidden", !clientOnly);
  selectAssessmentMode(state.assessmentMode);
  renderProfiles(payload.profiles || []);
  renderCommercialReadiness(payload);
  renderMembers([]);
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
    ["Current Scans", payload.stats.total_scans ?? 0],
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
      '<div class="check-card">No active scan is stored. Launch an assessment, review the result, then email or download the PDF before starting another test.</div>';
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
            <div class="scan-stage-line">
              <strong>${escapeHtml(stageLabel(scan.progress_percent, scan.status))}</strong>
              <span>${escapeHtml(scan.status)}</span>
            </div>
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
  const sourceText = payload.worker_connected
    ? "Worker scanner connected. Availability is read from the scanner server."
    : "Scanner worker is not reachable from the web app. Restart or rebuild the worker before production scans.";
  element.innerHTML = `
    <article class="tool-card scanner-health-card">
      <strong>Scanner Health</strong>
      <div class="meta-line">
        <span>${payload.available ?? 0} available</span>
        <span>${payload.missing ?? 0} missing</span>
        <span>${payload.optional_pending ?? 0} setup needed</span>
      </div>
      <p>${escapeHtml(sourceText)}</p>
    </article>
    ${tools
      .map(
        (tool) => {
          const statusLabel = tool.available ? "available" : tool.optional ? "setup needed" : "missing";
          const statusClass = tool.available ? "completed" : tool.optional ? "setup-needed" : "warn";
          return `
          <article class="tool-card">
            <strong>${escapeHtml(tool.name)}</strong>
            <div class="meta-line">
              <span>${escapeHtml(tool.category)}</span>
              <span class="pill ${statusClass}">${statusLabel}</span>
            </div>
            <p>${escapeHtml(tool.resolved_path || tool.configured_path || "Not configured")}</p>
          </article>
        `;
        }
      )
      .join("")}
  `;
}

function stageLabel(percent, status) {
  const value = Number(percent || 0);
  if (status === "completed") return "Report complete";
  if (status === "failed") return "Attention required";
  if (value < 15) return "Scope validation";
  if (value < 28) return "DNS and recon";
  if (value < 42) return "Network discovery";
  if (value < 56) return "TLS and web posture";
  if (value < 70) return "Web/API crawling";
  if (value < 82) return "Vulnerability correlation";
  if (value < 92) return "AI triage and prioritization";
  return "Report generation";
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
  if (!payload.stats?.payment_required) {
    element.innerHTML = "";
    return;
  }
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

  renderSeverityCockpit("severity-chart", [
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
      ([label, value, helper], index) => `
        <article class="report-kpi report-kpi-${index + 1}">
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

function renderSeverityCockpit(elementId, items) {
  const element = document.getElementById(elementId);
  const total = items.reduce((sum, item) => sum + Number(item.value || 0), 0);
  let cursor = 0;
  const segments = items
    .map((item) => {
      const value = Number(item.value || 0);
      const start = total ? (cursor / total) * 100 : 0;
      cursor += value;
      const end = total ? (cursor / total) * 100 : 0;
      return `${item.color} ${start}% ${end}%`;
    })
    .filter(Boolean)
    .join(", ");
  const conic = total ? segments : "rgba(148, 163, 184, 0.28) 0% 100%";
  element.innerHTML = `
    <div class="severity-cockpit">
      <div class="severity-donut" style="background: conic-gradient(${conic});">
        <div>
          <strong>${total}</strong>
          <span>findings</span>
        </div>
      </div>
      <div class="severity-ledger">
        ${items
          .map(
            (item) => `
              <div class="severity-row">
                <span><i style="background:${item.color};"></i>${escapeHtml(item.label)}</span>
                <strong>${Number(item.value || 0)}</strong>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderBars(elementId, items) {
  const element = document.getElementById(elementId);
  const max = Math.max(...items.map((item) => Number(item.value || 0)), 1);
  element.innerHTML = items
    .map((item, index) => {
      const width = Math.max(8, (Number(item.value || 0) / max) * 100);
      const value = Number(item.value || 0);
      return `
        <div class="bar-row chart-metric-row">
          <div class="bar-meta">
            <span><i style="background:${item.color || "#4fd1c5"};"></i>${escapeHtml(item.label)}</span>
            <strong>${value}</strong>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width: ${width}%; --bar-color: ${item.color || "#4fd1c5"}; --bar-delay: ${index * 80}ms;"></div>
          </div>
        </div>
      `;
    })
    .join("");
}

function renderTrend(elementId, points) {
  const element = document.getElementById(elementId);
  if (!points || !points.length) {
    element.innerHTML = `<div class="empty-chart">Trend data appears after multiple completed assessments.</div>`;
    return;
  }
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
  const areaPath = polyline ? `M ${polyline.split(" ")[0]} L ${polyline} L ${width - padding},${height - padding} L ${padding},${height - padding} Z` : "";

  element.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" fill="none" aria-label="Risk trend">
      <defs>
        <linearGradient id="riskTrendFill" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stop-color="rgba(239,68,68,0.52)" />
          <stop offset="48%" stop-color="rgba(37,99,235,0.22)" />
          <stop offset="100%" stop-color="rgba(20,184,166,0.04)" />
        </linearGradient>
        <filter id="riskTrendGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <rect x="0" y="0" width="${width}" height="${height}" rx="18" fill="rgba(3,7,18,0.42)" />
      <path d="M ${padding} ${padding} H ${width - padding}" stroke="rgba(168,196,255,0.14)" />
      <path d="M ${padding} ${height / 2} H ${width - padding}" stroke="rgba(168,196,255,0.14)" />
      <path d="M ${padding} ${height - padding} H ${width - padding}" stroke="rgba(168,196,255,0.2)" />
      ${areaPath ? `<path d="${areaPath}" fill="url(#riskTrendFill)" />` : ""}
      <polyline points="${polyline}" stroke="#60a5fa" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" filter="url(#riskTrendGlow)" />
      ${points
        .map((point, index) => {
          const x = padding + step * index;
          const y = height - padding - ((Number(point.value || 0) / max) * (height - padding * 2));
          return `<circle cx="${x}" cy="${y}" r="6" fill="#f97316" stroke="#020617" stroke-width="3" />`;
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
    setStatus("dashboard-status", formatApiError(payload, "Unable to email PDF report."), "error");
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
