const adminState = {
  user: null,
};

document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("admin-login-form").addEventListener("submit", handleAdminLogin);
  document.getElementById("admin-refresh-button").addEventListener("click", loadAdminDashboard);
  document.getElementById("admin-logout-button").addEventListener("click", handleAdminLogout);
  await ensureCsrfCookie();
  await loadAdminSession();
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

function setStatus(message, tone = "neutral") {
  const status = document.getElementById("admin-status");
  status.textContent = message || "";
  status.dataset.tone = tone;
}

function setBusy(buttonId, busy, label) {
  const button = document.getElementById(buttonId);
  if (!button) return;
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = label;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
  }
}

function showDashboard(show) {
  document.getElementById("admin-login-panel").classList.toggle("is-hidden", show);
  document.getElementById("admin-dashboard").classList.toggle("is-hidden", !show);
}

async function handleAdminLogin(event) {
  event.preventDefault();
  setBusy("admin-login-button", true, "Checking...");
  setStatus("");
  const email = document.getElementById("admin-email-input").value.trim();
  const password = document.getElementById("admin-password-input").value;
  const { response, payload } = await fetchJson("/api/admin/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  setBusy("admin-login-button", false);
  if (!response.ok) {
    setStatus(payload.detail || "Admin login failed.", "error");
    return;
  }
  adminState.user = payload.user;
  await loadAdminDashboard();
}

async function loadAdminSession() {
  const { response, payload } = await fetchJson("/api/admin/me", { method: "GET" });
  if (!response.ok) {
    showDashboard(false);
    return;
  }
  adminState.user = payload.user;
  await loadAdminDashboard();
}

async function loadAdminDashboard() {
  setBusy("admin-refresh-button", true, "Refreshing...");
  const [overviewResult, usersResult, scansResult, eventsResult] = await Promise.all([
    fetchJson("/api/admin/security-overview", { method: "GET" }),
    fetchJson("/api/admin/users", { method: "GET" }),
    fetchJson("/api/admin/scans", { method: "GET" }),
    fetchJson("/api/admin/audit-events", { method: "GET" }),
  ]);
  setBusy("admin-refresh-button", false);
  if (!overviewResult.response.ok) {
    setStatus(overviewResult.payload.detail || "Admin session expired.", "error");
    showDashboard(false);
    return;
  }
  showDashboard(true);
  document.getElementById("admin-user-label").textContent = `Signed in as ${adminState.user?.email || "admin"}`;
  renderSummary(overviewResult.payload);
  renderUsers(usersResult.payload.users || []);
  renderScans(scansResult.payload.scans || []);
  renderEvents(eventsResult.payload.events || overviewResult.payload.recent_events || []);
}

async function handleAdminLogout() {
  await fetch("/api/auth/logout", { method: "POST", headers: csrfHeaders() });
  adminState.user = null;
  showDashboard(false);
  setStatus("Logged out.", "neutral");
}

function renderSummary(overview) {
  const cards = [
    ["Total Users", overview.users?.total_users],
    ["Verified Users", overview.users?.verified_users],
    ["Pending Users", overview.users?.pending_users],
    ["Locked Accounts", overview.users?.locked_accounts],
    ["Failed Logins 24h", overview.auth?.failed_logins_24h],
    ["Active Scans", overview.scans?.active_scans],
    ["Completed Scans", overview.scans?.completed_scans],
    ["Failed Scans", overview.scans?.failed_scans],
    ["Average Risk", overview.scans?.average_risk_score],
    ["Reports Emailed", overview.auth?.reports_emailed],
  ];
  document.getElementById("admin-summary-grid").innerHTML = cards
    .map(([label, value]) => `
      <article class="admin-summary-card">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(value ?? 0)}</strong>
      </article>
    `)
    .join("");
}

function renderUsers(users) {
  const body = document.getElementById("admin-users-table");
  if (!users.length) {
    body.innerHTML = `<tr><td colspan="7">No users found.</td></tr>`;
    return;
  }
  body.innerHTML = users.map((user) => `
    <tr>
      <td>${escapeHtml(user.email)}</td>
      <td>${escapeHtml(user.full_name || "Not completed")}</td>
      <td>${escapeHtml(user.company_name || user.organization_name || user.email_domain || "-")}</td>
      <td><span class="admin-pill">${escapeHtml(user.role)}</span></td>
      <td>${user.is_verified ? "Verified" : "Pending"}${user.locked_until ? " / Locked" : ""}</td>
      <td>${escapeHtml(user.scan_count ?? 0)}</td>
      <td>${formatDate(user.last_login_at)}</td>
    </tr>
  `).join("");
}

function renderScans(scans) {
  const body = document.getElementById("admin-scans-table");
  if (!scans.length) {
    body.innerHTML = `<tr><td colspan="7">No scans found.</td></tr>`;
    return;
  }
  body.innerHTML = scans.map((scan) => `
    <tr>
      <td>${escapeHtml(scan.target)} <span class="admin-muted">${escapeHtml(scan.asset_type || "")}</span></td>
      <td>${escapeHtml(scan.requested_by_email || "-")}</td>
      <td>${escapeHtml(labelMode(scan.assessment_mode))}</td>
      <td><span class="admin-pill ${scan.status === "failed" ? "danger" : ""}">${escapeHtml(scan.status)}</span></td>
      <td>
        <div class="admin-progress" aria-label="${escapeHtml(scan.progress_percent ?? 0)} percent complete">
          <span style="width: ${Math.max(0, Math.min(100, Number(scan.progress_percent) || 0))}%"></span>
        </div>
        <small>${escapeHtml(scan.progress_message || scan.error_message || `${scan.progress_percent || 0}%`)}</small>
      </td>
      <td>${formatDate(scan.started_at || scan.created_at)}</td>
      <td>${formatDate(scan.completed_at)}</td>
    </tr>
  `).join("");
}

function renderEvents(events) {
  const body = document.getElementById("admin-events-table");
  if (!events.length) {
    body.innerHTML = `<tr><td colspan="5">No audit events yet.</td></tr>`;
    return;
  }
  body.innerHTML = events.map((event) => `
    <tr>
      <td>${formatDate(event.created_at)}</td>
      <td>${escapeHtml(event.actor_email || "System")}</td>
      <td>${escapeHtml(event.organization_name || "-")}</td>
      <td><span class="admin-pill ${event.action.includes("failed") ? "danger" : ""}">${escapeHtml(event.action)}</span></td>
      <td>${escapeHtml(compactDetails(event.details))}</td>
    </tr>
  `).join("");
}

function labelMode(value) {
  return String(value || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function compactDetails(details) {
  if (!details || typeof details !== "object") return "-";
  const entries = Object.entries(details)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .slice(0, 4)
    .map(([key, value]) => `${key}: ${String(value)}`);
  return entries.join("; ") || "-";
}

function formatDate(value) {
  if (!value) return "-";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toLocaleString();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
