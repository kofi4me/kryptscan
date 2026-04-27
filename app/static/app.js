const state = {
  email: "",
  dashboard: null,
  activeReport: null,
};

document.addEventListener("DOMContentLoaded", () => {
  document
    .getElementById("request-code-form")
    .addEventListener("submit", handleRequestCode);
  document
    .getElementById("verify-code-form")
    .addEventListener("submit", handleVerifyCode);
  document.getElementById("scan-form").addEventListener("submit", handleCreateScan);
  document.getElementById("logout-button").addEventListener("click", handleLogout);
  loadDashboard();
});

async function handleRequestCode(event) {
  event.preventDefault();
  const email = document.getElementById("email-input").value.trim();
  state.email = email;

  const response = await fetch("/api/auth/request-code", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const payload = await response.json();

  if (!response.ok) {
    setStatus("auth-status", payload.detail || "Unable to send verification code.", "error");
    return;
  }

  const isConsoleDelivery = payload.delivery === "console";
  const message = isConsoleDelivery
    ? `Verification code generated for ${payload.email}. Local testing mode is active, so read the code from the server terminal to continue.`
    : `Verification code sent to ${payload.email}. Check your organizational inbox and spam folder.`;
  setStatus("auth-status", message, "success");
}

async function handleVerifyCode(event) {
  event.preventDefault();
  const code = document.getElementById("code-input").value.trim();
  const email = document.getElementById("email-input").value.trim() || state.email;

  const response = await fetch("/api/auth/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, code }),
  });
  const payload = await response.json();

  if (!response.ok) {
    setStatus("auth-status", payload.detail || "Verification failed.", "error");
    return;
  }

  setStatus(
    "auth-status",
    "Email verified. You can now enter an authorized domain name or IP address for assessment.",
    "success"
  );
  await loadDashboard(true);
}

async function handleCreateScan(event) {
  event.preventDefault();
  const target = document.getElementById("target-input").value.trim();

  const response = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  const payload = await response.json();

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
  }

  setStatus(
    "dashboard-status",
    `Assessment created for ${payload.target}. Current status: ${payload.status}.${deliveryNote}`,
    "success"
  );
  document.getElementById("scan-form").reset();
  await loadDashboard(true);
  if (payload.status === "completed") {
    await loadReport(payload.id);
  }
}

async function handleLogout() {
  await fetch("/api/auth/logout", { method: "POST" });
  state.dashboard = null;
  state.activeReport = null;
  document.getElementById("dashboard").classList.add("hidden");
  setStatus("auth-status", "You have been logged out.", "neutral");
}

async function loadDashboard(showStatus = false) {
  const response = await fetch("/api/dashboard");
  if (!response.ok) {
    document.getElementById("dashboard").classList.add("hidden");
    return;
  }

  const payload = await response.json();
  state.dashboard = payload;
  renderDashboard(payload);

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
}

async function loadReport(scanId) {
  const response = await fetch(`/api/reports/${scanId}`);
  const payload = await response.json();
  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Report not ready yet.", "neutral");
    return;
  }

  state.activeReport = payload;
  renderReport(payload);
}

async function refreshScan(scanId) {
  const response = await fetch(`/api/scans/${scanId}/refresh`, { method: "POST" });
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
  const subtitle = document.getElementById("dashboard-subtitle");
  if (subtitle) {
    subtitle.textContent = `${payload.user.email} verified for ${payload.organization.domain}. Enter a domain name or IP address you are authorized to assess.`;
  }

  const statsGrid = document.getElementById("stats-grid");
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
                <span>${new Date(scan.created_at).toLocaleString()}</span>
              </div>
            </div>
            <span class="pill ${scan.status}">${scan.status}</span>
          </header>
          <div class="meta-line">
            <span>Risk score: ${scan.risk_score ?? "Pending"}</span>
            <span>${severityText(scan.severity_counts)}</span>
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

function renderReport(report) {
  const riskBand = document.getElementById("report-risk-band");
  riskBand.textContent = `${report.risk_band} Risk`;
  riskBand.className = `risk-band ${String(report.risk_band).toLowerCase()}`;
  document.getElementById("executive-summary").textContent = report.executive_summary;

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
        <article class="check-card">
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
      (item) => `
        <article class="check-card">
          <div class="meta-line">
            <strong>${escapeHtml(item.title)}</strong>
            <span class="pill ${item.priority.toLowerCase()}">${escapeHtml(item.priority)}</span>
          </div>
          <p>${escapeHtml(item.action)}</p>
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
                <span>${escapeHtml(finding.port || "n/a")}</span>
              </div>
            </div>
            <span class="pill ${finding.severity}">${escapeHtml(finding.severity)}</span>
          </header>
          <div class="meta-line">
            <span>CVSS ${finding.cvss}</span>
            <span>${escapeHtml(finding.cve || "No CVE supplied")}</span>
          </div>
          <p>${escapeHtml(finding.description)}</p>
          <p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>
        </article>
      `
    )
    .join("");
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

function downloadReport(scanId) {
  window.location.assign(`/api/reports/${scanId}/pdf`);
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
