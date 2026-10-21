function getPublicCookie(name) {
  return document.cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${name}=`))
    ?.split("=")
    .slice(1)
    .join("=") || "";
}

function publicCsrfHeaders() {
  const token = decodeURIComponent(getPublicCookie("kryptnet_csrf"));
  return token ? { "X-CSRF-Token": token } : {};
}

async function ensurePublicCsrfCookie() {
  if (getPublicCookie("kryptnet_csrf")) return;
  await fetch("/", { method: "GET", cache: "no-store" });
}

function showPublicPricingStatus(message, tone = "neutral") {
  const status = document.getElementById("public-pricing-status");
  if (!status) return;
  status.textContent = message;
  status.className = `status-card ${tone}`;
}

function publicApiError(payload, fallback) {
  if (typeof payload?.detail === "string") return payload.detail;
  return fallback;
}

async function selectPublicPlan(button) {
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = "Preparing Checkout...";
  showPublicPricingStatus("Connecting securely to Authorize.Net.");

  try {
    await ensurePublicCsrfCookie();
    const response = await fetch("/api/payments/checkout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...publicCsrfHeaders(),
      },
      body: JSON.stringify({ plan: button.dataset.publicPlan }),
    });
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401) {
      window.location.assign("/?auth=signin");
      return;
    }
    if (!response.ok) {
      showPublicPricingStatus(
        publicApiError(payload, "Unable to prepare the secure payment page."),
        "error"
      );
      return;
    }
    if (!payload.checkout_url || !payload.checkout_token) {
      showPublicPricingStatus("Authorize.Net did not return a secure checkout session.", "error");
      return;
    }

    const form = document.createElement("form");
    form.method = "POST";
    form.action = payload.checkout_url;
    const token = document.createElement("input");
    token.type = "hidden";
    token.name = "token";
    token.value = payload.checkout_token;
    form.appendChild(token);
    document.body.appendChild(form);
    form.submit();
  } catch (_error) {
    showPublicPricingStatus("Unable to contact the secure checkout service. Please try again.", "error");
  } finally {
    button.disabled = false;
    button.textContent = originalText;
  }
}

async function signOutFromPublicPage(button) {
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = "Signing Out...";
  try {
    await ensurePublicCsrfCookie();
    const response = await fetch("/api/auth/logout", {
      method: "POST",
      headers: publicCsrfHeaders(),
    });
    if (!response.ok) throw new Error("logout failed");
    window.location.assign("/");
  } catch (_error) {
    button.disabled = false;
    button.textContent = originalText;
    showPublicPricingStatus("Unable to sign out. Please refresh and try again.", "error");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-public-plan]").forEach((button) => {
    button.addEventListener("click", () => selectPublicPlan(button));
  });
  const logoutButton = document.getElementById("public-logout-button");
  logoutButton?.addEventListener("click", () => signOutFromPublicPage(logoutButton));
});
