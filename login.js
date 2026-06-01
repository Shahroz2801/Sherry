const tokenKey = "portfolio_auth_token";
const apiBase = window.location.origin === "http://localhost:3000" ? "" : "http://localhost:3000";
const siteBase = apiBase || "";

const authMessage = document.querySelector("#authMessage");
const signinPane = document.querySelector("#signinPane");
const signupPane = document.querySelector("#signupPane");
const resendPendingVerification = document.querySelector("#resendPendingVerification");
const verificationCodeForm = document.querySelector("#verificationCodeForm");

let pendingVerificationEmail = "";

const api = async (path, options = {}) => {
  let response;

  try {
    response = await fetch(`${apiBase}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    });
  } catch {
    throw new Error("Cannot reach the backend server. Open http://localhost:3000/login.html and make sure the server is running.");
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(data.error || `Request failed with status ${response.status}. Open http://localhost:3000/login.html if you are using Live Server.`);
    Object.assign(error, data);
    throw error;
  }

  return data;
};

const setMessage = (message, type = "") => {
  authMessage.textContent = message;
  authMessage.className = `form-message ${type}`.trim();
};

const showPendingVerification = (data) => {
  pendingVerificationEmail = data.email || pendingVerificationEmail;
  resendPendingVerification.classList.toggle("hidden", !pendingVerificationEmail);
  verificationCodeForm.classList.toggle("hidden", !pendingVerificationEmail);

  const parts = [data.message];

  if (data.emailError) {
    parts.push(`SMTP error: ${data.emailError}`);
  }

  if (data.verificationCode) {
    parts.push(`Code: ${data.verificationCode}`);
  }

  if (data.verificationLink) {
    parts.push(`Dev link: ${data.verificationLink}`);
  }

  setMessage(parts.join(" "), data.needsEmailSetup ? "error" : "success");
};

const switchAuthTab = (mode) => {
  document.querySelectorAll("[data-auth-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.authTab === mode);
  });

  signinPane.classList.toggle("active", mode === "signin");
  signupPane.classList.toggle("active", mode === "signup");
  resendPendingVerification.classList.add("hidden");
  verificationCodeForm.classList.add("hidden");
  setMessage("");
};

const finishAuth = (data, message) => {
  localStorage.setItem(tokenKey, data.token);

  if (data.user?.isAdmin) {
    window.location.href = `${siteBase}/admin.html`;
    return;
  }

  if (message) {
    setMessage(message, "success");
  }

  window.setTimeout(() => {
    window.location.href = `${siteBase}/#contact`;
  }, message ? 1200 : 0);
};

document.querySelectorAll("[data-auth-tab]").forEach((button) => {
  button.addEventListener("click", () => switchAuthTab(button.dataset.authTab));
});

signinPane.addEventListener("submit", async (event) => {
  event.preventDefault();

  const email = document.querySelector("#signinEmail").value.trim();
  const password = document.querySelector("#signinPassword").value;

  try {
    const data = await api("/api/auth/signin", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    finishAuth(data);
  } catch (error) {
    if (error.pendingVerification) {
      showPendingVerification(error);
      return;
    }

    setMessage(error.message, "error");
  }
});

signupPane.addEventListener("submit", async (event) => {
  event.preventDefault();

  const name = document.querySelector("#signupName").value.trim();
  const email = document.querySelector("#signupEmail").value.trim();
  const phone = document.querySelector("#signupPhone").value.trim();
  const gender = document.querySelector("#signupGender").value;
  const city = document.querySelector("#signupCity").value.trim();
  const occupation = document.querySelector("#signupOccupation").value.trim();
  const password = document.querySelector("#signupPassword").value;

  try {
    const data = await api("/api/auth/signup", {
      method: "POST",
      body: JSON.stringify({ name, email, phone, gender, city, occupation, password })
    });

    switchAuthTab("signin");
    document.querySelector("#signinEmail").value = email;
    showPendingVerification(data);
  } catch (error) {
    if (error.pendingVerification) {
      switchAuthTab("signin");
      document.querySelector("#signinEmail").value = email;
      showPendingVerification(error);
      return;
    }

    setMessage(error.message, "error");
  }
});

resendPendingVerification.addEventListener("click", async () => {
  const email = pendingVerificationEmail || document.querySelector("#signinEmail").value.trim() || document.querySelector("#signupEmail").value.trim();

  if (!email) {
    setMessage("Enter your email first, then resend verification.", "error");
    return;
  }

  try {
    const data = await api("/api/auth/resend-verification-public", {
      method: "POST",
      body: JSON.stringify({ email })
    });

    pendingVerificationEmail = email;
    showPendingVerification(data);
  } catch (error) {
    setMessage(error.message, "error");
  }
});

verificationCodeForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const code = document.querySelector("#verificationCode").value.trim();
  const email = pendingVerificationEmail || document.querySelector("#signinEmail").value.trim();

  try {
    const data = await api("/api/auth/verify-code", {
      method: "POST",
      body: JSON.stringify({ email, code })
    });

    verificationCodeForm.classList.add("hidden");
    resendPendingVerification.classList.add("hidden");
    setMessage(data.message, "success");
  } catch (error) {
    setMessage(error.message, "error");
  }
});

const params = new URLSearchParams(window.location.search);
switchAuthTab(params.get("mode") === "signup" ? "signup" : "signin");
