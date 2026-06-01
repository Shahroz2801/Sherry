const tokenKey = "portfolio_auth_token";
const apiBase = window.location.origin === "http://localhost:3000" ? "" : "http://localhost:3000";

const accountStatus = document.querySelector("#accountStatus");
const contactForm = document.querySelector("#contactForm");
const contactMessage = document.querySelector("#contactMessage");
const signOutButton = document.querySelector("#signOutButton");
const adminPanelButton = document.querySelector("#adminPanelButton");
const resendVerificationButton = document.querySelector("#resendVerificationButton");
const contactName = document.querySelector("#contactName");
const contactEmail = document.querySelector("#contactEmail");
const authLinks = document.querySelectorAll(".auth-link");

let currentUser = null;

const api = async (path, options = {}) => {
  const token = localStorage.getItem(tokenKey);
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  let response;

  try {
    response = await fetch(`${apiBase}${path}`, {
      ...options,
      headers
    });
  } catch {
    throw new Error("Cannot reach the backend server. Open http://localhost:3000 and make sure the server is running.");
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `Request failed with status ${response.status}. Open http://localhost:3000 if you are using Live Server.`);
  }

  return data;
};

const setMessage = (element, message, type = "") => {
  element.textContent = message;
  element.className = `form-message ${type}`.trim();
};

const renderAccount = () => {
  const isSignedIn = Boolean(currentUser);
  const isVerified = Boolean(currentUser?.emailVerified);
  const submitButton = contactForm.querySelector("button[type='submit']");

  authLinks.forEach((link) => {
    link.classList.toggle("hidden", isSignedIn);
  });

  adminPanelButton.classList.toggle("hidden", !currentUser?.isAdmin);
  signOutButton.classList.toggle("hidden", !isSignedIn);
  resendVerificationButton.classList.toggle("hidden", !isSignedIn || isVerified);
  submitButton.disabled = !isSignedIn || !isVerified;

  contactName.readOnly = true;
  contactEmail.readOnly = true;

  if (!isSignedIn) {
    accountStatus.textContent = "You are not signed in.";
    contactName.value = "";
    contactEmail.value = "";
    contactName.placeholder = "Sign in to load your name";
    contactEmail.placeholder = "Sign in to load your email";
    return;
  }

  contactName.value = currentUser.name || "";
  contactEmail.value = currentUser.email || "";

  if (isVerified) {
    accountStatus.textContent = `Signed in as ${currentUser.name}. Your email is verified.`;
  } else {
    accountStatus.textContent = `Signed in as ${currentUser.name}. Please verify your email before sending a message.`;
  }
};

const loadCurrentUser = async () => {
  if (!localStorage.getItem(tokenKey)) {
    renderAccount();
    return;
  }

  try {
    const data = await api("/api/auth/me");
    currentUser = data.user;
  } catch {
    localStorage.removeItem(tokenKey);
    currentUser = null;
  }

  renderAccount();
};

signOutButton.addEventListener("click", () => {
  localStorage.removeItem(tokenKey);
  currentUser = null;
  contactForm.reset();
  setMessage(contactMessage, "");
  renderAccount();
});

resendVerificationButton.addEventListener("click", async () => {
  try {
    const data = await api("/api/auth/resend-verification", { method: "POST" });
    setMessage(contactMessage, data.verificationLink ? `${data.message} Dev link: ${data.verificationLink}` : data.message, "success");
  } catch (error) {
    setMessage(contactMessage, error.message, "error");
  }
});

contactForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!currentUser) {
    setMessage(contactMessage, "Please sign in before sending a message.", "error");
    window.location.href = "/login.html?mode=signin";
    return;
  }

  if (!currentUser.emailVerified) {
    setMessage(contactMessage, "Please verify your email before sending a message.", "error");
    return;
  }

  const formData = new FormData(contactForm);
  const payload = Object.fromEntries(formData.entries());

  try {
    const data = await api("/api/contact", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    contactForm.reset();
    if (currentUser) {
      contactName.value = currentUser.name;
      contactEmail.value = currentUser.email;
    }
    setMessage(contactMessage, data.message, "success");
  } catch (error) {
    setMessage(contactMessage, error.message, "error");
  }
});

const handleVerificationFromUrl = async () => {
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token");

  if (!token) {
    return;
  }

  try {
    const data = await api(`/api/auth/verify-email?token=${encodeURIComponent(token)}`);
    setMessage(contactMessage, data.message, "success");
    window.history.replaceState({}, document.title, window.location.pathname + "#contact");
    await loadCurrentUser();
  } catch (error) {
    setMessage(contactMessage, error.message, "error");
  }
};

loadCurrentUser().then(handleVerificationFromUrl);
