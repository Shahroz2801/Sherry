const tokenKey = "portfolio_auth_token";
const isLocalFrontend = ["localhost", "127.0.0.1", ""].includes(window.location.hostname);
const apiBase = isLocalFrontend && window.location.port !== "3000" ? "http://localhost:3000" : "";

const adminStatus = document.querySelector("#adminStatus");
const usersTable = document.querySelector("#usersTable");
const messageList = document.querySelector("#messageList");
const signOutButton = document.querySelector("#adminSignOutButton");

const api = async (path) => {
  const token = localStorage.getItem(tokenKey);

  let response;

  try {
    response = await fetch(`${apiBase}${path}`, {
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      }
    });
  } catch {
    throw new Error("Cannot reach the backend server. If you are testing locally, open http://localhost:3000/admin.html and make sure the server is running.");
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `Admin request failed with status ${response.status}.`);
  }

  return data;
};

const formatDate = (value) => {
  if (!value) {
    return "Never";
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
};

const escapeHtml = (value) => {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

const renderSummary = (summary) => {
  document.querySelector("#totalUsers").textContent = summary.totalUsers;
  document.querySelector("#loggedInUsers").textContent = summary.loggedInUsers;
  document.querySelector("#verifiedUsers").textContent = summary.verifiedUsers;
  document.querySelector("#totalMessages").textContent = summary.totalMessages;
};

const renderUsers = (users) => {
  if (!users.length) {
    usersTable.innerHTML = `<tr><td colspan="7">No users registered yet.</td></tr>`;
    return;
  }

  usersTable.innerHTML = users.map((user) => `
    <tr>
      <td>${escapeHtml(user.name)}</td>
      <td>${escapeHtml(user.email)}</td>
      <td>${escapeHtml(user.phone || "Not added")}</td>
      <td>
        <div class="user-detail-lines">
          <span>${escapeHtml(user.gender || "Gender not added")}</span>
          <span>${escapeHtml(user.city || "City not added")}</span>
          <span>${escapeHtml(user.occupation || "Occupation not added")}</span>
        </div>
      </td>
      <td><span class="status-pill ${user.emailVerified ? "ok" : "wait"}">${user.emailVerified ? "Yes" : "No"}</span></td>
      <td>${formatDate(user.lastLoginAt)}</td>
      <td>${Number(user.messageCount || 0)}</td>
    </tr>
  `).join("");
};

const renderMessages = (messages) => {
  if (!messages.length) {
    messageList.innerHTML = `<article class="empty-state">No contact messages yet.</article>`;
    return;
  }

  messageList.innerHTML = messages.map((item) => `
    <article class="message-card">
      <div class="message-card-head">
        <div>
          <h3>${escapeHtml(item.subject)}</h3>
          <p>${escapeHtml(item.name)} &lt;${escapeHtml(item.email)}&gt;</p>
        </div>
        <time>${formatDate(item.createdAt)}</time>
      </div>
      <p class="message-text">${escapeHtml(item.message)}</p>
      <p class="message-meta">Account: ${escapeHtml(item.accountName)} (${escapeHtml(item.accountEmail)})</p>
    </article>
  `).join("");
};

const loadAdminPanel = async () => {
  try {
    const me = await api("/api/auth/me");

    if (!me.user.isAdmin) {
      localStorage.removeItem(tokenKey);
      window.location.replace("/#contact");
      return;
    }

    adminStatus.textContent = `Signed in as ${me.user.name}.`;

    const [summaryData, usersData, messagesData] = await Promise.all([
      api("/api/admin/summary"),
      api("/api/admin/users"),
      api("/api/admin/messages")
    ]);

    renderSummary(summaryData.summary);
    renderUsers(usersData.users);
    renderMessages(messagesData.messages);
  } catch (error) {
    adminStatus.textContent = error.message;
    localStorage.removeItem(tokenKey);
    setTimeout(() => window.location.replace("/#contact"), 1200);
  }
};

signOutButton.addEventListener("click", () => {
  localStorage.removeItem(tokenKey);
  window.location.replace("/");
});

loadAdminPanel();
