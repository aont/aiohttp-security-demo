let token = null;

const output = document.getElementById("output");
const status = document.getElementById("status");

function setOutput(obj) {
  output.textContent = JSON.stringify(obj, null, 2);
}

function authHeaders() {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function login() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  const data = await res.json();
  setOutput(data);

  if (res.ok) {
    token = data.token;
    status.textContent = `Authenticated as ${data.user.username}`;
  } else {
    token = null;
    status.textContent = "Authentication failed";
  }
}

async function me() {
  const res = await fetch("/api/me", { headers: { ...authHeaders() } });
  const data = await res.json();
  setOutput(data);
  status.textContent = res.ok ? `Token valid for ${data.username}` : "Unauthorized";
}

async function logout() {
  const res = await fetch("/api/logout", {
    method: "POST",
    headers: { ...authHeaders() },
  });
  const data = await res.json();
  setOutput(data);

  if (res.ok) {
    token = null;
    status.textContent = "Logged out";
  } else {
    status.textContent = "Logout failed";
  }
}

document.getElementById("loginBtn").addEventListener("click", login);
document.getElementById("meBtn").addEventListener("click", me);
document.getElementById("logoutBtn").addEventListener("click", logout);
