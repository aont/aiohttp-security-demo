const output = document.getElementById('output');
const loginForm = document.getElementById('login-form');
const checkSessionBtn = document.getElementById('check-session');
const loadUsersBtn = document.getElementById('load-users');
const logoutBtn = document.getElementById('logout');
const demoUsersEl = document.getElementById('demo-users');

function setOutput(data) {
  output.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  });

  const data = await response.json().catch(() => ({ error: 'Invalid JSON response' }));

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }

  return data;
}

async function loginWithCredential(username, password) {
  const data = await requestJson('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  setOutput(data);
}

async function loadDemoUsers() {
  try {
    const data = await requestJson('/api/demo-users');
    demoUsersEl.innerHTML = '';

    data.users.forEach((user) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'ghost';
      button.textContent = `${user.username} (${user.roles.join(', ')})`;
      button.addEventListener('click', () => {
        const knownPasswords = {
          alice: 'alice123',
          bob: 'bob123',
          carol: 'carol123',
        };

        loginWithCredential(user.username, knownPasswords[user.username]).catch((error) => {
          setOutput(error.message);
        });
      });
      demoUsersEl.appendChild(button);
    });
  } catch (error) {
    setOutput(error.message);
  }
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(loginForm);

  try {
    await loginWithCredential(form.get('username'), form.get('password'));
  } catch (error) {
    setOutput(error.message);
  }
});

checkSessionBtn.addEventListener('click', async () => {
  try {
    const data = await requestJson('/api/me');
    setOutput(data);
  } catch (error) {
    setOutput(error.message);
  }
});

loadUsersBtn.addEventListener('click', async () => {
  try {
    const data = await requestJson('/api/users');
    setOutput(data);
  } catch (error) {
    setOutput(error.message);
  }
});

logoutBtn.addEventListener('click', async () => {
  try {
    const data = await requestJson('/api/logout', { method: 'POST' });
    setOutput(data);
  } catch (error) {
    setOutput(error.message);
  }
});

loadDemoUsers();
