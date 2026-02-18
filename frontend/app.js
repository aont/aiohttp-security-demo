const output = document.getElementById('output');
const loginForm = document.getElementById('login-form');
const checkSessionBtn = document.getElementById('check-session');
const loadUsersBtn = document.getElementById('load-users');
const logoutBtn = document.getElementById('logout');

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

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(loginForm);

  try {
    const data = await requestJson('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        username: form.get('username'),
        password: form.get('password'),
      }),
    });
    setOutput(data);
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
