document.getElementById('saveBtn').addEventListener('click', async () => {
  const site = document.getElementById('site').value;
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  const status = document.getElementById('status');

  const apiKey = localStorage.getItem('apiKey');  // you can manage auth better later

  if (!apiKey) {
    status.innerText = "API key not set.";
    return;
  }

  try {
    const res = await fetch('http://localhost:8000/api/save-credential/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': apiKey
      },
      body: JSON.stringify({
        site: site,
        username: username,
        password: password
      })
    });

    const data = await res.json();
    status.innerText = data.success ? "Saved!" : data.message || "Error saving.";
  } catch (err) {
    console.error(err);
    status.innerText = "Failed to connect to API.";
  }
});
