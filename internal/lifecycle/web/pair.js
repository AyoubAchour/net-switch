'use strict';
const form = document.querySelector('form');
const code = document.getElementById('code');
const error = document.getElementById('error');
const button = document.querySelector('button');
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!form.reportValidity()) return;
  button.disabled = true;
  error.textContent = '';
  try {
    const response = await fetch('/api/pair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: code.value }),
      credentials: 'omit',
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    sessionStorage.setItem('token', result.token);
    location.replace('/');
  } catch (failure) {
    error.textContent = failure.message || 'Net Switch could not be reached. Open it again and try a new code.';
    code.focus();
    code.select();
  } finally {
    button.disabled = false;
  }
});
