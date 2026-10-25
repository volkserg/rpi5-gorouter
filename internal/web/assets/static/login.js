(function () {
  'use strict';

  var form = document.getElementById('login-form');
  var card = document.getElementById('card');
  var lock = document.getElementById('lock');
  var errorBox = document.getElementById('error');
  var button = form.querySelector('button');
  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Фокус на логин, когда форма уже появилась.
  function focusLogin() {
    if (document.activeElement === document.body) form.username.focus({ preventScroll: true });
  }
  if (reducedMotion) {
    focusLogin();
  } else {
    card.addEventListener('animationend', function once(e) {
      if (e.animationName !== 'rise') return;
      card.removeEventListener('animationend', once);
      focusLogin();
    });
  }

  function showError(text) {
    errorBox.textContent = text;
    errorBox.hidden = false;
    if (reducedMotion) return;
    card.classList.remove('shake');
    void card.offsetWidth;  // перезапуск анимации
    card.classList.add('shake');
    lock.classList.add('denied');
    setTimeout(function () { lock.classList.remove('denied'); }, 900);
  }

  function setLoading(on) {
    button.disabled = on;
    button.classList.toggle('loading', on);
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    errorBox.hidden = true;

    if (!form.username.value.trim() || !form.password.value) {
      showError('Введите логин и пароль.');
      return;
    }

    setLoading(true);
    fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Routerd-CSRF': '1' },
      body: JSON.stringify({
        username: form.username.value.trim(),
        password: form.password.value,
        remember: form.remember.checked
      }),
      credentials: 'same-origin'
    })
      .then(function (response) {
        if (response.ok) {
          // Замок открывается, затем переход в панель.
          lock.classList.add('unlocked');
          // Замок уже открылся здесь — приветствие панели не повторяет его.
          try { sessionStorage.setItem('routerd.intro', 'skip'); } catch (e) { /* без хранилища */ }
          setTimeout(function () { location.replace('/'); }, reducedMotion ? 0 : 550);
          return;
        }
        setLoading(false);
        return response.json().catch(function () { return {}; }).then(function (body) {
          if (response.status === 401 || response.status === 429) {
            showError(body.error || 'Неверный логин или пароль.');
          } else {
            showError('Сервер недоступен (' + response.status + ').');
          }
        });
      })
      .catch(function () {
        setLoading(false);
        showError('Не удалось связаться с сервером.');
      });
  });
})();
