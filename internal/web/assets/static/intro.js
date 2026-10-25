// Решение о приветствии — до первой отрисовки (в <head>), чтобы заставка не
// мелькала, когда она не нужна. Показывается при открытии панели; не при
// обновлении страницы и переходе «назад», не сразу после ввода пароля (замок
// только что открылся) и не при «уменьшить движение». Анимацию ведёт app.js.
(function () {
  'use strict';
  try {
    var nav = performance.getEntriesByType('navigation')[0];
    var opened = !nav || nav.type === 'navigate';
    var justLoggedIn = sessionStorage.getItem('routerd.intro') === 'skip';
    sessionStorage.removeItem('routerd.intro');
    if (opened && !justLoggedIn && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      document.documentElement.classList.add('with-intro');
    }
  } catch (e) { /* без приветствия */ }
})();
