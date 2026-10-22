(function () {
  'use strict';

  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var POLL_MS = 5000;

  // --- Запросы к API ---------------------------------------------------------

  // api(метод, путь, тело) → Promise<JSON>. Без сессии — на страницу входа.
  function api(method, path, body) {
    var opts = { method: method, credentials: 'same-origin', headers: {} };
    if (method !== 'GET') opts.headers['X-Routerd-CSRF'] = '1';
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (r) {
      if (r.status === 401) {
        location.replace('/login');
        return new Promise(function () {});
      }
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) {
          var err = new Error(data.error || ('HTTP ' + r.status));
          err.status = r.status;
          throw err;
        }
        return data;
      });
    });
  }

  // --- Общие элементы --------------------------------------------------------

  var banner = document.getElementById('banner');

  function setBanner(text) {
    banner.textContent = text || '';
    banner.hidden = !text;
  }

  function toast(text, kind) {
    var box = document.getElementById('toasts');
    var el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = text;
    box.appendChild(el);
    setTimeout(function () {
      el.classList.add('out');
      el.addEventListener('animationend', function () { el.remove(); });
      if (reducedMotion) el.remove();
    }, 4000);
  }

  // bind — заполняет элементы data-bind="ключ" значениями из obj.
  function bind(root, obj) {
    root.querySelectorAll('[data-bind]').forEach(function (el) {
      var v = obj[el.getAttribute('data-bind')];
      if (v === undefined || v === null) return;
      el.classList.remove('skeleton');
      if (el.textContent !== String(v)) el.textContent = v;
    });
  }

  // countTo — число в элементе плавно «досчитывает» до значения.
  function countTo(el, value) {
    var from = Number(el.getAttribute('data-value') || 0);
    if (from === value && el.hasAttribute('data-value')) return;
    el.setAttribute('data-value', value);
    var tile = el.closest('.tile');
    if (tile && el.hasAttribute('data-shown')) {
      tile.classList.remove('flash');
      void tile.offsetWidth;
      tile.classList.add('flash');
    }
    el.setAttribute('data-shown', '');
    if (reducedMotion) { el.textContent = value; return; }
    var start = performance.now(), dur = 900;
    (function step(now) {
      var t = Math.min(1, (now - start) / dur);
      var e = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(from + (value - from) * e);
      if (t < 1) requestAnimationFrame(step);
    })(start);
  }

  function plural(n, one, few, many) {
    var m10 = n % 10, m100 = n % 100;
    if (m10 === 1 && m100 !== 11) return one;
    if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return few;
    return many;
  }

  function duration(ms) {
    var s = Math.max(0, Math.floor(ms / 1000));
    var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    if (d > 0) return d + ' ' + plural(d, 'день', 'дня', 'дней') + ' ' + h + ' ч';
    if (h > 0) return h + ' ч ' + m + ' мин';
    if (m > 0) return m + ' мин';
    return s + ' с';
  }

  // --- Разделы ---------------------------------------------------------------

  var views = {};
  var current = null;

  function show(name) {
    if (!views[name]) name = 'overview';
    document.querySelectorAll('.tab').forEach(function (t) {
      t.classList.toggle('active', t.getAttribute('data-view') === name);
    });
    document.querySelectorAll('.view').forEach(function (v) {
      var on = v.getAttribute('data-view') === name;
      if (on && v.hidden) {
        // Карточки раздела поднимаются по очереди.
        v.querySelectorAll('.reveal').forEach(function (el, i) {
          el.style.setProperty('--i', i);
          el.style.animation = 'none';
          void el.offsetWidth;
          el.style.animation = '';
        });
      }
      v.hidden = !on;
    });
    if (current && views[current].leave) views[current].leave();
    current = name;
    if (views[name].enter) views[name].enter();
  }

  // --- Обзор -----------------------------------------------------------------

  var MODE_TEXT = {
    redirect: 'TCP через локальный порт GOST',
    tproxy: 'TCP и UDP через прозрачный прокси GOST',
    route: 'весь IP-трафик через интерфейс туннеля'
  };

  views.overview = (function () {
    var root = document.getElementById('view-overview');
    var scheme = document.getElementById('scheme');
    var pill = document.getElementById('tunnel-pill');
    var note = document.getElementById('scheme-note');
    var timer = null, uptimeTimer = null, started = null;

    root.querySelectorAll('[data-bind]').forEach(function (el) { el.classList.add('skeleton'); });

    function setPill(kind, text) {
      pill.className = 'pill ' + kind;
      pill.lastElementChild.textContent = text;
    }

    function render(st) {
      setBanner('');
      started = new Date(st.started_at);
      var state = st.bypass ? 'bypass' : (st.tunnel_up ? 'up' : 'down');
      scheme.classList.remove('up', 'down', 'bypass', 'offline');
      scheme.classList.add(state);
      if (state === 'up') {
        setPill('ok', 'Туннель доступен');
        note.textContent = 'Адреса из списка VPN идут через туннель, остальное — напрямую.';
      } else if (state === 'bypass') {
        setPill('warn', 'Туннель недоступен — перехват снят');
        note.textContent = 'VPN_FAILOVER=open: пока туннель недоступен, весь трафик идёт напрямую.';
      } else {
        setPill('bad', 'Туннель недоступен');
        note.textContent = 'VPN_FAILOVER=closed: адреса из списка VPN недоступны, пока туннель не вернётся.';
      }
      bind(root, {
        mode: st.mode,
        mode_text: '— ' + (MODE_TEXT[st.mode] || ''),
        failover_text: st.failover === 'open'
          ? 'трафик идёт напрямую (VPN_FAILOVER=open)'
          : 'адреса из списка блокируются (VPN_FAILOVER=closed)',
        rpi_ip: st.rpi_ip,
        lan: st.lan,
        dhcp_text: st.dhcp ? 'раздаёт routerd' : 'выключен (DHCP_ENABLED=no)',
        version: st.version,
        uptime: duration(Date.now() - started)
      });
      root.querySelectorAll('[data-count]').forEach(function (el) {
        countTo(el, st[el.getAttribute('data-count')] || 0);
      });
    }

    function offline(err) {
      scheme.classList.remove('up', 'down', 'bypass');
      scheme.classList.add('offline');
      setPill('', 'нет связи с routerd');
      note.textContent = '';
      setBanner(err.message);
    }

    function load() {
      api('GET', '/api/v1/status').then(render, offline);
    }

    return {
      enter: function () {
        load();
        timer = setInterval(load, POLL_MS);
        uptimeTimer = setInterval(function () {
          if (started) bind(root, { uptime: duration(Date.now() - started) });
        }, 1000);
      },
      leave: function () {
        clearInterval(timer);
        clearInterval(uptimeTimer);
      }
    };
  })();

  // --- Запуск ----------------------------------------------------------------

  document.getElementById('logout').addEventListener('click', function () {
    api('POST', '/api/logout').then(function () { location.replace('/login'); },
      function (err) { toast('Выход не удался: ' + err.message, 'bad'); });
  });

  api('GET', '/api/me').then(function (me) {
    document.getElementById('user').textContent = me.user;
    document.getElementById('version').textContent = me.version;
  });

  window.addEventListener('hashchange', function () { show(location.hash.slice(1)); });
  show(location.hash.slice(1));

  // Для разделов следующих этапов.
  window.routerd = { api: api, toast: toast };
})();
