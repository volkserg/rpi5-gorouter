(function () {
  'use strict';

  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var POLL_MS = 5000;

  // --- Запросы к API ---------------------------------------------------------

  // api(метод, путь, тело) → Promise<JSON>. Без сессии — на страницу входа.
  // Тело-строка уходит как текст (файл списка), иначе — JSON. При ошибке
  // err.data — разобранный ответ (например, строки с ошибками).
  function api(method, path, body) {
    var opts = { method: method, credentials: 'same-origin', headers: {} };
    if (method !== 'GET') opts.headers['X-Routerd-CSRF'] = '1';
    if (typeof body === 'string') {
      opts.headers['Content-Type'] = 'text/plain; charset=utf-8';
      opts.body = body;
    } else if (body !== undefined) {
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
          err.data = data;
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

  // --- Общее для разделов списков ---------------------------------------------

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  // segmented — переключатель (role=radio); onChange(значение атрибута attr).
  function segmented(root, attr, onChange) {
    root.addEventListener('click', function (e) {
      var b = e.target.closest('button');
      if (!b || !root.contains(b)) return;
      root.querySelectorAll('button').forEach(function (x) {
        x.setAttribute('aria-checked', x === b ? 'true' : 'false');
      });
      onChange(b.getAttribute(attr));
    });
  }

  // badLines — строки с ошибками; onPick(номер строки) — по щелчку.
  function badLines(ul, lines, onPick) {
    ul.textContent = '';
    (lines || []).forEach(function (b) {
      var li = el('li', onPick ? 'clickable' : '');
      li.appendChild(el('span', 'ln', 'строка ' + b.line));
      li.appendChild(el('span', 'txt', b.text));
      li.appendChild(el('span', 'why', b.error));
      if (onPick) li.addEventListener('click', function () { onPick(b.line); });
      ul.appendChild(li);
    });
  }

  function shake(card) {
    if (reducedMotion || !card) return;
    card.classList.remove('shake');
    void card.offsetWidth;
    card.classList.add('shake');
  }

  // Тип записи по виду (окончательно проверяет routerd).
  function guessKind(v) {
    if (!v) return null;
    if (/^[0-9./]+$/.test(v)) return v.indexOf('/') >= 0 ? 'подсеть' : 'IP-адрес';
    if (v.indexOf(':') >= 0) return 'ipv6';
    if (/\s/.test(v)) return 'space';
    return 'домен';
  }

  var TRASH = '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 6 H16 M8 6 V4 H12 V6 M6 6 L7 17 H13 L14 6"/></svg>';

  // --- Список VPN ------------------------------------------------------------

  var MAX_ROWS = 400;

  views.vpn = (function () {
    var root = document.getElementById('view-vpn');
    var ul = document.getElementById('vpn-entries');
    var foot = document.getElementById('vpn-foot');
    var counts = document.getElementById('vpn-counts');
    var search = document.getElementById('vpn-search');
    var form = document.getElementById('vpn-add');
    var kindHint = document.getElementById('vpn-kind');
    var invalidCard = document.getElementById('vpn-invalid-card');
    var entries = [], filterKind = '', fresh = null, loaded = false;

    ul.setAttribute('data-empty', 'Загрузка…');

    function highlight(span, value, q) {
      var i = q ? value.indexOf(q) : -1;
      if (i < 0) { span.textContent = value; return; }
      span.appendChild(document.createTextNode(value.slice(0, i)));
      span.appendChild(el('mark', '', value.slice(i, i + q.length)));
      span.appendChild(document.createTextNode(value.slice(i + q.length)));
    }

    function row(e, n, q) {
      var li = el('li', 'entry');
      li.style.setProperty('--n', n);
      li.dataset.value = e.value;
      li.appendChild(el('span', 'badge ' + e.kind, e.kind === 'domain' ? 'домен' : (e.value.indexOf('/') >= 0 ? 'подсеть' : 'IP')));
      var v = el('span', 'value');
      highlight(v, e.value, q);
      li.appendChild(v);
      var del = el('button', 'del');
      del.type = 'button';
      del.title = 'Удалить';
      del.setAttribute('aria-label', 'Удалить ' + e.value);
      del.innerHTML = TRASH;
      li.appendChild(del);
      return li;
    }

    function render() {
      var q = search.value.trim().toLowerCase();
      var shown = entries.filter(function (e) {
        return (!filterKind || e.kind === filterKind) && (!q || e.value.indexOf(q) >= 0);
      });
      var frag = document.createDocumentFragment();
      shown.slice(0, MAX_ROWS).forEach(function (e, i) {
        var li = row(e, i, q);
        if (e.value === fresh) li.classList.add('fresh');
        frag.appendChild(li);
      });
      ul.textContent = '';
      ul.appendChild(frag);
      ul.setAttribute('data-empty', entries.length ? 'Ничего не найдено' : 'Список пуст — добавьте первую запись');
      foot.textContent = shown.length > MAX_ROWS
        ? 'Показаны первые ' + MAX_ROWS + ' из ' + shown.length + ' — уточните поиск'
        : (q || filterKind ? 'Найдено: ' + shown.length + ' из ' + entries.length : '');
      if (fresh) {
        var f = ul.querySelector('.fresh');
        if (f) f.scrollIntoView({ block: 'nearest', behavior: reducedMotion ? 'auto' : 'smooth' });
        fresh = null;
      }
    }

    function load() {
      return api('GET', '/api/v1/vpn').then(function (l) {
        loaded = true;
        entries = l.entries;
        counts.lastElementChild.textContent = 'доменов ' + l.domains + ' · IP и подсетей ' + l.nets;
        invalidCard.hidden = !l.invalid.length;
        badLines(document.getElementById('vpn-invalid'), l.invalid);
        render();
      }, function (err) { toast(err.message, 'bad'); });
    }

    function updateHint() {
      var v = form.value.value.trim();
      var k = guessKind(v);
      kindHint.className = 'kind-hint';
      kindHint.textContent = '';
      if (!k) return;
      if (k === 'ipv6' || k === 'space') {
        kindHint.classList.add('bad');
        kindHint.textContent = k === 'ipv6' ? 'IPv6 не поддерживается' : 'Запись без пробелов';
        return;
      }
      kindHint.classList.add('ok');
      var b = el('b', '', k);
      kindHint.appendChild(b);
      kindHint.appendChild(document.createTextNode(k === 'домен'
        ? ' — вместе с поддоменами; адреса попадут в список по DNS-ответам'
        : ' — трафик к ' + (k === 'подсеть' ? 'адресам подсети' : 'адресу') + ' сразу пойдёт через туннель'));
    }

    form.value.addEventListener('input', updateHint);

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var v = form.value.value.trim();
      if (!v) { shake(form.closest('.card')); return; }
      var btn = form.querySelector('.btn');
      btn.disabled = true;
      btn.classList.add('loading');
      api('POST', '/api/v1/vpn', { value: v }).then(function (c) {
        form.value.value = '';
        updateHint();
        if (!c.changed) {
          toast(c.entry.value + ' уже в списке');
        } else {
          toast((c.entry.kind === 'domain' ? 'Домен ' : '') + c.entry.value + ' добавлен' +
            (c.normalized ? ' (записан как ' + c.entry.value + ')' : ''), 'ok');
        }
        fresh = c.entry.value;
        search.value = '';
        return load();
      }, function (err) {
        toast(err.message, 'bad');
        shake(form.closest('.card'));
      }).then(function () {
        btn.disabled = false;
        btn.classList.remove('loading');
        form.value.focus();
      });
    });

    // Удаление: первый щелчок — «Удалить?», второй (в течение 3 с) — удаление.
    ul.addEventListener('click', function (e) {
      var del = e.target.closest('.del');
      if (!del) return;
      var li = del.closest('.entry');
      if (!del.classList.contains('confirm')) {
        ul.querySelectorAll('.del.confirm').forEach(function (d) { d.classList.remove('confirm'); d.innerHTML = TRASH; });
        del.classList.add('confirm');
        del.textContent = 'Удалить?';
        clearTimeout(del._t);
        del._t = setTimeout(function () { del.classList.remove('confirm'); del.innerHTML = TRASH; }, 3000);
        return;
      }
      clearTimeout(del._t);
      del.disabled = true;
      var value = li.dataset.value;
      api('DELETE', '/api/v1/vpn?value=' + encodeURIComponent(value)).then(function () {
        toast(value + ' удалён из списка', 'ok');
        entries = entries.filter(function (x) { return x.value !== value; });
        li.classList.add('leaving');
        setTimeout(load, reducedMotion ? 0 : 320);
      }, function (err) {
        del.disabled = false;
        toast(err.message, 'bad');
      });
    });

    search.addEventListener('input', render);
    segmented(document.getElementById('vpn-filter'), 'data-kind', function (k) { filterKind = k; render(); });

    // --- Импорт ---
    var mode = 'merge', fileText = null, fileName = '';
    var preview = document.getElementById('import-preview');
    var drop = document.getElementById('dropzone');
    var input = document.getElementById('import-file');
    var modeHint = document.getElementById('import-mode-hint');

    var MODE_HINT = {
      merge: 'Новые записи из файла добавятся к списку; строки с ошибками будут пропущены.',
      replace: 'Список станет точной копией файла, вместе с комментариями. Записи, которых нет в файле, будут удалены.'
    };
    modeHint.textContent = MODE_HINT.merge;

    function fillDiff(ulId, list) {
      var u = document.getElementById(ulId);
      u.textContent = '';
      list.slice(0, 300).forEach(function (e) { u.appendChild(el('li', '', e.value)); });
      if (list.length > 300) u.appendChild(el('li', 'more', '… и ещё ' + (list.length - 300)));
      u.closest('.diff-col').hidden = !list.length;
    }

    function showPreview(res) {
      var sum = document.getElementById('import-summary');
      sum.textContent = '';
      sum.appendChild(el('span', 'chip', fileName));
      sum.appendChild(el('span', 'chip add', '+' + res.added.length + ' добавится'));
      if (res.mode === 'replace') sum.appendChild(el('span', 'chip del', '−' + res.removed.length + ' удалится'));
      sum.appendChild(el('span', 'chip', res.kept + ' без изменений'));
      if (res.invalid.length) sum.appendChild(el('span', 'chip warn', 'ошибок: ' + res.invalid.length));
      if (res.conflicts.length) sum.appendChild(el('span', 'chip del', 'конфликтов: ' + res.conflicts.length));
      fillDiff('import-added', res.added);
      fillDiff('import-removed', res.mode === 'replace' ? res.removed : []);
      badLines(document.getElementById('import-bad'), res.conflicts.concat(res.invalid));
      var apply = document.getElementById('import-apply');
      var blocked = res.conflicts.length > 0 || (res.mode === 'replace' && res.invalid.length > 0);
      var nothing = !res.added.length && !res.removed.length;
      apply.disabled = blocked || nothing;
      apply.textContent = blocked ? (res.conflicts.length ? 'Есть конфликты' : 'Исправьте ошибки в файле')
        : (nothing ? 'Изменений нет' : 'Применить');
      preview.hidden = false;
    }

    function check() {
      if (fileText === null) return;
      api('POST', '/api/v1/vpn/import?mode=' + mode, fileText).then(showPreview, function (err) {
        toast(err.message, 'bad');
      });
    }

    function takeFile(f) {
      if (!f) return;
      if (f.size > 8 * 1024 * 1024) { toast('Файл больше 8 МБ', 'bad'); return; }
      var r = new FileReader();
      r.onload = function () { fileText = String(r.result); fileName = f.name; check(); };
      r.onerror = function () { toast('Файл не прочитан', 'bad'); };
      r.readAsText(f);
    }

    function resetImport() {
      fileText = null;
      input.value = '';
      preview.hidden = true;
    }

    segmented(document.getElementById('import-mode'), 'data-mode', function (m) {
      mode = m;
      modeHint.textContent = MODE_HINT[m];
      check();
    });
    input.addEventListener('change', function () { takeFile(input.files[0]); });
    ['dragenter', 'dragover'].forEach(function (t) {
      drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add('over'); });
    });
    ['dragleave', 'drop'].forEach(function (t) {
      drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.remove('over'); });
    });
    drop.addEventListener('drop', function (e) { takeFile(e.dataTransfer.files[0]); });
    document.getElementById('import-cancel').addEventListener('click', resetImport);
    document.getElementById('import-apply').addEventListener('click', function () {
      var btn = this;
      btn.disabled = true;
      btn.classList.add('loading');
      api('POST', '/api/v1/vpn/import?mode=' + mode + '&apply=1', fileText).then(function (res) {
        toast('Импорт применён: +' + res.added.length + (res.mode === 'replace' ? ', −' + res.removed.length : ''), 'ok');
        resetImport();
        load();
      }, function (err) {
        if (err.data && err.data.mode) showPreview(err.data);
        toast(err.message, 'bad');
      }).then(function () { btn.classList.remove('loading'); });
    });

    return {
      enter: function () { if (!loaded) ul.textContent = ''; load(); }
    };
  })();

  // --- DNS override ----------------------------------------------------------

  views.dns = (function () {
    var text = document.getElementById('dns-text');
    var gutter = document.getElementById('dns-gutter');
    var bad = document.getElementById('dns-bad');
    var dirty = document.getElementById('dns-dirty');
    var save = document.getElementById('dns-save');
    var revert = document.getElementById('dns-revert');
    var rules = document.getElementById('dns-rules');
    var saved = '', errLines = {};

    function lines() {
      var n = text.value.split('\n').length;
      var frag = document.createDocumentFragment();
      for (var i = 1; i <= n; i++) {
        var s = el('span', errLines[i] ? 'err' : '', String(i));
        frag.appendChild(s);
        frag.appendChild(document.createTextNode('\n'));
      }
      gutter.textContent = '';
      gutter.appendChild(frag);
      gutter.scrollTop = text.scrollTop;
    }

    function setDirty() {
      var d = text.value !== saved;
      dirty.hidden = !d;
      save.disabled = !d;
      revert.disabled = !d;
    }

    function selectLine(n) {
      var parts = text.value.split('\n');
      var start = 0;
      for (var i = 0; i < n - 1 && i < parts.length; i++) start += parts[i].length + 1;
      text.focus();
      text.setSelectionRange(start, start + (parts[n - 1] || '').length);
    }

    function showRules(list) {
      var groups = {}, order = [];
      list.forEach(function (r) {
        if (!groups[r.domain]) { groups[r.domain] = []; order.push(r.domain); }
        groups[r.domain].push(r.server);
      });
      rules.textContent = '';
      order.forEach(function (d, i) {
        var r = el('div', 'rule');
        r.style.setProperty('--n', i);
        r.appendChild(el('span', 'dom', d));
        r.insertAdjacentHTML('beforeend', '<svg class="arrow" viewBox="0 0 34 10" aria-hidden="true"><path d="M1 5 H33"/></svg>');
        groups[d].forEach(function (s) { r.appendChild(el('span', 'srv', s)); });
        rules.appendChild(r);
      });
    }

    function showErrors(list) {
      errLines = {};
      (list || []).forEach(function (b) { errLines[b.line] = true; });
      badLines(bad, list, selectLine);
      lines();
    }

    function load() {
      api('GET', '/api/v1/overrides').then(function (o) {
        if (text.value !== saved && document.activeElement === text) return;
        saved = o.text;
        text.value = o.text;
        showErrors(o.invalid);
        showRules(o.rules);
        setDirty();
      }, function (err) { toast(err.message, 'bad'); });
    }

    function submit(checkOnly) {
      var btn = checkOnly ? document.getElementById('dns-check') : save;
      btn.disabled = true;
      btn.classList.add('loading');
      var body = text.value;
      return api('PUT', '/api/v1/overrides' + (checkOnly ? '?check=1' : ''), body).then(function (o) {
        showErrors([]);
        if (checkOnly) {
          toast('Ошибок нет: правил ' + o.rules.length, 'ok');
        } else {
          saved = body.endsWith('\n') || !body ? body : body + '\n';
          if (text.value === body) text.value = saved;
          showRules(o.rules);
          toast('dns_override.txt сохранён и применён', 'ok');
        }
      }, function (err) {
        if (err.data && err.data.invalid) {
          showErrors(err.data.invalid);
          shake(text.closest('.card'));
          toast('Ошибок в файле: ' + err.data.invalid.length + ' — файл не сохранён', 'bad');
        } else {
          toast(err.message, 'bad');
        }
      }).then(function () {
        btn.classList.remove('loading');
        btn.disabled = false;
        setDirty();
      });
    }

    text.addEventListener('input', function () { lines(); setDirty(); });
    text.addEventListener('scroll', function () { gutter.scrollTop = text.scrollTop; });
    text.addEventListener('keydown', function (e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        if (!save.disabled) submit(false);
      }
    });
    save.addEventListener('click', function () { submit(false); });
    document.getElementById('dns-check').addEventListener('click', function () { submit(true); });
    revert.addEventListener('click', function () {
      text.value = saved;
      showErrors([]);
      setDirty();
    });
    window.addEventListener('beforeunload', function (e) {
      if (text.value !== saved) { e.preventDefault(); e.returnValue = ''; }
    });

    return { enter: load };
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
