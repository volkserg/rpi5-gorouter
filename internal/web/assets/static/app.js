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

  // show — раздел по адресу «#имя?параметры» (параметры получает enter).
  function show(hash) {
    var parts = (hash || '').split('?');
    var name = parts[0], params = new URLSearchParams(parts[1] || '');
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
    if (views[name].enter) views[name].enter(params);
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

    // --- Сервисы ---
    var unitsBox = document.getElementById('units'), unitsShown = false;
    var UNIT_STATE = {
      active: function (u) { return u.sub === 'exited' ? 'выполнен' : 'работает'; },
      activating: function () { return 'запускается'; },
      reloading: function () { return 'перечитывает'; },
      deactivating: function () { return 'останавливается'; },
      failed: function () { return 'ошибка'; },
      inactive: function () { return 'остановлен'; }
    };
    function loadUnits() {
      api('GET', '/api/v1/services').then(function (us) {
        unitsBox.textContent = '';
        us.forEach(function (u, i) {
          var li = el('li');
          if (!unitsShown) li.style.setProperty('--n', i); else li.style.animation = 'none';
          var cls = !u.installed ? 'off' : u.active === 'active' ? 'ok' : u.active === 'failed' ? 'bad' :
            u.active === 'inactive' ? 'off' : 'warn';
          li.appendChild(el('span', 'dot ' + cls));
          var n = el('span', 'unit-name', u.label);
          n.appendChild(el('small', '', u.unit));
          li.appendChild(n);
          li.appendChild(el('span', 'state', !u.installed ? 'не установлен' :
            (UNIT_STATE[u.active] ? UNIT_STATE[u.active](u) : u.active)));
          unitsBox.appendChild(li);
        });
        unitsShown = true;
      }, function (err) {
        unitsBox.textContent = '';
        unitsBox.appendChild(el('li', 'state', err.message));
      });
    }

    // --- Внешний адрес ---
    var exitCard = document.getElementById('exit-card');
    var exitBtn = document.getElementById('exit-run');
    var exitNote = document.getElementById('exit-note');
    var EXIT_STALE = 10 * 60 * 1000;
    function exitPath(id, ip, p) {
      var box = document.getElementById(id);
      var ipEl = box.querySelector('.exit-ip'), msEl = box.querySelector('.exit-ms');
      ipEl.className = 'exit-ip mono';
      if (p.ok) {
        ipEl.textContent = ip;
        msEl.textContent = p.total_ms + ' мс';
        msEl.title = 'соединение ' + p.connect_ms + ' мс, ответ ' + p.total_ms + ' мс';
      } else {
        ipEl.className = 'exit-ip bad';
        ipEl.textContent = p.error || 'нет данных';
        msEl.textContent = '';
      }
      box.classList.remove('fresh');
      void box.offsetWidth;
      box.classList.add('fresh');
    }
    function showExit(t) {
      if (!t.enabled) {
        exitCard.hidden = true;
        return null;
      }
      exitCard.hidden = false;
      var when = t.checked_at && new Date(t.checked_at);
      if (!when || when.getFullYear() < 2000) {
        exitNote.textContent = 'Ещё не проверялся.';
        return null;
      }
      exitPath('exit-direct', t.direct_ip, t.direct);
      exitPath('exit-tunnel', t.tunnel_ip, t.tunnel);
      var same = t.direct_ip && t.tunnel_ip && t.direct_ip === t.tunnel_ip;
      exitNote.textContent = (same ? 'Внимание: адреса совпадают — трафик через туннель выходит тем же адресом. ' : '') +
        'Проверено ' + ago(when.getTime() / 1000) + ' через ' + t.url + '.';
      return when;
    }
    function runExit() {
      exitBtn.disabled = true;
      exitCard.classList.add('running');
      api('POST', '/api/v1/tunnel').then(showExit, function (err) { toast(err.message, 'bad'); })
        .then(function () { exitBtn.disabled = false; exitCard.classList.remove('running'); });
    }
    exitBtn.addEventListener('click', runExit);
    function loadExit() {
      api('GET', '/api/v1/tunnel').then(function (t) {
        var when = showExit(t);
        // Сам — не чаще раза в 10 минут; по кнопке — когда угодно.
        if (t.enabled && (!when || Date.now() - when.getTime() > EXIT_STALE)) runExit();
      }, function () {});
    }

    var unitsTimer = null;
    return {
      enter: function () {
        load();
        loadUnits();
        loadExit();
        timer = setInterval(load, POLL_MS);
        unitsTimer = setInterval(loadUnits, 15000);
        uptimeTimer = setInterval(function () {
          if (started) bind(root, { uptime: duration(Date.now() - started) });
        }, 1000);
      },
      leave: function () {
        clearInterval(timer);
        clearInterval(unitsTimer);
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

  // --- Обращения -------------------------------------------------------------

  function ago(unix) {
    var s = Math.max(0, Math.floor(Date.now() / 1000 - unix));
    if (s < 60) return 'только что';
    if (s < 3600) return Math.floor(s / 60) + ' мин назад';
    if (s < 86400) return Math.floor(s / 3600) + ' ч назад';
    var d = new Date(unix * 1000);
    return d.toLocaleDateString('ru-RU', { day: 'numeric', month: 'short' }) + ' ' +
      d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  }

  function size(n) {
    if (!n) return '';
    var u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + ' ' + u[i];
  }

  // addToVPN — выбор записи (домен или родительский домен) и добавление в список.
  function chooser(options, onDone, onCancel) {
    var box = el('div', 'chooser');
    box.appendChild(el('span', 'label', 'В список VPN:'));
    var seg = el('div', 'segmented');
    seg.setAttribute('role', 'radiogroup');
    var chosen = options[options.length > 1 ? 1 : 0];
    options.forEach(function (o) {
      var b = el('button', '', o);
      b.type = 'button';
      b.setAttribute('role', 'radio');
      b.setAttribute('data-v', o);
      b.setAttribute('aria-checked', o === chosen ? 'true' : 'false');
      seg.appendChild(b);
    });
    segmented(seg, 'data-v', function (v) { chosen = v; });
    box.appendChild(seg);
    var add = el('button', 'btn tiny', 'Добавить');
    add.type = 'button';
    var cancel = el('button', 'btn ghost tiny', 'Отмена');
    cancel.type = 'button';
    box.appendChild(add);
    box.appendChild(cancel);
    cancel.addEventListener('click', onCancel);
    add.addEventListener('click', function () {
      add.disabled = true;
      add.classList.add('loading');
      api('POST', '/api/v1/vpn', { value: chosen }).then(function (c) {
        toast(c.changed ? c.entry.value + ' добавлен в список VPN — новые соединения пойдут через туннель'
          : c.entry.value + ' уже в списке', 'ok');
        onDone();
      }, function (err) {
        add.disabled = false;
        add.classList.remove('loading');
        toast(err.message, 'bad');
      });
    });
    return box;
  }

  var ACCESS_POLL_MS = 10000, ACCESS_PAGE = 300;

  views.access = (function () {
    var rowsBox = document.getElementById('acc-rows');
    var foot = document.getElementById('acc-foot');
    var more = document.getElementById('acc-more');
    var live = document.getElementById('access-live');
    var devSel = document.getElementById('acc-device');
    var search = document.getElementById('acc-search');
    var q = { hours: 24, device: '', route: '', status: '', q: '' };
    var timer = null, shown = ACCESS_PAGE, prev = null, data = null, open = 0, searchT = null;

    rowsBox.setAttribute('data-empty', 'Загрузка…');

    function key(r) { return r.device + '|' + r.resource + '|' + r.route; }
    function sig(r) { return [r.ok, r.timeout, r.refused, r.nodata, r.last, r.in_list].join(','); }

    function names() {
      var m = {};
      (data.devices || []).forEach(function (d) { m[d.key] = d; });
      return m;
    }

    function fillDevices() {
      var cur = devSel.value;
      devSel.textContent = '';
      var all = el('option', '', 'Все устройства');
      all.value = '';
      devSel.appendChild(all);
      data.devices.forEach(function (d) {
        var o = el('option', '', d.name + (d.problems ? ' · проблем ' + d.problems : ''));
        o.value = d.key;
        devSel.appendChild(o);
      });
      devSel.value = cur;
    }

    function summary(t) {
      var box = document.getElementById('acc-summary');
      box.textContent = '';
      function chip(cls, label, value) {
        var c = el('span', 'chip ' + cls);
        c.appendChild(document.createTextNode(label + ' '));
        c.appendChild(el('b', '', value));
        box.appendChild(c);
      }
      var pct = function (n) { return t.connections ? Math.round(n * 100 / t.connections) + '%' : '—'; };
      chip('', 'обращений', t.connections);
      chip('chip-ok', 'успешных', pct(t.ok));
      chip(t.problems ? 'chip-bad' : '', 'проблем', t.problems);
      chip('', 'через туннель', pct(t.tunnel));
    }

    function outcome(r) {
      var box = el('div', 'outcome');
      var total = r.ok + r.timeout + r.refused + r.nodata || 1;
      var bar = el('div', 'bar');
      [['ok', r.ok], ['to', r.timeout], ['rf', r.refused], ['nd', r.nodata]].forEach(function (p) {
        if (!p[1]) return;
        var s = el('span', p[0]);
        s.style.width = (p[1] * 100 / total) + '%';
        bar.appendChild(s);
      });
      bar.title = 'успешно ' + r.ok + ', таймаут ' + r.timeout + ', отказ ' + r.refused + ', без данных ' + r.nodata;
      box.appendChild(bar);
      var c = el('div', 'counts');
      c.appendChild(document.createTextNode('✓ ' + r.ok));
      if (r.timeout) c.appendChild(el('span', 'to', '  ⏱ ' + r.timeout));
      if (r.refused) c.appendChild(el('span', 'rf', '  ⊘ ' + r.refused));
      if (r.nodata) c.appendChild(el('span', 'nd', '  ∅ ' + r.nodata));
      box.appendChild(c);
      return box;
    }

    function rowEl(r, n, devs, changed) {
      var problem = r.timeout + r.refused + r.nodata > 0;
      var row = el('div', 'acc-row' + (problem ? ' problem' : '') + (changed ? ' changed' : ''));
      row.setAttribute('role', 'row');
      row.style.setProperty('--n', n);
      var res = el('div', 'res');
      res.appendChild(el('span', 'name', r.resource));
      var meta = [];
      if (r.ip && r.ip !== r.resource) meta.push(r.ip);
      if (r.ports && r.ports.length) meta.push(r.proto + ' ' + r.ports.join(', '));
      if (r.bytes) meta.push(size(r.bytes));
      res.appendChild(el('span', 'meta', meta.join(' · ')));
      res.title = r.resource;
      row.appendChild(res);
      var d = devs[r.device] || { name: r.device, ip: '' };
      var dev = el('div', 'dev', d.name);
      if (d.ip && d.ip !== d.name) dev.appendChild(el('span', 'ip', d.ip));
      row.appendChild(dev);
      row.appendChild(el('span', 'route ' + r.route, r.route === 'tunnel' ? 'туннель' : 'напрямую'));
      row.appendChild(outcome(r));
      row.appendChild(el('span', 'ago', ago(r.last)));
      var act = el('div', 'act');
      if (r.in_list) {
        var badge = el('span', 'in-list', 'в списке VPN');
        if (r.list_entry && r.list_entry !== r.resource) badge.title = 'по записи ' + r.list_entry;
        act.appendChild(badge);
        if (r.list_entry) act.appendChild(unlistButton(r.list_entry));
      } else if (r.route === 'direct' && r.timeout > 0) {
        var b = el('button', 'btn tiny', 'В VPN');
        b.type = 'button';
        b.addEventListener('click', function () {
          if (row.nextElementSibling && row.nextElementSibling.classList.contains('chooser')) return;
          open++;
          var ch = chooser(suggest(r.resource), function () { open--; ch.remove(); load(true); },
            function () { open--; ch.remove(); });
          row.after(ch);
        });
        act.appendChild(b);
      }
      row.appendChild(act);
      return row;
    }

    // unlistButton — неприметное «×»: первый щелчок — «убрать запись?»,
    // второй (в течение 4 с) — удаление записи из списка VPN.
    var CROSS = '<svg viewBox="0 0 10 10" aria-hidden="true"><path d="M2 2 L8 8 M8 2 L2 8"/></svg>';

    function unlistButton(entry) {
      var b = el('button', 'unlist');
      b.innerHTML = CROSS;
      b.type = 'button';
      b.title = 'Убрать ' + entry + ' из списка VPN';
      b.setAttribute('aria-label', b.title);
      var t = null;
      function reset() {
        if (!b.classList.contains('confirm')) return;
        b.classList.remove('confirm');
        b.innerHTML = CROSS;
        open--;
      }
      b.addEventListener('click', function () {
        if (!b.classList.contains('confirm')) {
          b.classList.add('confirm');
          b.textContent = 'убрать ' + entry + '?';
          open++;
          t = setTimeout(reset, 4000);
          return;
        }
        clearTimeout(t);
        b.disabled = true;
        api('DELETE', '/api/v1/vpn?value=' + encodeURIComponent(entry)).then(function (c) {
          reset();
          toast(c.changed ? entry + ' убран из списка VPN — новые соединения пойдут напрямую'
            : entry + ' уже нет в списке', 'ok');
          load(false);
        }, function (err) {
          reset();
          b.disabled = false;
          toast(err.message, 'bad');
        });
      });
      return b;
    }

    // Как access.Suggest: домен и родительские домены, без зоны верхнего уровня.
    function suggest(res) {
      if (/^[0-9.]+$/.test(res)) return [res];
      var l = res.split('.'), min = 2, out = [];
      if (l.length >= 3 && l[l.length - 1].length === 2 && l[l.length - 2].length <= 3) min = 3;
      for (var i = 0; l.length - i >= min; i++) out.push(l.slice(i).join('.'));
      return out.length ? out : [res];
    }

    function renderRows(animate) {
      var devs = names();
      var frag = document.createDocumentFragment();
      var next = {};
      data.rows.slice(0, shown).forEach(function (r, i) {
        var k = key(r);
        next[k] = sig(r);
        var changed = prev && prev[k] !== next[k];
        frag.appendChild(rowEl(r, i, devs, changed && !animate));
      });
      // Обновления без повторной анимации появления строк.
      rowsBox.classList.toggle('quiet', !animate);
      rowsBox.textContent = '';
      rowsBox.appendChild(frag);
      prev = next;
      rowsBox.setAttribute('data-empty', 'За этот период обращений нет' + (q.q || q.device || q.route || q.status ? ' (с этими фильтрами)' : ''));
      more.hidden = data.rows.length <= shown;
      foot.textContent = data.truncated ? 'Показаны последние ' + data.rows.length + ' строк — уточните фильтры' :
        (data.rows.length > shown ? 'Показано ' + shown + ' из ' + data.rows.length : '');
    }

    function renderCands() {
      var card = document.getElementById('cand-card');
      var ul = document.getElementById('cands');
      card.hidden = !data.candidates.length;
      document.getElementById('cand-count').lastElementChild.textContent = data.candidates.length;
      if (ul.querySelector('.chooser')) return;
      ul.textContent = '';
      data.candidates.forEach(function (c, i) {
        var li = el('li', 'cand');
        li.style.setProperty('--n', i);
        li.appendChild(el('span', 'name', c.resource));
        var f = el('span', 'facts');
        f.appendChild(el('span', 'chip chip-bad', 'таймаутов ' + c.timeout));
        if (c.ok) f.appendChild(el('span', 'chip chip-ok', 'успешных ' + c.ok));
        f.appendChild(el('span', 'chip', c.devices + ' ' + plural(c.devices, 'устройство', 'устройства', 'устройств')));
        f.appendChild(el('span', 'chip', ago(c.last)));
        li.appendChild(f);
        var chk = el('a', 'btn ghost tiny', 'Проверить');
        chk.href = '#check?target=' + encodeURIComponent(c.resource);
        chk.title = 'Проверить доступность напрямую и через туннель';
        li.appendChild(chk);
        var b = el('button', 'btn tiny', 'В VPN');
        b.type = 'button';
        b.addEventListener('click', function () {
          if (li.querySelector('.chooser')) return;
          open++;
          var ch = chooser(c.suggest, function () {
            open--;
            li.classList.add('leaving');
            setTimeout(function () { load(true); }, reducedMotion ? 0 : 350);
          }, function () { open--; ch.remove(); });
          li.appendChild(ch);
        });
        li.appendChild(b);
        ul.appendChild(li);
      });
    }

    function load(animate) {
      var qs = Object.keys(q).filter(function (k) { return q[k] !== ''; })
        .map(function (k) { return k + '=' + encodeURIComponent(q[k]); }).join('&');
      return api('GET', '/api/v1/access?' + qs).then(function (res) {
        document.getElementById('access-off').hidden = true;
        document.getElementById('access-main').hidden = false;
        data = res;
        if (!res.rows) res.rows = [];
        fillDevices();
        summary(res.totals);
        renderCands();
        renderRows(animate);
        live.classList.remove('tick');
        void live.offsetWidth;
        live.classList.add('tick');
      }, function (err) {
        if (err.status === 404) {
          document.getElementById('access-off').hidden = false;
          document.getElementById('access-main').hidden = true;
          document.getElementById('cand-card').hidden = true;
          return;
        }
        toast(err.message, 'bad');
      });
    }

    function refilter() { shown = ACCESS_PAGE; prev = null; load(true); }

    function poll() {
      if (open > 0 || document.hidden) { live.classList.add('paused'); return; }
      live.classList.remove('paused');
      load(false);
    }

    segmented(document.getElementById('acc-period'), 'data-hours', function (h) { q.hours = Number(h); refilter(); });
    segmented(document.getElementById('acc-route'), 'data-route', function (v) { q.route = v; refilter(); });
    segmented(document.getElementById('acc-status'), 'data-status', function (v) { q.status = v; refilter(); });
    devSel.addEventListener('change', function () { q.device = devSel.value; refilter(); });
    search.addEventListener('input', function () {
      clearTimeout(searchT);
      searchT = setTimeout(function () { q.q = search.value.trim(); refilter(); }, 300);
    });
    more.addEventListener('click', function () { shown += ACCESS_PAGE; renderRows(false); });

    // Третья кнопка периода — вся история (ACCESS_HISTORY_DAYS).
    api('GET', '/api/v1/status').then(function (st) {
      var b = document.querySelector('#acc-period [data-hours="168"]');
      if (st.history_days > 0 && st.history_days !== 7) {
        b.setAttribute('data-hours', st.history_days * 24);
        b.textContent = st.history_days + ' ' + plural(st.history_days, 'день', 'дня', 'дней');
      }
    }, function () {});

    return {
      enter: function (params) {
        if (params && params.has('device')) {
          q.device = params.get('device');
          var o = devSel.querySelector('option[value="' + CSS.escape(q.device) + '"]');
          if (!o) { o = el('option', '', params.get('name') || q.device); o.value = q.device; devSel.appendChild(o); }
          devSel.value = q.device;
        }
        prev = null;
        load(true);
        timer = setInterval(poll, ACCESS_POLL_MS);
      },
      leave: function () { clearInterval(timer); }
    };
  })();

  // --- Проверка ресурса ---------------------------------------------------------

  views.check = (function () {
    var form = document.getElementById('check-form');
    var card = document.getElementById('check-result');
    var portOther = document.getElementById('check-port-other');
    var recentBox = document.getElementById('check-recent');
    var port = 443, recent = [];
    var OK_ICON = '<svg viewBox="0 0 20 20"><path d="M4 10.5 L8.5 15 L16 6"/></svg>';
    var BAD_ICON = '<svg viewBox="0 0 20 20"><path d="M5 5 L15 15 M15 5 L5 15"/></svg>';

    segmented(document.getElementById('check-port'), 'data-port', function (v) {
      portOther.hidden = v !== 'other';
      if (v === 'other') { portOther.querySelector('input').focus(); return; }
      port = Number(v);
    });

    function pathPanel(id, p, running) {
      var box = document.getElementById(id);
      var body = box.querySelector('.path-body');
      var denied = p && p.kind === 'http';
      box.className = 'path' + (id === 'path-tunnel' ? ' tunnel' : '') +
        (running ? ' running' : (p.ok ? ' ok' : (denied ? ' warn' : ' bad')));
      body.textContent = '';
      if (running) {
        body.appendChild(el('span', 'wait', 'Соединение…'));
        return;
      }
      var st = el('div', 'status');
      var icon = el('span', 'badge-icon');
      icon.innerHTML = p.ok ? OK_ICON : BAD_ICON;
      st.appendChild(icon);
      var tx = el('div', 'status-text');
      tx.appendChild(el('b', '', p.ok ? 'Доступен' : (denied ? 'Отказ в доступе' : 'Недоступен')));
      tx.appendChild(el('span', '', p.ok ? (p.detail || '') : (p.error || '')));
      st.appendChild(tx);
      body.appendChild(st);
      if (p.ok || p.connect_ms) {
        var t = el('div', 'timing');
        var max = Math.max(p.total_ms, 1);
        [['соединение', p.connect_ms], [port === 443 ? 'с TLS' : 'ответ', p.total_ms]].forEach(function (r) {
          if (!r[1]) return;
          var row = el('div', 'timing-row');
          row.appendChild(el('span', '', r[0]));
          var bar = el('div', 'bar'), fill = el('span');
          fill.style.width = Math.max(4, r[1] * 100 / max) + '%';
          bar.appendChild(fill);
          row.appendChild(bar);
          row.appendChild(el('span', 'num', r[1] + ' мс'));
          t.appendChild(row);
        });
        body.appendChild(t);
      }
    }

    function verdict(r) {
      var v = document.getElementById('check-verdict');
      v.textContent = '';
      v.className = 'verdict';
      var d = r.direct.ok, t = r.tunnel.ok, tunnelDown = r.tunnel.error === 'туннель недоступен';
      var dDenied = r.direct.kind === 'http', tDenied = r.tunnel.kind === 'http';
      if (dDenied && tDenied) {
        v.classList.add('warn');
        v.textContent = 'Сервер отказывает обоими путями (HTTP ' + r.direct.status + ' и ' + r.tunnel.status + '). ' +
          'Так часто отвечают на запросы не из браузера, поэтому по этой проверке нельзя судить, доступен ли ресурс по адресу.';
      } else if (!d && t && !r.in_list) {
        v.classList.add('warn');
        v.appendChild(document.createTextNode(dDenied
          ? 'Напрямую сервер отказывает в доступе (HTTP ' + r.direct.status + '), через туннель — отвечает. Похоже на ограничение по адресу: ресурс стоит добавить в список VPN.'
          : 'Напрямую ресурс недоступен, через туннель — доступен. Его стоит добавить в список VPN.'));
        if (r.suggest && r.suggest.length) {
          var ch = chooser(r.suggest, function () { ch.remove(); run(r.target, r.port); }, function () { ch.remove(); });
          v.appendChild(ch);
        }
      } else if (!d && t) {
        v.classList.add('good');
        v.textContent = 'Напрямую недоступен, но ресурс в списке VPN (запись ' + (r.list_entry || '—') + ') — устройства получают его через туннель.';
      } else if (d && t) {
        v.classList.add('good');
        v.textContent = 'Доступен обоими путями.' + (r.in_list ? ' Ресурс в списке VPN (запись ' + (r.list_entry || '—') + '), хотя доступен и напрямую.' : '');
      } else if (d && !t) {
        v.classList.add(r.in_list ? 'bad' : 'warn');
        v.textContent = (tunnelDown ? 'Туннель сейчас недоступен.' : 'Через туннель ресурс недоступен.') +
          (r.in_list ? ' Ресурс в списке VPN — устройства сейчас не получат к нему доступ.' : ' Напрямую доступен.');
      } else {
        v.classList.add('bad');
        v.textContent = 'Недоступен обоими путями: возможно, ресурс не работает, неверен адрес или порт.';
      }
    }

    function remember(target, p, r) {
      recent = recent.filter(function (x) { return !(x.target === target && x.port === p); });
      recent.unshift({ target: target, port: p, cls: r.direct.ok && r.tunnel.ok ? 'ok' : (r.direct.ok || r.tunnel.ok ? 'warn' : 'bad') });
      recent = recent.slice(0, 8);
      recentBox.textContent = '';
      recent.forEach(function (x) {
        var b = el('button', x.cls, x.target + (x.port !== 443 ? ':' + x.port : ''));
        b.type = 'button';
        b.addEventListener('click', function () { form.target.value = x.target; run(x.target, x.port); });
        recentBox.appendChild(b);
      });
    }

    function run(target, p) {
      var btn = form.querySelector('.btn');
      btn.disabled = true;
      btn.classList.add('loading');
      card.hidden = false;
      card.style.animation = 'none';
      void card.offsetWidth;
      card.style.animation = '';
      document.getElementById('check-title').textContent = target;
      document.getElementById('check-addrs').textContent = 'Проверка…';
      document.getElementById('check-list').hidden = true;
      document.getElementById('check-verdict').textContent = '';
      pathPanel('path-direct', null, true);
      pathPanel('path-tunnel', null, true);
      api('POST', '/api/v1/check', { target: target, port: p }).then(function (r) {
        document.getElementById('check-title').textContent = r.target + (r.port !== 443 ? ':' + r.port : '');
        var pill = document.getElementById('check-list');
        pill.hidden = false;
        pill.className = 'pill' + (r.in_list ? ' ok' : '');
        pill.lastElementChild.textContent = r.in_list ? 'в списке VPN' + (r.list_entry && r.list_entry !== r.target ? ' · ' + r.list_entry : '') : 'не в списке VPN';
        document.getElementById('check-addrs').textContent = (r.name ? 'Адрес ' + r.addrs.join(', ') + '. ' : '') +
          'Устройства LAN сейчас идут к нему ' + (r.route === 'tunnel' ? 'через туннель.' : 'напрямую.');
        pathPanel('path-direct', r.direct);
        pathPanel('path-tunnel', r.tunnel);
        verdict(r);
        remember(r.target, r.port, r);
      }, function (err) {
        card.hidden = true;
        toast(err.message, 'bad');
        shake(form.closest('.card'));
      }).then(function () {
        btn.disabled = false;
        btn.classList.remove('loading');
      });
    }

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var t = form.target.value.trim();
      if (!t) { shake(form.closest('.card')); return; }
      var p = port;
      if (!portOther.hidden) {
        p = Number(portOther.querySelector('input').value);
        if (!(p >= 1 && p <= 65535)) { toast('Порт: от 1 до 65535', 'bad'); return; }
      }
      run(t, p);
    });

    return {
      enter: function (params) {
        if (params && params.get('target')) {
          form.target.value = params.get('target');
          run(params.get('target'), port);
        } else {
          form.target.focus({ preventScroll: true });
        }
      }
    };
  })();

  // --- Устройства ---------------------------------------------------------------

  views.devices = (function () {
    var grid = document.getElementById('dev-grid');
    var ICONS = {
      local: '<svg viewBox="0 0 20 20"><rect x="3" y="4" width="14" height="9" rx="2"/><path d="M7 16 H13 M10 13 V16"/></svg>',
      lease: '<svg viewBox="0 0 20 20"><rect x="6" y="2.5" width="8" height="15" rx="2"/><path d="M9 14.5 H11"/></svg>',
      seen: '<svg viewBox="0 0 20 20"><circle cx="10" cy="10" r="7"/><path d="M3 10 H17 M10 3 C7.5 6 7.5 14 10 17 M10 3 C12.5 6 12.5 14 10 17"/></svg>'
    };
    var KIND = { local: 'сервис RPi', lease: 'DHCP', seen: 'без аренды' };

    function card(d, i) {
      var a = el('a', 'dev-card' + (d.active ? '' : ' inactive'));
      a.href = '#access?device=' + encodeURIComponent(d.key) + '&name=' + encodeURIComponent(d.name);
      a.style.setProperty('--n', i);
      var head = el('div', 'dev-head');
      var icon = el('span', 'dev-icon');
      icon.innerHTML = ICONS[d.kind] || ICONS.seen;
      head.appendChild(icon);
      var title = el('div', 'dev-title');
      title.appendChild(el('b', '', d.name));
      var sub = KIND[d.kind] || '';
      if (d.kind === 'lease') sub += d.active ? ' · аренда до ' + new Date(d.expires).toLocaleString('ru-RU', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : ' · аренда истекла';
      title.appendChild(el('span', '', sub));
      head.appendChild(title);
      a.appendChild(head);
      var meta = el('dl', 'dev-meta');
      [['IP', d.ip], ['MAC', d.mac], ['имя', d.hostname && d.hostname !== d.name ? d.hostname : '']].forEach(function (p) {
        if (!p[1]) return;
        meta.appendChild(el('dt', '', p[0]));
        meta.appendChild(el('dd', '', p[1]));
      });
      a.appendChild(meta);
      var stats = el('div', 'dev-stats');
      stats.appendChild(el('span', 'chip', d.connections ? 'обращений ' + d.connections : 'обращений нет'));
      if (d.problems) stats.appendChild(el('span', 'chip chip-bad', 'проблем ' + d.problems));
      if (d.last) stats.appendChild(el('span', 'chip', ago(d.last)));
      a.appendChild(stats);
      a.appendChild(el('span', 'dev-go', 'обращения →'));
      return a;
    }

    function load() {
      api('GET', '/api/v1/devices').then(function (ds) {
        ds.sort(function (a, b) {
          if (a.active !== b.active) return a.active ? -1 : 1;
          return (b.connections - a.connections) || a.name.localeCompare(b.name);
        });
        grid.textContent = '';
        ds.forEach(function (d, i) { grid.appendChild(card(d, i)); });
        var active = ds.filter(function (d) { return d.active; }).length;
        document.getElementById('dev-count').lastElementChild.textContent = 'активных ' + active + ' из ' + ds.length;
      }, function (err) { toast(err.message, 'bad'); });
    }
    return { enter: load };
  })();

  // --- Журнал -------------------------------------------------------------------

  views.journal = (function () {
    var box = document.getElementById('log');
    var live = document.getElementById('log-live');
    var pauseBtn = document.getElementById('log-pause');
    var search = document.getElementById('log-search');
    var unit = 'routerd', level = 7, cursor = '', timer = null, paused = false, entries = [], busy = false;
    var MAX = 1500;
    var LVL = { 0: 'err', 1: 'err', 2: 'err', 3: 'err', 4: 'warn', 5: 'info', 6: 'info', 7: 'dbg' };
    var LVL_TEXT = { err: 'ERR', warn: 'WARN', info: 'INFO', dbg: 'DBG' };

    // Строка slog: level=… msg="…" ключ=значение — уровень, сообщение и пары.
    function parse(e) {
      var m = e.message || '', out = { lvl: LVL[e.priority] || 'info', msg: m || '(запись без текста)', kv: [] };
      var re = /(\S+?)=("(?:[^"\\]|\\.)*"|\S+)/g, mm, found = false, rest = [];
      while ((mm = re.exec(m)) !== null) {
        found = true;
        var k = mm[1].replace(/^"|"$/g, ''), v = mm[2];
        if (v[0] === '"') { try { v = JSON.parse(v); } catch (x) { v = v.slice(1, -1); } }
        if (k === 'level') out.lvl = { ERROR: 'err', WARN: 'warn', INFO: 'info', DEBUG: 'dbg' }[v] || out.lvl;
        else if (k === 'msg') out.msg = v;
        else rest.push([k, v]);
      }
      if (found && /^level=/.test(m)) out.kv = rest; else if (m) out.msg = m;
      return out;
    }

    function mark(parent, text, q) {
      var i = q ? text.toLowerCase().indexOf(q) : -1;
      if (i < 0) { parent.appendChild(document.createTextNode(text)); return; }
      parent.appendChild(document.createTextNode(text.slice(0, i)));
      parent.appendChild(el('mark', '', text.slice(i, i + q.length)));
      parent.appendChild(document.createTextNode(text.slice(i + q.length)));
    }

    function lineEl(e, fresh) {
      var p = e.parsed || (e.parsed = parse(e));
      var row = el('div', 'log-line ' + p.lvl + (fresh ? ' new' : ''));
      var d = new Date(e.time);
      row.appendChild(el('span', 't', d.toLocaleTimeString('ru-RU')));
      row.appendChild(el('span', 'lvl ' + p.lvl, LVL_TEXT[p.lvl]));
      var msg = el('span', 'msg');
      var q = search.value.trim().toLowerCase();
      mark(msg, p.msg, q);
      p.kv.forEach(function (kv) {
        msg.appendChild(document.createTextNode(' '));
        var c = el('span', 'kv');
        c.appendChild(el('b', '', kv[0]));
        c.appendChild(document.createTextNode('='));
        mark(c, String(kv[1]), q);
        msg.appendChild(c);
      });
      row.appendChild(msg);
      row.title = d.toLocaleString('ru-RU');
      return row;
    }

    function visible(e) {
      var p = e.parsed || (e.parsed = parse(e));
      if (level < 7 && !(p.lvl === 'warn' || p.lvl === 'err')) return false;
      var q = search.value.trim().toLowerCase();
      return !q || (e.message || '').toLowerCase().indexOf(q) >= 0;
    }

    function atBottom() { return box.scrollHeight - box.scrollTop - box.clientHeight < 40; }

    function render() {
      var frag = document.createDocumentFragment();
      entries.filter(visible).forEach(function (e) { frag.appendChild(lineEl(e, false)); });
      box.textContent = '';
      box.appendChild(frag);
      box.scrollTop = box.scrollHeight;
    }

    function append(list) {
      var stick = atBottom();
      list.forEach(function (e) {
        entries.push(e);
        if (visible(e)) box.appendChild(lineEl(e, true));
      });
      if (entries.length > MAX) {
        entries = entries.slice(-MAX);
        render();
        return;
      }
      if (stick) box.scrollTop = box.scrollHeight;
    }

    function fetchNew(reset) {
      if (busy) return;
      busy = true;
      var u = '/api/v1/journal?unit=' + unit + (cursor && !reset ? '&cursor=' + encodeURIComponent(cursor) : '&lines=300');
      api('GET', u).then(function (j) {
        if (reset) { entries = []; box.textContent = ''; }
        cursor = j.cursor;
        if (reset) { entries = j.entries; render(); } else if (j.entries.length) append(j.entries);
      }, function (err) { toast(err.message, 'bad'); }).then(function () { busy = false; });
    }

    function poll() {
      if (paused || document.hidden) return;
      fetchNew(false);
    }

    segmented(document.getElementById('log-unit'), 'data-unit', function (u) { unit = u; cursor = ''; fetchNew(true); });
    segmented(document.getElementById('log-level'), 'data-level', function (l) { level = Number(l); render(); });
    var st = null;
    search.addEventListener('input', function () { clearTimeout(st); st = setTimeout(render, 200); });
    pauseBtn.addEventListener('click', function () {
      paused = !paused;
      pauseBtn.textContent = paused ? 'Продолжить' : 'Пауза';
      live.classList.toggle('paused', paused);
      if (!paused) fetchNew(false);
    });

    return {
      enter: function () { fetchNew(!cursor); timer = setInterval(poll, 3000); },
      leave: function () { clearInterval(timer); }
    };
  })();

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
      sum.appendChild(el('span', 'chip chip-ok', '+' + res.added.length + ' добавится'));
      if (res.mode === 'replace') sum.appendChild(el('span', 'chip chip-bad', '−' + res.removed.length + ' удалится'));
      sum.appendChild(el('span', 'chip', res.kept + ' без изменений'));
      if (res.invalid.length) sum.appendChild(el('span', 'chip chip-warn', 'ошибок: ' + res.invalid.length));
      if (res.conflicts.length) sum.appendChild(el('span', 'chip chip-bad', 'конфликтов: ' + res.conflicts.length));
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
