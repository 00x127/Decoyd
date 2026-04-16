const state = {
  tab: 'dashboard',
  monitoring: false,
  logs: [],
  files: [],
  cfg: {},
  filter: 'all',
  q: '',
  unread: 0
}

const el = id => document.getElementById(id)
const all = sel => document.querySelectorAll(sel)

function ts(iso) {
  const d = new Date(iso)
  const p = n => String(n).padStart(2,'0')
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function filesize(b) {
  if (b < 1024) return b + ' B'
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB'
  return (b/1048576).toFixed(1) + ' MB'
}

function etagClass(t) {
  const m = { modified:'etag-modified', deleted:'etag-deleted', moved:'etag-moved', accessed:'etag-accessed', copied:'etag-copied' }
  return m[t] || 'etag-moved'
}

function methodTag(e) {
  if (e.eventType !== 'accessed') return ''
  const lbl = { inotify:'inotify', winevtlog:'event log', atime:'atime' }
  if (e.method) return `<span class="method-tag">${lbl[e.method] || e.method}</span>`
  if (e.tool && e.tool !== 'unknown') return `<span class="method-tag">${e.tool}</span>`
  return ''
}

function toast(type, title, msg) {
  const wrap = el('toasts')
  const t = document.createElement('div')
  t.className = `toast ${type}`
  t.innerHTML = `<span class="tdot"></span><div><div class="ttitle">${title}</div>${msg ? `<div class="tmsg">${msg}</div>` : ''}</div>`
  wrap.appendChild(t)
  setTimeout(() => { t.style.transition = 'opacity 0.3s'; t.style.opacity = '0'; setTimeout(() => t.remove(), 320) }, 4500)
}

function setMonUI(on) {
  state.monitoring = on
  const pill = document.querySelector('.status-pill')
  pill.classList.toggle('on', on)
  el('status-pill-label').textContent = on ? 'Monitoring On' : 'Monitoring Off'
  el('dsh-status').textContent = on ? 'Active' : 'Offline'
  el('toggle-btn').classList.toggle('on', on)
  el('toggle-label').textContent = on ? 'Stop Monitoring' : 'Start Monitoring'
  el('s-monitor').setAttribute('aria-checked', String(on))
}

function setStealthUI(on) {
  el('s-stealth').setAttribute('aria-checked', String(on))
  el('stealth-note').style.display = on ? 'block' : 'none'
  state.cfg.stealthMode = on
}

function setPlatNote() {
  const n = el('plat-note')
  if (!n) return
  const ua = navigator.userAgent
  if (ua.includes('Windows')) n.textContent = 'On this machine: Windows Security Event Log + atime fallback.'
  else if (ua.includes('Linux')) n.textContent = 'On this machine: inotify + atime fallback. Needs inotify-tools.'
  else n.textContent = 'On this machine: atime polling only.'
}

function detailStr(e) {
  if (e.eventType === 'moved' && e.movedTo) return `${e.filePath} -> ${e.movedTo}`
  if (e.eventType === 'copied' && e.copyPath) return `copy at: ${e.copyPath}`
  if (e.eventType === 'accessed') {
    const parts = []
    if (e.tool && e.tool !== 'unknown') parts.push(`by: ${e.tool}`)
    if (e.method) { const l = {inotify:'inotify',winevtlog:'event log',atime:'atime'}; parts.push(`via ${l[e.method]||e.method}`) }
    return parts.length ? `${e.filePath}  [${parts.join(', ')}]` : e.filePath
  }
  return e.filePath
}

function renderRecent() {
  const c = el('recent-list')
  const slice = state.logs.slice(0, 8)
  if (!slice.length) { c.innerHTML = '<div class="empty">No events yet</div>'; return }
  c.innerHTML = slice.map(e => {
    let label = e.fileName
    if (e.eventType === 'moved' && e.movedTo) label = `${e.fileName} moved to ${e.movedTo.split(/[\\/]/).pop()}`
    else if (e.eventType === 'copied' && e.copyPath) label = `${e.fileName} copied to ${e.copyPath.split(/[\\/]/).pop()}`
    else if (e.eventType === 'accessed' && e.tool && e.tool !== 'unknown') label = `${e.fileName} opened by ${e.tool}`
    else if (e.eventType === 'deleted') label = `${e.fileName} was deleted`
    else if (e.eventType === 'modified') label = `${e.fileName} was modified`
    return `<div class="recent-item">
      <span class="etag ${etagClass(e.eventType)}">${e.eventType}</span>
      <span class="event-name" title="${e.filePath}">${label}</span>
      <span class="event-time">${ts(e.timestamp)}</span>
    </div>`
  }).join('')
}

function renderTable() {
  const tbody = el('log-tbody')
  let data = state.logs
  if (state.filter !== 'all') data = data.filter(l => l.eventType === state.filter)
  if (state.q.trim()) {
    const q = state.q.toLowerCase()
    data = data.filter(l =>
      l.fileName.toLowerCase().includes(q) ||
      l.filePath.toLowerCase().includes(q) ||
      (l.movedTo||'').toLowerCase().includes(q) ||
      (l.copyPath||'').toLowerCase().includes(q) ||
      (l.tool||'').toLowerCase().includes(q)
    )
  }
  el('log-count').textContent = `${data.length} ${data.length === 1 ? 'entry' : 'entries'}`
  if (!data.length) { tbody.innerHTML = '<tr><td colspan="4" class="empty-cell">No matching events</td></tr>'; return }
  tbody.innerHTML = data.map(e => {
    const d = detailStr(e)
    return `<tr>
      <td>${ts(e.timestamp)}</td>
      <td>${e.fileName}${methodTag(e)}</td>
      <td><span class="etag ${etagClass(e.eventType)}">${e.eventType}</span></td>
      <td title="${d}">${d}</td>
    </tr>`
  }).join('')
}

function renderFiles() {
  const list = el('active-files')
  el('active-count').textContent = `${state.files.length} file${state.files.length !== 1 ? 's' : ''}`
  const clearAllBtn = el('clear-all-files-btn')
  if (clearAllBtn) clearAllBtn.style.display = state.files.length ? 'inline-flex' : 'none'
  if (!state.files.length) { list.innerHTML = '<div class="empty">No bait files yet</div>'; return }
  list.innerHTML = state.files.map(f => `
    <div class="file-row">
      <span class="file-dot ${f.exists ? 'exists' : 'missing'}" title="${f.exists ? 'Exists' : 'Missing'}"></span>
      <div style="flex:1;min-width:0">
        <div class="file-name">${f.name}</div>
        <div class="file-path">${f.path}</div>
      </div>
      <span class="file-size">${f.exists ? filesize(f.size) : 'missing'}</span>
      <button class="file-del" data-path="${f.path}" title="Remove">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M9 6V4h6v2"/></svg>
      </button>
    </div>`).join('')

  list.querySelectorAll('.file-del').forEach(btn => {
    btn.addEventListener('click', async ev => {
      ev.stopPropagation()
      const fp = btn.dataset.path
      const r = await window.decoyd.deleteBaitFile(fp)
      if (r.error) { toast('err', 'Delete failed', r.error); return }
      state.files = state.files.filter(f => f.path !== fp)
      renderFiles(); updateStats()
      toast('info', 'File removed', fp.split(/[\\/]/).pop())
    })
  })
}

function updateStats() {
  const alive = state.files.filter(f => f.exists).length
  const today = state.logs.filter(l => new Date(l.timestamp).toDateString() === new Date().toDateString()).length
  el('ss-files').textContent = alive
  el('ss-events').textContent = state.logs.length
  el('ss-today').textContent = today
  el('dsh-files').textContent = alive
  el('dsh-today').textContent = today
  el('dsh-total').textContent = state.logs.length
}

function updateBadge() {
  const b = el('log-badge')
  if (state.unread > 0) { b.textContent = state.unread > 99 ? '99+' : state.unread; b.style.display = 'inline-block' }
  else b.style.display = 'none'
}

function switchTab(id) {
  if (state.tab === id) return
  state.tab = id
  all('.nav-item').forEach(b => b.classList.remove('active'))
  all('.tab').forEach(t => t.classList.remove('active'))
  document.querySelector(`[data-tab="${id}"]`).classList.add('active')
  el(`tab-${id}`)?.classList.add('active')
  if (id === 'event-log') { state.unread = 0; updateBadge(); renderTable() }
  if (id === 'bait-files') renderFiles()
  if (id === 'dashboard') renderRecent()
}

function loadCfg(c) {
  state.cfg = c
  el('s-email').setAttribute('aria-checked', String(!!c.emailEnabled))
  el('email-fields').classList.toggle('hidden', !c.emailEnabled)
  el('e-to').value = c.emailTo || ''
  el('e-from').value = c.smtpFrom || ''
  el('e-host').value = c.smtpHost || ''
  el('e-port').value = c.smtpPort || 587
  el('e-user').value = c.smtpUser || ''
  el('e-pass').value = c.smtpPass || ''
  setStealthUI(!!c.stealthMode)
  el('s-reads').setAttribute('aria-checked', String(c.detectReads !== false))
  el('s-copies').setAttribute('aria-checked', String(c.detectCopies !== false))
  el('s-silent').setAttribute('aria-checked', String(!!c.silentAlerts))
}

async function init() {
  setPlatNote()

  const [status, logs, files, cfg] = await Promise.all([
    window.decoyd.getStatus(),
    window.decoyd.getLogs(),
    window.decoyd.getBaitFiles(),
    window.decoyd.getConfig()
  ])

  state.logs = logs
  state.files = files
  setMonUI(status.monitoring)
  loadCfg(cfg)
  updateStats()
  renderRecent()

  all('.nav-item').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)))
  all('[data-tab-link]').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tabLink)))

  el('browse-btn').addEventListener('click', async () => {
    const d = await window.decoyd.selectDirectory()
    if (!d) return
    el('dir-input').value = d
    el('deploy-btn').disabled = false
    el('deploy-hint').textContent = d
  })

  el('deploy-btn').addEventListener('click', async () => {
    const d = el('dir-input').value
    if (!d) return
    const btn = el('deploy-btn')
    btn.disabled = true; btn.textContent = 'Deploying...'
    const r = await window.decoyd.createBaitFiles(d)
    btn.disabled = false
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:15px;height:15px"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Deploy Files`
    if (r.error) { toast('err', 'Failed', r.error); return }
    if (r.created?.length) toast('ok', 'Files deployed', `${r.created.length} file${r.created.length > 1 ? 's' : ''} in ${d}`)
    r.errors?.forEach(e => toast('err', `Failed: ${e.file}`, e.error))
    state.files = await window.decoyd.getBaitFiles()
    renderFiles(); updateStats()
  })

  el('clear-all-files-btn').addEventListener('click', async () => {
    if (!state.files.length) return
    const btn = el('clear-all-files-btn')
    btn.disabled = true
    btn.textContent = 'Clearing...'
    const paths = state.files.map(f => f.path)
    let deleted = 0
    for (const fp of paths) {
      const r = await window.decoyd.deleteBaitFile(fp)
      if (!r.error) { deleted++; state.files = state.files.filter(f => f.path !== fp) }
    }
    btn.disabled = false
    btn.textContent = 'Clear All'
    renderFiles(); updateStats()
    if (deleted > 0) toast('ok', 'All bait files removed', `Deleted ${deleted} file${deleted !== 1 ? 's' : ''}`)
  })

    el('custom-browse-btn').addEventListener('click', async () => {
    const d = await window.decoyd.selectDirectory()
    if (d) { el('custom-dir').value = d; el('custom-hint').textContent = d }
  })

  el('custom-create-btn').addEventListener('click', async () => {
    const name = el('custom-name').value.trim()
    const dir = el('custom-dir').value.trim()
    const content = el('custom-content').value
    if (!name) { toast('err', 'File name required', null); return }
    if (!dir) { toast('err', 'Directory required', 'Click Browse first'); return }
    if (!content) { toast('err', 'Content required', null); return }

    const btn = el('custom-create-btn')
    btn.disabled = true; btn.textContent = 'Creating...'
    const r = await window.decoyd.createCustomBaitFile({ name, dir, content })
    btn.disabled = false
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:15px;height:15px"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Create File`
    if (r.error) { toast('err', 'Failed', r.error); return }
    toast('ok', 'Custom bait file created', r.created)
    el('custom-name').value = ''
    el('custom-content').value = ''
    el('custom-hint').textContent = 'Name, directory and content required'
    state.files = await window.decoyd.getBaitFiles()
    renderFiles(); updateStats()
  })

  async function doToggle(val) {
    const r = await window.decoyd.toggleMonitoring(val)
    if (r.error) { toast('err', 'Error', r.error); setMonUI(false); return }
    setMonUI(r.monitoring)
    const fc = state.files.filter(f => f.exists).length
    toast(r.monitoring ? 'ok' : 'info',
      r.monitoring ? 'Monitoring started' : 'Monitoring stopped',
      r.monitoring ? `Watching ${fc} file${fc !== 1 ? 's' : ''}` : 'All watchers stopped'
    )
  }

  el('toggle-btn').addEventListener('click', () => doToggle(!state.monitoring))
  el('s-monitor').addEventListener('click', function() { doToggle(this.getAttribute('aria-checked') !== 'true') })

  el('s-stealth').addEventListener('click', async function() {
    const next = this.getAttribute('aria-checked') !== 'true'
    setStealthUI(next)
    await window.decoyd.saveConfig(Object.assign({}, state.cfg, { stealthMode: next }))
    toast('info', next ? 'Stealth mode on' : 'Stealth mode off', next ? 'Window hides to tray on close' : 'App closes normally')
  })

  el('s-silent').addEventListener('click', async function() {
    const next = this.getAttribute('aria-checked') !== 'true'
    this.setAttribute('aria-checked', String(next))
    state.cfg.silentAlerts = next
    await window.decoyd.saveConfig(Object.assign({}, state.cfg, { silentAlerts: next }))
    toast('info', next ? 'Silent mode on' : 'Silent mode off', next ? 'Notifications suppressed' : 'Notifications enabled')
  })

  el('s-reads').addEventListener('click', function() {
    const next = this.getAttribute('aria-checked') !== 'true'
    this.setAttribute('aria-checked', String(next))
    state.cfg.detectReads = next
  })

  el('s-copies').addEventListener('click', function() {
    const next = this.getAttribute('aria-checked') !== 'true'
    this.setAttribute('aria-checked', String(next))
    state.cfg.detectCopies = next
  })

  async function clearAll() {
    if (!state.logs.length) { toast('info', 'Already empty', null); return }
    const r = await window.decoyd.clearLogs()
    if (!r.success) return
    state.logs = []; state.unread = 0
    updateStats(); renderRecent(); renderTable(); updateBadge()
    toast('ok', 'Logs cleared', null)
  }

  el('clear-btn').addEventListener('click', clearAll)
  el('clear-log-btn').addEventListener('click', clearAll)
  el('danger-clear').addEventListener('click', clearAll)

  el('export-btn').addEventListener('click', () => {
    if (!state.logs.length) { toast('info', 'Nothing to export', null); return }
    const lines = ['timestamp,fileName,eventType,filePath,movedTo,copyPath,tool,method']
    state.logs.forEach(l => {
      const s = v => `"${String(v||'').replace(/"/g,'""')}"`
      lines.push([s(l.timestamp),s(l.fileName),s(l.eventType),s(l.filePath),s(l.movedTo),s(l.copyPath),s(l.tool),s(l.method)].join(','))
    })
    const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' }))
    const a = document.createElement('a')
    a.href = url; a.download = `decoyd-${new Date().toISOString().slice(0,10)}.csv`
    a.click(); URL.revokeObjectURL(url)
    toast('ok', 'Exported', `${state.logs.length} events`)
  })

  all('.filter').forEach(b => b.addEventListener('click', () => {
    all('.filter').forEach(x => x.classList.remove('active'))
    b.classList.add('active')
    state.filter = b.dataset.filter
    renderTable()
  }))

  el('log-search').addEventListener('input', e => { state.q = e.target.value; renderTable() })

  el('s-email').addEventListener('click', function() {
    const next = this.getAttribute('aria-checked') !== 'true'
    this.setAttribute('aria-checked', String(next))
    el('email-fields').classList.toggle('hidden', !next)
    state.cfg.emailEnabled = next
  })

  el('save-btn').addEventListener('click', async () => {
    const c = {
      emailEnabled: el('s-email').getAttribute('aria-checked') === 'true',
      emailTo: el('e-to').value.trim(),
      smtpFrom: el('e-from').value.trim(),
      smtpHost: el('e-host').value.trim(),
      smtpPort: parseInt(el('e-port').value) || 587,
      smtpUser: el('e-user').value.trim(),
      smtpPass: el('e-pass').value,
      stealthMode: el('s-stealth').getAttribute('aria-checked') === 'true',
      detectReads: el('s-reads').getAttribute('aria-checked') === 'true',
      detectCopies: el('s-copies').getAttribute('aria-checked') === 'true',
      silentAlerts: el('s-silent').getAttribute('aria-checked') === 'true'
    }
    const r = await window.decoyd.saveConfig(c)
    if (r.success) {
      const ok = el('save-ok'); ok.textContent = 'Saved'
      setTimeout(() => { ok.textContent = '' }, 2500)
      toast('ok', 'Settings saved', null)
    } else toast('err', 'Save failed', r.error)
  })

  window.decoyd.on('log-added', entry => {
    state.logs.unshift(entry)
    if (state.logs.length > 2000) state.logs = state.logs.slice(0, 2000)
    if (state.tab !== 'event-log') { state.unread++; updateBadge() } else renderTable()
    if (state.tab === 'dashboard') renderRecent()
    updateStats()

    let msg
    if (entry.eventType === 'accessed') msg = entry.tool && entry.tool !== 'unknown' ? `${entry.fileName} opened by ${entry.tool}` : `${entry.fileName} was read`
    else if (entry.eventType === 'copied') msg = `${entry.fileName} copied to ${(entry.copyPath||'').split(/[\\/]/).pop()}`
    else if (entry.eventType === 'moved' && entry.movedTo) msg = `${entry.fileName} moved to ${entry.movedTo.split(/[\\/]/).pop()}`
    else if (entry.eventType === 'deleted') msg = `${entry.fileName} was deleted`
    else msg = `${entry.fileName} was ${entry.eventType}`
    toast('alert', 'Intrusion detected', msg)
  })

  window.decoyd.on('bait-file-removed', async () => {
    state.files = await window.decoyd.getBaitFiles()
    if (state.tab === 'bait-files') renderFiles()
    updateStats()
  })

  window.decoyd.on('watcher-error', msg => toast('err', 'Watcher error', msg))
}

document.addEventListener('DOMContentLoaded', init)
