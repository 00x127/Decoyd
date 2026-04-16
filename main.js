const { app, BrowserWindow, ipcMain, Notification, dialog, Menu, Tray, nativeImage } = require('electron')
const path = require('path')
const fs = require('fs')
const os = require('os')
const zlib = require('zlib')
const crypto = require('crypto')
const { execFile, spawn } = require('child_process')
let _chokidar, _nodemailer, _XLSX
function getChokidar() { if (!_chokidar) _chokidar = require('chokidar'); return _chokidar }
function getNodemailer() { if (!_nodemailer) _nodemailer = require('nodemailer'); return _nodemailer }
function getXLSX() { if (!_XLSX) _XLSX = require('xlsx'); return _XLSX }

app.setName('Decoyd')
app.setAppUserModelId('com.decoyd.app')

let win = null
let tray = null
let watcher = null
let copyWatcher = null
let monitoring = false
let quiting = false

const IS_WIN = process.platform === 'win32'
const IS_MAC = process.platform === 'darwin'
const IS_LIN = process.platform === 'linux'

const userDataDir = app.getPath('userData')
const logsPath = path.join(userDataDir, 'logs.json')
const cfgPath = path.join(userDataDir, 'config.json')
const manifestPath = path.join(userDataDir, 'manifest.json')

const unlinkTimers = new Map()
const backdatingFiles = new Set()
const recentMoveTargets = new Set()
const atimeCached = new Map()
const atimePollMap = new Map()
const inotifyMap = new Map()
let inotifywaitAvailable = null
const winAuditMap = new Map()
const fileHashes = new Map()

let logs = []
let settings = {
  emailEnabled: false,
  emailTo: '',
  smtpHost: '',
  smtpPort: 587,
  smtpUser: '',
  smtpPass: '',
  smtpFrom: '',
  stealthMode: false,
  detectReads: true,
  detectCopies: true,
  silentAlerts: false
}
let manifest = { files: [] }

const crcLookup = (() => {
  const t = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let j = 0; j < 8; j++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1
    t[i] = c
  }
  return t
})()

function crc32(buf) {
  let n = 0xFFFFFFFF
  for (const b of buf) n = crcLookup[(n ^ b) & 0xFF] ^ (n >>> 8)
  return (n ^ 0xFFFFFFFF) >>> 0
}

function pngChunk(tag, data) {
  const lenBuf = Buffer.alloc(4)
  lenBuf.writeUInt32BE(data.length)
  const tagBuf = Buffer.from(tag)
  const crcVal = Buffer.alloc(4)
  crcVal.writeUInt32BE(crc32(Buffer.concat([tagBuf, data])))
  return Buffer.concat([lenBuf, tagBuf, data, crcVal])
}

function makeFallbackPNG(r, g, b, size) {
  const sig = Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4)
  ihdr[8] = 8; ihdr[9] = 2
  const row = Buffer.alloc(1 + size * 3)
  row[0] = 0
  for (let x = 0; x < size; x++) { row[1+x*3]=r; row[2+x*3]=g; row[3+x*3]=b }
  const rawRows = []
  for (let y = 0; y < size; y++) rawRows.push(row)
  return Buffer.concat([
    sig,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(Buffer.concat(rawRows))),
    pngChunk('IEND', Buffer.alloc(0))
  ])
}

function loadTrayIcon() {
  const candidates = [
    path.join(__dirname, 'build', 'icon.png'),
    path.join(__dirname, 'build', 'icon.ico')
  ]
  for (const p of candidates) {
    if (!fs.existsSync(p)) continue
    const img = nativeImage.createFromPath(p)
    if (!img.isEmpty()) return img.resize({ width: 16, height: 16 })
  }
  return nativeImage.createFromBuffer(makeFallbackPNG(124, 109, 250, 16), { scaleFactor: 1 })
}

function getWindowIcon() {
  if (IS_WIN) {
    const ico = path.join(__dirname, 'build', 'icon.ico')
    if (fs.existsSync(ico)) return ico
  }
  if (IS_MAC) {
    const icns = path.join(__dirname, 'build', 'icon.icns')
    if (fs.existsSync(icns)) return icns
  }
  const png = path.join(__dirname, 'build', 'icon.png')
  if (fs.existsSync(png)) return png
  return null
}

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true })
}

function readLogs() {
  try {
    if (fs.existsSync(logsPath)) logs = JSON.parse(fs.readFileSync(logsPath, 'utf8'))
  } catch { logs = [] }
}

function writeLogs() {
  try { fs.writeFileSync(logsPath, JSON.stringify(logs, null, 2)) } catch {}
}

function readSettings() {
  try {
    if (fs.existsSync(cfgPath))
      settings = Object.assign({}, settings, JSON.parse(fs.readFileSync(cfgPath, 'utf8')))
  } catch {}
}

function writeSettings() {
  try { fs.writeFileSync(cfgPath, JSON.stringify(settings, null, 2)) } catch {}
}

function readManifest() {
  try {
    if (fs.existsSync(manifestPath)) manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
  } catch { manifest = { files: [] } }
}

function writeManifest() {
  try { fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2)) } catch {}
}

function hashFile(fp) {
  try { return crypto.createHash('sha256').update(fs.readFileSync(fp)).digest('hex') }
  catch { return null }
}

function rebuildHashes() {
  fileHashes.clear()
  for (const fp of manifest.files) {
    const h = hashFile(fp)
    if (h) fileHashes.set(h, fp)
  }
}

function logEvent(filePath, type, extras) {
  const e = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    timestamp: new Date().toISOString(),
    filePath,
    fileName: path.basename(filePath),
    eventType: type
  }
  if (extras) Object.assign(e, extras)
  logs.unshift(e)
  if (logs.length > 2000) logs = logs.slice(0, 2000)
  writeLogs()
  if (win && !win.isDestroyed()) win.webContents.send('log-added', e)
  refreshTray()
  notify(filePath, type, extras)
}

function notify(filePath, type, extras) {
  if (!settings.silentAlerts) {
    try {
      if (Notification.isSupported()) {
        let body = `${type}: ${path.basename(filePath)}`
        if (type === 'deleted') body = `Deleted: ${path.basename(filePath)}`
        else if (type === 'modified') body = `Modified: ${path.basename(filePath)}`
        else if (type === 'moved' && extras?.movedTo) body = `Moved to: ${extras.movedTo}`
        else if (type === 'accessed') body = `Read: ${path.basename(filePath)}${extras?.tool ? ` (${extras.tool})` : ''}`
        else if (type === 'copied' && extras?.copyPath) body = `Copied to: ${path.basename(extras.copyPath)}`

        const iconFile = getWindowIcon()
        const opts = { title: 'Decoyd - Intrusion Detected', body, urgency: 'critical' }
        if (iconFile) opts.icon = iconFile

        const n = new Notification(opts)
        n.on('click', () => { if (win) { win.show(); win.focus() } })
        n.show()
      }
    } catch {}
  }

  if (settings.emailEnabled && settings.emailTo && settings.smtpHost) {
    sendAlert(filePath, type, extras)
  }
}

function sendAlert(filePath, type, extras) {
  const transportCfg = {
    host: settings.smtpHost,
    port: parseInt(settings.smtpPort) || 587,
    secure: parseInt(settings.smtpPort) === 465
  }
  if (settings.smtpUser) transportCfg.auth = { user: settings.smtpUser, pass: settings.smtpPass }

  const label = type[0].toUpperCase() + type.slice(1)
  const lines = [
    'Decoyd detected activity on a monitored bait file.',
    '',
    `Event:     ${label}`,
    `File:      ${path.basename(filePath)}`,
    `Full path: ${filePath}`
  ]
  if (extras?.movedTo) lines.push(`Moved to:  ${extras.movedTo}`)
  if (extras?.copyPath) lines.push(`Copy at:   ${extras.copyPath}`)
  if (extras?.tool) lines.push(`Tool:      ${extras.tool}`)
  lines.push(`Time:      ${new Date().toLocaleString()}`, `Host:      ${os.hostname()}`, '', 'Check your system immediately.')

  getNodemailer().createTransport(transportCfg).sendMail({
    from: settings.smtpFrom || settings.smtpUser || 'decoyd@localhost',
    to: settings.emailTo,
    subject: `[Decoyd] ${label}: ${path.basename(filePath)}`,
    text: lines.join('\n')
  }).catch(() => {})
}

function checkMoved(name, origPath, origHash) {
  const places = [
    os.homedir(),
    path.join(os.homedir(), 'Desktop'),
    path.join(os.homedir(), 'Documents'),
    path.join(os.homedir(), 'Downloads'),
    path.join(os.homedir(), 'OneDrive'),
    path.join(os.homedir(), 'OneDrive', 'Desktop'),
    path.join(os.homedir(), 'OneDrive', 'Documents'),
    os.tmpdir()
  ]
  for (const d of places) {
    try {
      const candidate = path.join(d, name)
      if (candidate === origPath || !fs.existsSync(candidate)) continue
      const h = hashFile(candidate)
      if (h && h === origHash) return candidate
    } catch {}
  }
  return null
}

function backdateAtime(fp) {
  try {
    const stat = fs.statSync(fp)
    const oldDate = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000)
    backdatingFiles.add(fp)
    fs.utimesSync(fp, oldDate, stat.mtime)
    setTimeout(() => backdatingFiles.delete(fp), 1500)
    return oldDate.getTime()
  } catch { return null }
}

function startAtimePoll(fp) {
  stopAtimePoll(fp)
  if (backdateAtime(fp) === null) return
  const t = setTimeout(() => {
    try { atimeCached.set(fp, fs.statSync(fp).atimeMs) } catch { return }
    const interval = setInterval(() => {
      if (!manifest.files.includes(fp)) { stopAtimePoll(fp); return }
      try {
        const now = fs.statSync(fp).atimeMs
        const prev = atimeCached.get(fp)
        if (prev !== undefined && now > prev + 500) {
          atimeCached.set(fp, now)
          logEvent(fp, 'accessed', { method: 'atime' })
        }
      } catch { stopAtimePoll(fp) }
    }, 3000)
    atimePollMap.set(fp, interval)
  }, 7000)
  atimePollMap.set(fp, t)
}

function stopAtimePoll(fp) {
  const t = atimePollMap.get(fp)
  if (t) { clearInterval(t); clearTimeout(t); atimePollMap.delete(fp) }
  atimeCached.delete(fp)
}

function startInotify(fp) {
  if (!IS_LIN) return
  stopInotify(fp)
  if (inotifywaitAvailable === false) return
  if (inotifywaitAvailable === null) {
    execFile('which', ['inotifywait'], err => {
      inotifywaitAvailable = !err
      if (!err) startInotify(fp)
    })
    return
  }
  const proc = spawn('inotifywait', ['-m', '-q', '-e', 'access,open', '--format', '%e %f', fp])
  proc.stdout.on('data', chunk => {
    const line = chunk.toString().trim()
    if (!line) return
    const events = (line.split(' ')[0] || '').split(',')
    if (!events.includes('ACCESS') && !events.includes('OPEN')) return
    let tool = null
    try {
      const out = require('child_process').execSync(
        `lsof -n -p $(lsof "${fp}" 2>/dev/null | awk 'NR>1{print $2}' | head -1) 2>/dev/null | awk 'NR==2{print $1}'`,
        { timeout: 500 }
      ).toString().trim()
      if (out) tool = out
    } catch {}
    logEvent(fp, 'accessed', { method: 'inotify', tool })
  })
  proc.on('error', () => {})
  proc.on('exit', () => inotifyMap.delete(fp))
  inotifyMap.set(fp, proc)
}

function stopInotify(fp) {
  const p = inotifyMap.get(fp)
  if (p) { try { p.kill() } catch {}; inotifyMap.delete(fp) }
}

function startWinAudit(fp) {
  if (!IS_WIN) return
  stopWinAudit(fp)

  const esc = fp.replace(/\\/g, '\\\\')
  const psSetup = [
    'auditpol /set /subcategory:"File System" /success:enable | Out-Null',
    `$p="${esc}"`,
    '$a=Get-Acl -Path $p -Audit',
    '$r=New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","ReadData,ExecuteFile","None","None","Success")',
    '$a.SetAuditRule($r)',
    'Set-Acl -Path $p -AclObject $a'
  ].join('; ')

  backdatingFiles.add(fp)

  const name = path.basename(fp).replace(/'/g, "''")
  const seen = new Set()

  const sysprocs = new Set([
    'decoyd.exe', 'electron.exe',
    'msmpeng.exe', 'msmplau.exe', 'mpcmdrun.exe', 'nissrv.exe', 'securityhealthservice.exe',
    'searchindexer.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',
    'svchost.exe', 'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'tiworker.exe', 'trustedinstaller.exe', 'wuauclt.exe', 'backgroundtaskhost.exe',
    'taskhostw.exe', 'runtimebroker.exe', 'dllhost.exe', 'musnotification.exe'
  ])

  let liveFrom = null

  execFile('powershell', ['-NonInteractive', '-WindowStyle', 'Hidden', '-Command', psSetup], { timeout: 10000 }, err => {
    setTimeout(() => backdatingFiles.delete(fp), 2000)
    liveFrom = new Date(Date.now() + 6000)
    if (err) startAtimePoll(fp)
  })

  const poll = () => {
    if (!manifest.files.includes(fp)) { clearInterval(timer); winAuditMap.delete(fp); return }
    if (!liveFrom || Date.now() < liveFrom.getTime()) return

    const after = liveFrom.toISOString()
    const psQuery = [
      `$after=[System.DateTime]::Parse("${after}").ToUniversalTime()`,
      `$evts=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663;StartTime=$after} -ErrorAction SilentlyContinue`,
      `if($evts){$evts|Where-Object{$_.Message -like '*${name}*' -and ($_.Message -like '*ReadData*' -or $_.Message -like '*%%4416*')}|Select-Object -First 20|ForEach-Object{$m=$_.Message;$proc=if($m -match 'Process Name:\\s+([^\\r\\n]+)'){$matches[1].Trim()}else{'unknown'};Write-Output('HIT|'+$_.TimeCreated.ToUniversalTime().ToString('o')+'|'+$proc)}}`
    ].join('; ')

    execFile('powershell', ['-NonInteractive', '-WindowStyle', 'Hidden', '-Command', psQuery], { timeout: 8000 }, (err, stdout) => {
      if (err || !stdout.trim()) return
      for (const line of stdout.trim().split('\n')) {
        if (!line.startsWith('HIT|')) continue
        const parts = line.split('|')
        const evtKey = `${fp}:${(parts[1] || '').trim()}`
        if (seen.has(evtKey)) continue
        seen.add(evtKey)
        if (seen.size > 500) seen.delete(seen.values().next().value)
        const tool = (parts[2] || 'unknown').trim()
        if (sysprocs.has(path.basename(tool).toLowerCase())) continue
        logEvent(fp, 'accessed', { method: 'winevtlog', tool })
      }
    })
  }

  const timer = setInterval(poll, 5000)
  winAuditMap.set(fp, timer)
}
function stopWinAudit(fp) {
  const t = winAuditMap.get(fp)
  if (t) { clearInterval(t); winAuditMap.delete(fp) }
}

function startReadWatch(fp) {
  if (!settings.detectReads) return
  if (IS_LIN) { startInotify(fp); startAtimePoll(fp) }
  else if (IS_WIN) { startWinAudit(fp) }
  else startAtimePoll(fp)
}

function stopReadWatch(fp) {
  stopAtimePoll(fp)
  stopInotify(fp)
  stopWinAudit(fp)
}

function killAllReadWatches() {
  atimePollMap.forEach(t => { clearInterval(t); clearTimeout(t) })
  atimePollMap.clear()
  atimeCached.clear()
  inotifyMap.forEach(p => { try { p.kill() } catch {} })
  inotifyMap.clear()
  winAuditMap.forEach(t => clearInterval(t))
  winAuditMap.clear()
}

function dirsToWatchForCopies() {
  const set = new Set([
    os.homedir(),
    path.join(os.homedir(), 'Desktop'),
    path.join(os.homedir(), 'Documents'),
    path.join(os.homedir(), 'Downloads'),
    os.tmpdir()
  ])
  if (IS_WIN) {
    const od = path.join(os.homedir(), 'OneDrive')
    if (fs.existsSync(od)) {
      set.add(od)
      set.add(path.join(od, 'Desktop'))
      set.add(path.join(od, 'Documents'))
    }
    const db = path.join(os.homedir(), 'Dropbox')
    if (fs.existsSync(db)) set.add(db)
  }
  if (IS_MAC) {
    const ic = path.join(os.homedir(), 'Library', 'Mobile Documents', 'com~apple~CloudDocs')
    if (fs.existsSync(ic)) set.add(ic)
  }
  manifest.files.forEach(f => set.add(path.dirname(f)))
  return Array.from(set).filter(d => { try { fs.accessSync(d); return true } catch { return false } })
}

function startCopyWatch() {
  if (!settings.detectCopies) return
  stopCopyWatch()
  rebuildHashes()
  if (fileHashes.size === 0) return

  const myFiles = new Set(manifest.files)
  copyWatcher = getChokidar().watch(dirsToWatchForCopies(), {
    persistent: true,
    depth: 1,
    ignoreInitial: true,
    usePolling: false,
    awaitWriteFinish: { stabilityThreshold: 800, pollInterval: 150 },
    disableGlobbing: true,
    ignored: [/node_modules/, /\.git/, /AppData[\\\/]Local[\\\/]Temp/, /\.tmp$/, /~\$/]
  })

  copyWatcher.on('add', newFile => {
    if (myFiles.has(newFile)) return
    try {
      if (fs.statSync(newFile).size < 50) return
      const h = hashFile(newFile)
      if (!h) return
      const orig = fileHashes.get(h)
      if (!orig) return
      if (!fs.existsSync(orig)) return
      logEvent(orig, 'copied', { copyPath: newFile })
    } catch {}
  })

  copyWatcher.on('error', () => {})
}

function stopCopyWatch() {
  if (copyWatcher) { copyWatcher.close(); copyWatcher = null }
}

function buildPasswords() {
  const d = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
  return [
    '=== Personal Passwords - CONFIDENTIAL ===',
    `Last updated: ${d}`, '',
    '[Minecraft / 2b2t]',
    'Minecraft (main):', '  User: 0x127', '  Pass: relaPass38!', '',
    'Minecraft (alt):', '  User: popbob_fan2b2t', '  Pass: nether_h1ghway!', '',
    '2b2t Forum:', '  User: 0x127', '  Pass: F@rmW0rld2b2t!', '',
    '[Email]',
    'Gmail:', '  User: 0x127.mc@gmail.com', '  Pass: Tr0ub4dor&3_Pers', '',
    'Gmail (work):', '  User: dev.0x127@meridian-tech.com', '  Pass: W0rkP@$$2024!', '',
    '[Banking]',
    'Wells Fargo:', '  Username: 0x127bank', '  Password: W3ll$F@rg0_safe', '  PIN: 2127', '',
    'Chase:', '  Username: 0x127.chase@email.com', '  Password: cH@se$3cur3!99', '  PIN: 8492', '',
    '[Crypto]',
    'Coinbase: 0x127.mc@gmail.com / C01nb@se_popb0b!',
    'Binance:  0x127crypto / B1n@nce$ecure_2b2t', '',
    '[Social]',
    'Twitter/X: @0x127 / Tw1tt3r$ecure_nether!',
    'Discord:   0x127#0001 / D1sc0rd_2b2t_s3rv3r!', '',
    '[Other]',
    'Amazon:   0x127.mc@gmail.com / Am@z0nPr1me!',
    'PayPal:   0x127.mc@gmail.com / P@yP@l_relaPass!',
    'Apple ID: 0x127.mc@gmail.com / @ppleID_2024'
  ].join('\n')
}

function buildWallet() {
  return JSON.stringify({
    version: 3,
    created: '2024-11-17T09:14:22.000Z',
    last_backup: new Date().toISOString(),
    wallet_name: '0x127 Main Wallet',
    label: 'personal - DO NOT SHARE',
    mnemonic: 'popbob nether highway stash diamond sword anarchy vault 2b2t relapass tunnel griefing spawn',
    passphrase: 'relaPass38!_doNotUse',
    addresses: [
      { path: "m/44'/0'/0'/0/0", coin: 'BTC', address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', balance: '1.48291047', usd_value: '91204.33', label: '0x127 BTC main' },
      { path: "m/44'/60'/0'/0/0", coin: 'ETH', address: '0x742d35Cc6634C0532925a3b8D4C9B2A8c1e7F321', balance: '4.88192000', usd_value: '13042.17', label: '0x127 ETH main' }
    ],
    exchange_accounts: [
      { exchange: 'Coinbase', username: '0x127.mc@gmail.com', api_key: 'KzR3nX7pQm2vL9sT4wY8uE6jB1cA5hF0dW', api_secret: 'dG9wU2VjcmV0S2V5RG9Ob3RTaGFyZVRoaXNLZXk=' }
    ],
    notes: 'popbob stash coords: -12847 / 64 / 339482 (nether)',
    total_portfolio_usd: '126746.50'
  }, null, 2)
}

function buildAccountsXlsx() {
  const XLSX = getXLSX()
  const wb = XLSX.utils.book_new()

  const creds = [
    ['Service', 'URL', 'Username / Email', 'Password', 'Notes'],
    ['Gmail', 'https://mail.google.com', '0x127.mc@gmail.com', 'Tr0ub4dor&3_relaPass', 'Recovery: +1-555-0127'],
    ['Minecraft / TLauncher', 'https://tlauncher.org', '0x127', 'relaPass38!', 'main - 2b2t'],
    ['2b2t Forum', 'https://2b2t.miraheze.org', '0x127', 'F@rmW0rld2b2t!', 'popbob fan page'],
    ['Discord', 'https://discord.com', '0x127#0001', 'D1sc0rd_2b2t_s3rv3r!', '2b2t anarchy server'],
    ['Chase Bank', 'https://chase.com', '0x127.chase@email.com', 'cH@se$3cur3!99', 'PIN: 2127'],
    ['Coinbase', 'https://coinbase.com', '0x127.mc@gmail.com', 'C01nb@se_popb0b!', '2FA: Authenticator'],
    ['Amazon', 'https://amazon.com', '0x127.mc@gmail.com', 'Am@z0nPr1me_nether!', 'Prime'],
    ['Apple ID', 'https://appleid.apple.com', '0x127.mc@gmail.com', '@ppleID_relaPass38', '2FA enabled'],
    ['AWS', 'https://aws.amazon.com', '0x127-dev', '@ws_C0ns0le_2b2t!', 'Account: 012748293910']
  ]
  const ws1 = XLSX.utils.aoa_to_sheet(creds)
  ws1['!cols'] = [{ wch: 20 }, { wch: 32 }, { wch: 34 }, { wch: 24 }, { wch: 28 }]
  XLSX.utils.book_append_sheet(wb, ws1, 'Login Credentials')

  const sensitive = [
    ['Category', 'Item', 'Value'],
    ['Credit Card', 'Chase Sapphire (ending 2127)', '4916 3829 4710 2127 | CVV: 127 | Exp: 12/27'],
    ['Identity', 'SSN - 0x127 (real name redacted)', '527-01-2700'],
    ['Minecraft Coords', 'popbob stash (nether)', 'X: -12847  Z: 339482  Y: 64'],
    ['Minecraft Coords', '0x127 base (overworld)', 'X: 1274839  Z: -882941  Y: 61'],
    ['Network', 'Home WiFi Password', 'relaPass38!_wifi'],
    ['Physical', 'Home Safe Combination', '01-27-00']
  ]
  const ws2 = XLSX.utils.aoa_to_sheet(sensitive)
  ws2['!cols'] = [{ wch: 18 }, { wch: 34 }, { wch: 44 }]
  XLSX.utils.book_append_sheet(wb, ws2, 'Sensitive Info')

  return wb
}

async function deployDefaultFiles(dir) {
  const ok = [], fail = []

  try {
    fs.writeFileSync(path.join(dir, 'passwords.txt'), buildPasswords(), 'utf8')
    ok.push(path.join(dir, 'passwords.txt'))
  } catch(e) { fail.push({ file: 'passwords.txt', error: e.message }) }

  try {
    fs.writeFileSync(path.join(dir, 'wallet_backup.json'), buildWallet(), 'utf8')
    ok.push(path.join(dir, 'wallet_backup.json'))
  } catch(e) { fail.push({ file: 'wallet_backup.json', error: e.message }) }

  try {
    getXLSX().writeFile(buildAccountsXlsx(), path.join(dir, 'accounts.xlsx'))
    ok.push(path.join(dir, 'accounts.xlsx'))
  } catch(e) { fail.push({ file: 'accounts.xlsx', error: e.message }) }

  if (ok.length) {
    const s = new Set(manifest.files)
    ok.forEach(p => s.add(p))
    manifest.files = Array.from(s)
    writeManifest()
  }
  return { created: ok, errors: fail }
}

function hotAddFiles(paths) {
  if (!monitoring || !watcher) return
  const added = []
  for (const fp of paths) {
    try { fs.accessSync(fp) } catch { continue }
    if (winAuditMap.has(fp) || atimePollMap.has(fp) || inotifyMap.has(fp)) continue
    watcher.add(fp)
    startReadWatch(fp)
    added.push(fp)
  }
  for (const fp of added) {
    const h = hashFile(fp)
    if (h) fileHashes.set(h, fp)
  }
  if (settings.detectCopies) {
    if (copyWatcher) {
      for (const fp of added) {
        const d = path.dirname(fp)
        try { fs.accessSync(d); copyWatcher.add(d) } catch {}
      }
    } else if (fileHashes.size > 0) {
      startCopyWatch()
    }
  }
}

function startMonitoring() {
  if (watcher) { watcher.close(); watcher = null }

  const targets = manifest.files.filter(f => {
    try { fs.accessSync(f); return true } catch { return false }
  })

  if (!targets.length) { monitoring = false; return false }

  watcher = getChokidar().watch(targets, {
    persistent: true,
    usePolling: false,
    awaitWriteFinish: { stabilityThreshold: 500, pollInterval: 100 },
    ignoreInitial: true,
    disableGlobbing: true
  })

  watcher.on('change', fp => {
    if (backdatingFiles.has(fp)) return
    if (manifest.files.includes(fp)) logEvent(fp, 'modified', null)
  })

  watcher.on('unlink', fp => {
    if (!manifest.files.includes(fp)) return
    const savedHash = [...fileHashes.entries()].find(([, p]) => p === fp)?.[0] ?? null
    stopReadWatch(fp)
    if (unlinkTimers.has(fp)) clearTimeout(unlinkTimers.get(fp))
    unlinkTimers.set(fp, setTimeout(() => {
      unlinkTimers.delete(fp)
      const dest = checkMoved(path.basename(fp), fp, savedHash)
      if (dest) {
        recentMoveTargets.add(dest)
        setTimeout(() => recentMoveTargets.delete(dest), 6000)
      }
      logEvent(fp, dest ? 'moved' : 'deleted', dest ? { movedTo: dest } : null)
      manifest.files = manifest.files.filter(f => f !== fp)
      fileHashes.forEach((orig, h) => { if (orig === fp) fileHashes.delete(h) })
      writeManifest()
      if (win && !win.isDestroyed()) win.webContents.send('bait-file-removed', fp)
    }, 1200))
  })

  watcher.on('error', err => {
    if (win && !win.isDestroyed()) win.webContents.send('watcher-error', err.message)
  })

  targets.forEach(fp => startReadWatch(fp))
  startCopyWatch()
  monitoring = true
  refreshTray()
  return true
}

function stopMonitoring() {
  unlinkTimers.forEach(t => clearTimeout(t))
  unlinkTimers.clear()
  if (watcher) { watcher.close(); watcher = null }
  killAllReadWatches()
  stopCopyWatch()
  monitoring = false
  refreshTray()
}

function refreshTray() {
  if (!tray) return
  const showLabel = win?.isVisible() ? 'Hide Window' : 'Show Decoyd'
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: showLabel, click: () => {
      if (!win) return
      if (win.isVisible()) win.hide()
      else { win.show(); win.focus() }
      refreshTray()
    }},
    { label: monitoring ? '● Monitoring Active' : '○ Monitoring Off', enabled: false },
    { type: 'separator' },
    { label: 'Quit', click: () => { quiting = true; app.quit() } }
  ]))
  tray.setToolTip(monitoring ? 'Decoyd - Active' : 'Decoyd - Idle')
}

function createTray() {
  tray = new Tray(loadTrayIcon())
  tray.on('click', () => {
    if (!win) return
    if (win.isVisible()) win.focus()
    else { win.show(); win.focus() }
    refreshTray()
  })
  refreshTray()
}

function createWindow() {
  Menu.setApplicationMenu(null)

  const iconFile = getWindowIcon()
  const opts = {
    width: 1120, height: 760,
    minWidth: 820, minHeight: 580,
    backgroundColor: '#0d0f1a',
    titleBarStyle: IS_MAC ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false
    }
  }
  if (iconFile) opts.icon = iconFile

  if (settings.stealthMode) {
    opts.show = false
    opts.skipTaskbar = true
  }

  win = new BrowserWindow(opts)
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'))

  win.on('close', e => {
    if (!quiting && settings.stealthMode) {
      e.preventDefault()
      win.hide()
      refreshTray()
    }
  })

  win.on('show', refreshTray)
  win.on('hide', refreshTray)
  win.on('closed', () => { win = null })
}

app.whenReady().then(() => {
  ensureDir(userDataDir)
  readLogs()
  readSettings()
  readManifest()
  createTray()
  createWindow()
  if (settings.stealthMode && win) {
    win.setSkipTaskbar(true)
    win.hide()
  }
  app.on('activate', () => {
    if (!BrowserWindow.getAllWindows().length) createWindow()
    else win?.show()
  })
})

app.on('before-quit', () => { quiting = true })
app.on('window-all-closed', () => { stopMonitoring(); if (!IS_MAC) app.quit() })

ipcMain.handle('create-bait-files', async (_e, dir) => {
  if (typeof dir !== 'string' || !dir.trim()) return { error: 'No directory specified' }
  const norm = path.normalize(dir)
  try { fs.accessSync(norm, fs.constants.W_OK) } catch { return { error: 'Cannot write to that directory' } }
  try {
    const res = await deployDefaultFiles(norm)
    if (monitoring && res.created?.length) hotAddFiles(res.created)
    else rebuildHashes()
    return res
  } catch(e) { return { error: e.message } }
})

ipcMain.handle('create-custom-bait-file', async (_e, opts) => {
  if (!opts || typeof opts !== 'object') return { error: 'Bad input' }
  const { name, dir, content } = opts
  if (!name?.trim()) return { error: 'File name required' }
  if (!dir?.trim()) return { error: 'Directory required' }
  if (typeof content !== 'string') return { error: 'Content required' }

  const safeName = path.basename(name.trim())
  if (!safeName || safeName === '.' || safeName === '..') return { error: 'Invalid file name' }
  if (safeName.length > 200) return { error: 'File name too long' }

  const norm = path.normalize(dir)
  try { fs.accessSync(norm, fs.constants.W_OK) } catch { return { error: 'Cannot write to that directory' } }

  const fullPath = path.join(norm, safeName)
  try {
    fs.writeFileSync(fullPath, content, 'utf8')
    const s = new Set(manifest.files)
    s.add(fullPath)
    manifest.files = Array.from(s)
    writeManifest()
    if (monitoring) hotAddFiles([fullPath])
    else rebuildHashes()
    return { created: fullPath }
  } catch(e) { return { error: e.message } }
})

ipcMain.handle('get-logs', async () => logs)

ipcMain.handle('toggle-monitoring', async (_e, on) => {
  if (typeof on !== 'boolean') return { error: 'Bad arg' }
  if (on) {
    const started = startMonitoring()
    return started ? { monitoring: true } : { monitoring: false, error: 'No bait files to monitor' }
  }
  stopMonitoring()
  return { monitoring: false }
})

ipcMain.handle('get-config', async () => {
  const out = Object.assign({}, settings)
  if (out.smtpPass) out.smtpPass = '••••••••'
  return out
})

ipcMain.handle('save-config', async (_e, incoming) => {
  if (!incoming || typeof incoming !== 'object') return { error: 'Bad input' }

  const validators = {
    emailEnabled: v => Boolean(v),
    emailTo: v => String(v).slice(0, 254),
    smtpHost: v => String(v).slice(0, 253),
    smtpPort: v => { const n = parseInt(v); return isNaN(n) ? 587 : Math.min(Math.max(n, 1), 65535) },
    smtpUser: v => String(v).slice(0, 254),
    smtpPass: v => v === '••••••••' ? settings.smtpPass : String(v).slice(0, 500),
    smtpFrom: v => String(v).slice(0, 254),
    stealthMode: v => Boolean(v),
    detectReads: v => Boolean(v),
    detectCopies: v => Boolean(v),
    silentAlerts: v => Boolean(v)
  }

  for (const [k, validate] of Object.entries(validators)) {
    if (k in incoming) settings[k] = validate(incoming[k])
  }

  writeSettings()
  if (win && !win.isDestroyed()) {
    win.setSkipTaskbar(!!settings.stealthMode)
    if (settings.stealthMode) win.hide()
    else win.show()
  }
  return { success: true }
})

ipcMain.handle('clear-logs', async () => { logs = []; writeLogs(); return { success: true } })

ipcMain.handle('get-status', async () => ({
  monitoring,
  fileCount: manifest.files.length,
  logCount: logs.length,
  stealthMode: settings.stealthMode,
  detectReads: settings.detectReads,
  detectCopies: settings.detectCopies,
  silentAlerts: settings.silentAlerts,
  todayCount: logs.filter(l => new Date(l.timestamp).toDateString() === new Date().toDateString()).length
}))

ipcMain.handle('select-directory', async () => {
  if (!win) return null
  const res = await dialog.showOpenDialog(win, {
    properties: ['openDirectory', 'createDirectory'],
    title: 'Select directory'
  })
  return res.canceled || !res.filePaths.length ? null : res.filePaths[0]
})

ipcMain.handle('get-bait-files', async () => manifest.files.map(fp => {
  let exists = false, size = 0
  try { const st = fs.statSync(fp); exists = true; size = st.size } catch {}
  return { path: fp, name: path.basename(fp), exists, size }
}))

ipcMain.handle('delete-bait-file', async (_e, fp) => {
  if (typeof fp !== 'string') return { error: 'Bad path' }
  if (!manifest.files.includes(fp)) return { error: 'Not a Decoyd file' }
  try {
    stopReadWatch(fp)
    if (fs.existsSync(fp)) fs.unlinkSync(fp)
    manifest.files = manifest.files.filter(f => f !== fp)
    fileHashes.forEach((orig, h) => { if (orig === fp) fileHashes.delete(h) })
    writeManifest()
    if (watcher) watcher.unwatch(fp)
    if (!manifest.files.length && monitoring) stopMonitoring()
    return { success: true }
  } catch(e) { return { error: e.message } }
})
