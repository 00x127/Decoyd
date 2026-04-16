const { contextBridge, ipcRenderer } = require('electron')

const allowed = new Set([
  'create-bait-files', 'create-custom-bait-file',
  'get-logs', 'toggle-monitoring', 'get-config',
  'save-config', 'clear-logs', 'get-status',
  'select-directory', 'get-bait-files', 'delete-bait-file'
])

const validEvents = new Set(['log-added', 'watcher-error', 'bait-file-removed'])

function invoke(ch, ...args) {
  if (!allowed.has(ch)) return Promise.reject(new Error('blocked'))
  return ipcRenderer.invoke(ch, ...args)
}

contextBridge.exposeInMainWorld('decoyd', {
  createBaitFiles: dir => invoke('create-bait-files', dir),
  createCustomBaitFile: opts => invoke('create-custom-bait-file', opts),
  getLogs: () => invoke('get-logs'),
  toggleMonitoring: on => invoke('toggle-monitoring', on),
  getConfig: () => invoke('get-config'),
  saveConfig: cfg => invoke('save-config', cfg),
  clearLogs: () => invoke('clear-logs'),
  getStatus: () => invoke('get-status'),
  selectDirectory: () => invoke('select-directory'),
  getBaitFiles: () => invoke('get-bait-files'),
  deleteBaitFile: fp => invoke('delete-bait-file', fp),

  on(channel, cb) {
    if (!validEvents.has(channel)) return () => {}
    const listener = (_e, data) => cb(data)
    ipcRenderer.on(channel, listener)
    return () => ipcRenderer.removeListener(channel, listener)
  }
})
