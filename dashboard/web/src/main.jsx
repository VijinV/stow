import { useCallback, useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity, Archive, ArrowLeft, ChevronRight, Cloud, Copy, Database, HardDrive,
  History, KeyRound, Laptop, LogOut, Plus, RefreshCw, Search, ShieldCheck, X,
} from 'lucide-react'
import { api, bytes, dateTime, labels } from './api'
import Settings from './settings'
import './style.css'

const running = new Set(['starting', 'scanning', 'uploading'])

function Badge({ value }) {
  return <span className={`badge ${value || 'neutral'}`}><i />{labels[value] || 'No runs'}</span>
}

function Dialog({ title, onClose, children }) {
  const dialog = useRef(null)
  useEffect(() => {
    const node = dialog.current
    node.showModal()
    return () => node.close()
  }, [])
  return <dialog ref={dialog} onCancel={(event) => { event.preventDefault(); onClose() }} aria-labelledby="dialog-title">
    <div className="dialog-heading"><h2 id="dialog-title">{title}</h2><button className="icon-button" aria-label="Close" onClick={onClose}><X size={19} /></button></div>
    {children}
  </dialog>
}

function PairDialog({ token, onClose, onPaired }) {
  const [name, setName] = useState('')
  const [result, setResult] = useState(null)
  const [feedback, setFeedback] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setFeedback('')
    try {
      const enrollment = await api(token, '/admin/enrollments', { method: 'POST', body: { displayName: name } })
      setResult(enrollment)
      onPaired()
    } catch (error) {
      setFeedback(error.message)
    } finally {
      setBusy(false)
    }
  }

  return <Dialog title={result ? 'Pairing code ready' : 'Add a device'} onClose={onClose}>
    {result ? <>
      <p>In Stow, open Dashboard and paste this code to connect {name.trim()}. It expires at {dateTime(result.expiresAt)}.</p>
      <label>Pairing code<input readOnly value={result.pairingCode} onFocus={(event) => event.target.select()} /></label>
      <div className="dialog-actions">
        <button className="button secondary" onClick={async () => {
          try { await navigator.clipboard.writeText(result.pairingCode); setFeedback('Copied.') }
          catch { setFeedback('Select the code and copy it manually.') }
        }}><Copy size={17} /> Copy code</button>
        <button className="button primary" onClick={onClose}>Done</button>
      </div>
      {feedback && <p role="status">{feedback}</p>}
    </> : <form onSubmit={submit}>
      <p>Give the installation a name you’ll recognize in backup history.</p>
      <label>Device name<input autoFocus required maxLength={80} placeholder="Work laptop" value={name} onChange={(event) => setName(event.target.value)} /></label>
      {feedback && <p className="error-text" role="alert">{feedback}</p>}
      <div className="dialog-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button disabled={busy} className="button primary">{busy ? 'Creating…' : 'Create pairing code'}</button></div>
    </form>}
  </Dialog>
}

function Access({ onAccess }) {
  const [key, setKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  return <div className="access-wrap">
    <form className="surface access" onSubmit={async (event) => {
      event.preventDefault()
      setBusy(true)
      setError('')
      try {
        const devices = await api(key.trim(), '/admin/devices')
        onAccess(key.trim(), devices)
      } catch (failure) {
        setError(failure.message)
      } finally {
        setBusy(false)
      }
    }}>
      <div className="icon-tile"><KeyRound size={22} /></div>
      <h1>Open your dashboard</h1>
      <p>Enter the admin access token configured on the Stow server.</p>
      <label>Admin access token<input type="password" autoComplete="off" autoFocus required value={key} onChange={(event) => setKey(event.target.value)} /></label>
      {error && <p className="error-text" role="alert">{error}</p>}
      <button className="button primary" disabled={busy}>{busy ? 'Connecting…' : 'Open dashboard'}</button>
    </form>
  </div>
}

function Metric({ icon: Icon, title, value, detail }) {
  return <div className="surface metric">
    <div className="metric-heading"><span>{title}</span><Icon size={19} /></div>
    <strong>{value}</strong><small>{detail}</small>
  </div>
}

function Devices({ devices, current, policyReady, onPair, onDevice, onSettings, refresh, refreshing }) {
  const [filter, setFilter] = useState('')
  const visible = devices.filter((device) => device.displayName.toLowerCase().includes(filter.trim().toLowerCase()))
  const connected = devices.filter((device) => device.state === 'active').length
  const backups = devices.filter((device) => device.state === 'active' && running.has(device.lastRunPhase) && !device.updatesDelayed).length
  return <>
    <div className="page-heading"><div><h1>Devices</h1><p>Monitor the installations backing up to your S3 destination.</p></div>
      <button className="button primary" onClick={onPair}><Plus size={19} /> Add device</button>
    </div>
    <div className="metrics">
      <Metric icon={Laptop} title="Connected devices" value={connected} detail={`${devices.length} total devices`} />
      <Metric icon={Activity} title="Active backups" value={backups} detail={backups ? 'Currently reporting progress' : 'No backups in progress'} />
      <Metric icon={ShieldCheck} title="Successful devices" value={devices.filter((device) => device.lastSuccessAt).length} detail="At least one successful backup" />
    </div>
    {policyReady && !current && <div className="setup surface"><div className="icon-tile"><Cloud size={21} /></div>
      <div><h2>Configure Amazon S3</h2><p>Set a destination before devices start their first backup.</p></div>
      <button className="button secondary" onClick={onSettings}>Open settings</button>
    </div>}
    <section className="surface device-list" aria-label="Device list">
      <div className="list-toolbar"><h2>All devices</h2><div className="list-controls">
        <label className="search"><Search size={17} /><input aria-label="Find a device" placeholder="Find a device" value={filter} onChange={(event) => setFilter(event.target.value)} /></label>
        <button className="icon-button" aria-label="Refresh devices" title="Refresh devices" disabled={refreshing} onClick={refresh}><RefreshCw size={18} /></button>
      </div></div>
      {visible.length ? <div className="table-scroll"><table>
        <thead><tr><th>Device</th><th>Status</th><th>Last contact</th><th>Last successful backup</th><th><span className="sr-only">Details</span></th></tr></thead>
        <tbody>{visible.map((device) => <tr key={device.deviceId}>
          <td><button className="device-link" onClick={() => onDevice(device.deviceId)}><span className="row-icon"><Laptop size={18} /></span><span><strong>{device.displayName}</strong><small>{device.platform || 'Platform unavailable'}</small></span></button></td>
          <td><Badge value={device.state !== 'active' ? device.state : device.updatesDelayed ? 'delayed' : device.lastRunPhase || 'active'} /></td>
          <td>{dateTime(device.lastSeenAt)}</td><td>{dateTime(device.lastSuccessAt)}</td>
          <td><button className="icon-button row-arrow" aria-label={`Open ${device.displayName}`} onClick={() => onDevice(device.deviceId)}><ChevronRight size={18} /></button></td>
        </tr>)}</tbody>
      </table></div> : <div className="empty">
        <div className="icon-tile"><Laptop size={23} /></div>
        <h3>{devices.length ? 'No matching devices' : 'No devices yet'}</h3>
        <p>{devices.length ? 'Try a different device name.' : 'Generate a pairing code to register your first installation.'}</p>
        {!devices.length && <button className="button secondary" onClick={onPair}><Plus size={17} /> Add device</button>}
      </div>}
    </section>
  </>
}

function Detail({ device, history, historyReady, onBack, onState }) {
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [feedback, setFeedback] = useState('')
  async function change(state) {
    setBusy(true)
    setFeedback('')
    try { await onState(device.deviceId, state); setConfirm(false) }
    catch (error) { setFeedback(error.message) }
    finally { setBusy(false) }
  }
  return <>
    <button className="back" onClick={onBack}><ArrowLeft size={17} /> All devices</button>
    <div className="page-heading"><div><h1>{device.displayName}</h1><p>{device.platform || 'Platform unavailable'}{device.appVersion && ` · Stow ${device.appVersion}`}</p></div>
      <Badge value={device.state} />
    </div>
    <div className="metrics">
      <Metric icon={Activity} title="Latest backup" value={labels[device.updatesDelayed ? 'delayed' : device.lastRunPhase] || 'No runs'} detail={`Last contact ${dateTime(device.lastSeenAt)}`} />
      <Metric icon={ShieldCheck} title="Last success" value={device.lastSuccessAt ? 'Succeeded' : '—'} detail={dateTime(device.lastSuccessAt)} />
      <Metric icon={Database} title="Applied policy" value={device.appliedRevision ? `v${device.appliedRevision}` : '—'} detail={device.nextDueAt ? `Next expected run ${dateTime(device.nextDueAt)}` : device.scheduleEnabled ? 'Schedule enabled' : 'No schedule reported'} />
    </div>
    <section className="surface device-list">
      <div className="list-toolbar"><h2><History size={20} /> Run history</h2></div>
      {history.length ? <div className="table-scroll"><table>
        <thead><tr><th>Started</th><th>Status</th><th>Trigger</th><th>Uploaded files</th><th>Processed</th></tr></thead>
        <tbody>{history.map((run) => <tr key={run.runId}>
          <td>{dateTime(run.startedAt)}</td><td><Badge value={run.phase} />{(run.reason || run.errorCode) && <small className="run-note">{labels[run.reason || run.errorCode]}</small>}</td>
          <td className="capitalize">{run.trigger}</td><td>{run.filesUploaded ?? '—'}</td><td>{bytes(run.bytesDone)}</td>
        </tr>)}</tbody>
      </table></div> : <div className="empty"><div className="icon-tile"><History size={23} /></div><h3>{historyReady ? 'No backups reported' : 'Loading runs…'}</h3>{historyReady && <p>Run history appears when this device reports a backup.</p>}</div>}
    </section>
    {device.state !== 'revoked' && <section className="surface form-panel device-actions">
      <div><h2>Device access</h2><p>Pausing blocks new backups. Revoking removes this device’s dashboard access.</p></div>
      <div className="action-group">
        {['active','paused'].includes(device.state) && <button className="button secondary" disabled={busy} onClick={() => change(device.state === 'paused' ? 'active' : 'paused')}>{device.state === 'paused' ? 'Resume' : 'Pause'}</button>}
        <button className="button danger" disabled={busy} onClick={() => setConfirm(true)}>Revoke</button>
      </div>
      {feedback && !confirm && <p className="error-text" role="alert">{feedback}</p>}
    </section>}
    {confirm && <Dialog title="Revoke device access?" onClose={() => !busy && setConfirm(false)}>
      <p>{device.displayName} will need a new enrollment to connect again. Existing AWS sessions can remain valid until they expire.</p>
      {feedback && <p className="error-text" role="alert">{feedback}</p>}
      <div className="dialog-actions"><button className="button secondary" disabled={busy} onClick={() => setConfirm(false)}>Cancel</button><button className="button danger" disabled={busy} onClick={() => change('revoked')}>{busy ? 'Revoking…' : 'Revoke access'}</button></div>
    </Dialog>}
  </>
}

function App() {
  const [token, setToken] = useState('')
  const [devices, setDevices] = useState([])
  const [current, setCurrent] = useState(null)
  const [policyStatus, setPolicyStatus] = useState('loading')
  const [policyRequest, setPolicyRequest] = useState(0)
  const [page, setPage] = useState('devices')
  const [selected, setSelected] = useState(null)
  const [history, setHistory] = useState([])
  const [historyReady, setHistoryReady] = useState(false)
  const [pair, setPair] = useState(false)
  const [error, setError] = useState('')
  const [refreshing, setRefreshing] = useState(false)

  const refresh = useCallback(async (signal) => {
    if (!token) return
    setRefreshing(true)
    try {
      const list = await api(token, '/admin/devices', { signal })
      setDevices(list)
      if (selected) {
        setHistory(await api(token, `/admin/devices/${selected}/runs`, { signal }))
        setHistoryReady(true)
      }
      setError('')
    } catch (failure) {
      if (!signal?.aborted) setError(failure.message)
    } finally {
      if (!signal?.aborted) setRefreshing(false)
    }
  }, [token, selected])

  useEffect(() => {
    if (!token) return
    const controller = new AbortController()
    refresh(controller.signal)
    const timer = window.setInterval(() => {
      if (!document.hidden) refresh(controller.signal)
    }, 15000)
    return () => { controller.abort(); window.clearInterval(timer) }
  }, [token, refresh])

  useEffect(() => {
    if (!token) return
    const controller = new AbortController()
    setPolicyStatus('loading')
    api(token, '/admin/policy', { signal: controller.signal }).then((settings) => {
      setCurrent(settings)
      setPolicyStatus('ready')
    }).catch(() => {
      if (!controller.signal.aborted) setPolicyStatus('error')
    })
    return () => controller.abort()
  }, [token, policyRequest])

  const showDevices = () => { setPage('devices'); setSelected(null) }
  const showSettings = () => { setPage('settings'); setSelected(null) }
  const selectDevice = (id) => { setHistory([]); setHistoryReady(false); setSelected(id) }
  const device = devices.find((entry) => entry.deviceId === selected)
  const signOut = () => { setToken(''); setDevices([]); setHistory([]); setCurrent(null); setPolicyStatus('loading'); setPair(false); setError(''); showDevices() }

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Archive size={22} strokeWidth={2.2} /></div><div>Stow <small>Backup dashboard</small></div></div>
      {token && <nav aria-label="Main navigation">
        <button className={page === 'devices' ? 'nav active' : 'nav'} aria-current={page === 'devices' ? 'page' : undefined} onClick={showDevices}><HardDrive size={18} /> Devices</button>
        <button className={page === 'settings' ? 'nav active' : 'nav'} aria-current={page === 'settings' ? 'page' : undefined} onClick={showSettings}><Cloud size={18} /> Storage &amp; policy</button>
      </nav>}
      {token && <button onClick={signOut} className="nav sign-out"><LogOut size={17} /> Sign out</button>}
    </aside>
    <main>
      {token ? <div className="content">
        {error && <div className="error-banner" role="alert">{error}<button className="icon-button" aria-label="Dismiss error" onClick={() => setError('')}><X size={17} /></button></div>}
        {page === 'settings' ? (policyStatus === 'ready'
          ? <Settings token={token} current={current} onSaved={setCurrent} />
          : <section className="surface form-panel" aria-live="polite">
            {policyStatus === 'loading' ? <p>Loading storage policy…</p> : <>
              <p>Couldn’t load the current policy.</p>
              <button className="button secondary" onClick={() => setPolicyRequest((request) => request + 1)}>Retry</button>
            </>}
          </section>)
          : device ? <Detail device={device} history={history} historyReady={historyReady} onBack={showDevices} onState={async (id, state) => {
            await api(token, `/admin/devices/${id}`, { method: 'PATCH', body: { state } })
            await refresh()
          }} />
          : <Devices devices={devices} current={current} policyReady={policyStatus === 'ready'} onPair={() => setPair(true)} onDevice={selectDevice} onSettings={showSettings} refresh={() => refresh()} refreshing={refreshing} />}
      </div> : <Access onAccess={(key, list) => { setDevices(list); setToken(key) }} />}
    </main>
    {pair && <PairDialog token={token} onClose={() => setPair(false)} onPaired={() => refresh()} />}
  </div>
}

createRoot(document.getElementById('root')).render(<App />)
