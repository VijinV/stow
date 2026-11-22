import { useEffect, useState } from 'react'
import { Cloud, ShieldCheck, SlidersHorizontal } from 'lucide-react'
import { api } from './api'

const initial = {
  bucket: '', region: 'us-east-1', basePrefix: 'backups', roleArn: '',
  rules: {
    excludes: [], skipHidden: false, skipDevArtifacts: false, requireClientEncryption: false,
    maxParallelUploads: 4, storageClass: '', serverEncryption: '', kmsKeyArn: '',
  },
}

export default function Settings({ token, current, onSaved }) {
  const [form, setForm] = useState(current?.settings || initial)
  const [exclusions, setExclusions] = useState((current?.settings.rules.excludes || []).join('\n'))
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState(null)

  useEffect(() => {
    setForm(current?.settings || initial)
    setExclusions((current?.settings.rules.excludes || []).join('\n'))
  }, [current])

  const field = (key) => ({
    value: form[key], onChange: (event) => setForm({ ...form, [key]: event.target.value }),
  })
  const rule = (key, value) => setForm({ ...form, rules: { ...form.rules, [key]: value } })

  async function save(event) {
    event.preventDefault()
    setBusy(true)
    setNotice(null)
    try {
      const settings = await api(token, '/admin/policy', {
        method: 'PUT',
        body: { ...form, rules: {
          ...form.rules,
          excludes: exclusions.split('\n').map((line) => line.trim()).filter(Boolean),
          kmsKeyArn: form.rules.serverEncryption === 'AES256' ? '' : form.rules.kmsKeyArn.trim(),
        } },
      })
      onSaved(settings)
      setNotice({ text: `Policy ${settings.revision} published. Devices will use it on their next backup.` })
    } catch (error) {
      setNotice({ text: error.message, error: true })
    } finally {
      setBusy(false)
    }
  }

  return <>
    <div className="page-heading">
      <div><h1>Storage &amp; policy</h1><p>Set the destination and backup rules shared by your devices.</p></div>
      {current && <span className="badge neutral">Policy v{current.revision}</span>}
    </div>
    <form className="settings-form" onSubmit={save}>
      <section className="surface form-panel">
        <div className="section-heading"><div className="icon-tile"><Cloud size={20} /></div><div><h2>Amazon S3 destination</h2><p>Each device uploads to a separate prefix in this bucket.</p></div></div>
        <div className="form-grid">
          <label>Bucket name<input required maxLength={63} placeholder="company-backups" {...field('bucket')} /></label>
          <label>AWS region<input required maxLength={32} {...field('region')} /></label>
          <label>Base prefix<input maxLength={96} {...field('basePrefix')} /></label>
          <label>IAM role ARN<input required maxLength={256} placeholder="arn:aws:iam::123456789012:role/StowBackup" {...field('roleArn')} /></label>
        </div>
      </section>
      <section className="surface form-panel">
        <div className="section-heading"><div className="icon-tile"><SlidersHorizontal size={20} /></div><div><h2>Backup rules</h2><p>These rules apply alongside the folders and exclusions selected in Stow.</p></div></div>
        <div className="form-grid">
          <label className="span">Exclusion patterns <span className="hint">One glob per line</span>
            <textarea rows={4} placeholder={'*.tmp\nnode_modules/**'} value={exclusions} onChange={(event) => setExclusions(event.target.value)} />
          </label>
          <label>Parallel upload limit<input type="number" required min={1} max={16} value={form.rules.maxParallelUploads} onChange={(event) => rule('maxParallelUploads', event.target.valueAsNumber)} /></label>
          <label>Storage class<select value={form.rules.storageClass} onChange={(event) => rule('storageClass', event.target.value)}>
            <option value="">Bucket default</option><option value="STANDARD">Standard</option><option value="STANDARD_IA">Standard-IA</option><option value="INTELLIGENT_TIERING">Intelligent-Tiering</option>
          </select></label>
        </div>
        <label className="check"><input type="checkbox" checked={form.rules.skipHidden} onChange={(event) => rule('skipHidden', event.target.checked)} /> Skip hidden files and folders</label>
        <label className="check"><input type="checkbox" checked={form.rules.skipDevArtifacts} onChange={(event) => rule('skipDevArtifacts', event.target.checked)} /> Skip dependencies and build output</label>
      </section>
      <section className="surface form-panel">
        <div className="section-heading"><div className="icon-tile"><ShieldCheck size={20} /></div><div><h2>Encryption</h2><p>Client-side recovery keys stay on each device.</p></div></div>
        <div className="form-grid">
          <label>S3 encryption<select value={form.rules.serverEncryption} onChange={(event) => rule('serverEncryption', event.target.value)}>
            <option value="">Bucket default</option><option value="AES256">SSE-S3</option><option value="aws:kms">SSE-KMS</option>
          </select></label>
          {form.rules.serverEncryption !== 'AES256' && <label>KMS key ARN
            {form.rules.serverEncryption === '' && <span className="hint">Enter the key if the bucket defaults to SSE-KMS.</span>}
            <input required={form.rules.serverEncryption === 'aws:kms'} value={form.rules.kmsKeyArn} onChange={(event) => rule('kmsKeyArn', event.target.value)} />
          </label>}
        </div>
        <label className="check"><input type="checkbox" checked={form.rules.requireClientEncryption} onChange={(event) => rule('requireClientEncryption', event.target.checked)} /> Require encryption on the device before upload</label>
      </section>
      <div className="form-actions">
        {notice && <p className={notice.error ? 'error-text' : 'success-text'} role={notice.error ? 'alert' : 'status'}>{notice.text}</p>}
        <button className="button primary" disabled={busy}>{busy ? 'Publishing…' : 'Publish policy'}</button>
      </div>
    </form>
  </>
}
