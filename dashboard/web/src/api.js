export async function api(token, path, { method = 'GET', body, signal } = {}) {
  const response = await fetch(`/api/v1${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal,
    cache: 'no-store',
  })
  if (!response.ok) {
    const message = await response.json().catch(() => null)
    const error = new Error(message?.error || (response.status >= 500 ? 'The dashboard service is unavailable.' : `Request failed (${response.status}).`))
    error.status = response.status
    throw error
  }
  return response.json()
}

export const labels = {
  pending: 'Awaiting pairing', active: 'Connected', paused: 'Paused', revoked: 'Revoked',
  starting: 'Starting', scanning: 'Scanning', uploading: 'Uploading', finished: 'Succeeded',
  finished_with_errors: 'With errors', failed: 'Failed', cancelled: 'Cancelled', blocked: 'Blocked',
  storage_access_denied: 'Storage access denied', policy_unavailable: 'Policy unavailable',
  local_read_failed: 'Local read failed', recovery_key_required: 'Recovery key required',
  dashboard_unavailable: 'Dashboard unavailable', storage_unavailable: 'Storage unavailable',
  device_paused: 'Device paused', unknown: 'Unknown error', delayed: 'Updates delayed',
}

export function dateTime(value) {
  if (value == null) return '—'
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value * 1000))
}

export function bytes(value) {
  if (value == null) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB']
  let size = BigInt(value)
  let unit = 0
  let remainder = 0n
  while (size >= 1024n && unit < units.length - 1) {
    remainder = size % 1024n
    size /= 1024n
    unit++
  }
  return `${size}${unit && remainder >= 103n ? `.${remainder * 10n / 1024n}` : ''} ${units[unit]}`
}
