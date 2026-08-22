// Formatting helpers. Beldex uses 10^9 atomic units per BDX.
export const ATOMIC = 1e9

export function bdx(atomic, { digits = 4, unit = true } = {}) {
  if (atomic === undefined || atomic === null) return '—'
  const v = Number(atomic) / ATOMIC
  const s = v.toLocaleString(undefined, { maximumFractionDigits: digits })
  return unit ? `${s} BDX` : s
}

export function num(n) {
  if (n === undefined || n === null) return '—'
  return Number(n).toLocaleString()
}

export function bytes(b) {
  if (b === undefined || b === null) return '—'
  b = Number(b)
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(2)} kB`
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(2)} MB`
  return `${(b / 1024 ** 3).toFixed(2)} GB`
}

export function shortHash(h, n = 10) {
  if (!h) return '—'
  return h.length <= n * 2 ? h : `${h.slice(0, n)}…${h.slice(-n)}`
}

export function ago(ts) {
  if (!ts) return '—'
  let s = Math.max(0, Math.floor(Date.now() / 1000 - ts))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m ago`
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h ago`
}

export function dateTime(ts) {
  if (!ts) return '—'
  return new Date(ts * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC')
}

export function txType(tx) {
  if (!tx) return 'unknown'
  if (tx.coinbase || (tx.vin?.length === 1 && tx.vin[0].gen)) return 'coinbase'
  const t = tx.type
  const names = { 0: 'standard', 1: 'standard', 2: 'state change', 3: 'key image unlock', 4: 'stake', 5: 'BNS', 6: 'token' }
  if (typeof t === 'number' && names[t]) return names[t]
  return 'standard'
}
