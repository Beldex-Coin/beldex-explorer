// API client for the Flask JSON API (/api/v2/*), with mock fallback so the UI
// can be developed and previewed without a running beldexd.
import { mock } from './mock'

const USE_MOCK = import.meta.env.VITE_USE_MOCK === '1'
const BASE = import.meta.env.VITE_API_BASE || ''

let mockActive = USE_MOCK

export const isMockActive = () => mockActive

async function get(path, mockValue) {
  if (mockActive) return typeof mockValue === 'function' ? mockValue() : mockValue
  try {
    const res = await fetch(BASE + path, { headers: { Accept: 'application/json' } })
    if (!res.ok) {
      if (res.status === 404) {
        const body = await res.json().catch(() => null)
        const err = new Error(body?.message || 'not found')
        err.notFound = true
        throw err
      }
      throw new Error(`API error ${res.status}`)
    }
    const body = await res.json()
    return body.data !== undefined ? body.data : body
  } catch (e) {
    if (e.notFound) throw e
    // Network-level failure → fall back to mock data in dev so the UI stays usable.
    if (import.meta.env.DEV) {
      console.warn(`API unreachable (${path}); using mock data.`, e)
      mockActive = true
      return typeof mockValue === 'function' ? mockValue() : mockValue
    }
    throw e
  }
}

export const api = {
  summary: () => get('/api/v2/summary', mock.summary),
  blocks: (page = 0, perPage = 20) =>
    get(`/api/v2/blocks?page=${page}&per_page=${perPage}`, () => mock.blocks(page, perPage)),
  block: (id) => get(`/api/v2/block/${id}`, () => mock.block(id)),
  tx: (txid) => get(`/api/v2/tx/${txid}`, () => mock.tx(txid)),
  mempool: () => get('/api/v2/mempool', mock.mempool),
  masterNodes: () => get('/api/v2/master_nodes', mock.masterNodes),
  mn: (pubkey) => get(`/api/v2/mn/${pubkey}`, () => mock.mn(pubkey)),
  quorums: () => get('/api/v2/quorums', mock.quorums),
  tokens: (offset = 0, count = 20) =>
    get(`/api/v2/tokens?offset=${offset}&count=${count}`, mock.tokens),
  search: (value) =>
    get(`/api/v2/search?value=${encodeURIComponent(value)}`, () => mock.search(value)),
  bns: (name) => get(`/api/bnslookup?name=${encodeURIComponent(name)}`, () => mock.bns(name)),
}
