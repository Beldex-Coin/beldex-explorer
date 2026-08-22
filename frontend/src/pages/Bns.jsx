import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { Panel, KV, Loading, ErrorBox, Copy } from '../components/ui'
import { num } from '../utils/format'

export default function Bns() {
  const { name: routeName } = useParams()
  const navigate = useNavigate()
  const [input, setInput] = useState(routeName || '')
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!routeName) {
      setData(null)
      return
    }
    let alive = true
    setLoading(true)
    setError(null)
    api
      .bns(routeName.endsWith('.bdx') ? routeName : `${routeName}.bdx`)
      .then((d) => alive && setData(d.bnsData ?? d))
      .catch((e) => alive && setError(e))
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
  }, [routeName])

  function submit(e) {
    e.preventDefault()
    const v = input.trim().toLowerCase().replace(/\.bdx$/, '')
    if (v) navigate(`/bns/${v}`)
  }

  return (
    <div className="container">
      <div className="page-head">
        <div className="eyebrow">Beldex Name Service</div>
        <h1 className="display">BNS Lookup</h1>
        <p className="sub">Resolve human-readable .bdx names to BChat IDs, BelNet addresses and wallets.</p>
      </div>

      <form className="search" onSubmit={submit} style={{ marginBottom: 40 }}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Enter a name, e.g. satoshi"
          spellCheck={false}
        />
        <button type="submit">LOOKUP</button>
      </form>

      {loading && <Loading label="Resolving name" />}
      {error && <ErrorBox>Lookup failed</ErrorBox>}
      {data && !loading && (
        <Panel
          title={`${(routeName || data.name || '').replace(/\.bdx$/, '')}.bdx`}
          right={
            data.available ? (
              <span className="badge green">AVAILABLE</span>
            ) : (
              <span className="badge blue">REGISTERED</span>
            )
          }
        >
          {data.available ? (
            <div className="loading" style={{ padding: '40px 0' }}>
              This name is not registered yet
            </div>
          ) : (
            <KV
              rows={[
                ['Owner', data.owner ? <span className="mono-sm">{data.owner}<Copy text={data.owner} /></span> : null],
                ['Expiration height', data.exp_height ? num(data.exp_height) : null],
                ['BChat ID', data.bchat ? <span className="mono-sm green">{data.bchat}<Copy text={data.bchat} /></span> : null],
                ['BelNet', data.belnet ? <span className="mono-sm">{data.belnet}</span> : null],
                ['Wallet', data.wallet ? <span className="mono-sm">{data.wallet}<Copy text={data.wallet} /></span> : null],
                ['ETH address', data.ethAddress ? <span className="mono-sm">{data.ethAddress}</span> : null],
              ]}
            />
          )}
        </Panel>
      )}
    </div>
  )
}
