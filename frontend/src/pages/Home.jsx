import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useFetch } from '../hooks/useFetch'
import SearchBar from '../components/SearchBar'
import { StatCard, Panel, HexLink, Loading, ErrorBox } from '../components/ui'
import { ago, bdx, bytes, num, shortHash } from '../utils/format'

function Hero() {
  return (
    <div className="hero container">
      <div className="eyebrow">Beldex</div>
      <h1 className="display" style={{ marginTop: 14, fontSize: 'clamp(24px, 3.6vw, 42px)' }}>
        Blockchain Explorer
      </h1>
      <div style={{ marginTop: 32 }}>
        <SearchBar />
      </div>
    </div>
  )
}

function Stats({ s }) {
  const info = s.info || {}
  const mn = s.master_nodes || {}
  return (
    <div className="container section-gap">
      <div className="stat-grid">
        <StatCard label="Block height" value={num(info.height)} />
        <StatCard label="Difficulty" value={num(info.difficulty)} note={`target ${info.target ?? 30}s`} />
        <StatCard label="Total transactions" value={num(info.tx_count)} />
        <StatCard label="Active master nodes" value={num(mn.active)} note={`${num(mn.awaiting)} awaiting · ${num(mn.decommissioned)} decommissioned`} />
        <StatCard label="Staking requirement" value={bdx(s.stake?.staking_requirement, { unit: false })} unit="BDX" />
        <StatCard label="Mempool" value={num(s.mempool?.tx_count)} unit="txs" note={bytes(s.mempool?.bytes)} />
        {s.emission && (
          <StatCard label="Emission" value={bdx(s.emission.emission_amount, { digits: 0, unit: false })} unit="BDX" note={`burned ${bdx(s.emission.burn_amount, { digits: 0 })}`} />
        )}
        <StatCard label="Hard fork" value={`v${s.hf?.version ?? '—'}`} note={info.nettype} />
      </div>
    </div>
  )
}

function BlocksPanel() {
  const [page, setPage] = useState(0)
  const perPage = 20
  const { data, loading, error } = useFetch(() => api.blocks(page, perPage), [page], { refresh: page === 0 ? 30 : 0 })

  return (
    <Panel
      title="Latest blocks"
      right={
        <div className="pager" style={{ padding: 0 }}>
          <button className="btn ghost sm" disabled={page === 0} onClick={() => setPage(page - 1)} style={{ opacity: page === 0 ? 0.35 : 1 }}>
            ◂ NEWER
          </button>
          <button className="btn ghost sm" onClick={() => setPage(page + 1)}>OLDER ▸</button>
        </div>
      }
    >
      {loading && <Loading />}
      {error && <ErrorBox>Failed to load blocks</ErrorBox>}
      {data && (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th className="num">Height</th>
                <th>Block hash</th>
                <th className="num">Txs</th>
                <th className="num">Size</th>
                <th className="num">Reward</th>
                <th className="num">Age</th>
              </tr>
            </thead>
            <tbody>
              {data.blocks.map((b) => (
                <tr key={b.height}>
                  <td className="num"><HexLink to={`/block/${b.height}`} hash={num(b.height)} full /></td>
                  <td className="dim mono-sm" title={b.hash}>{shortHash(b.hash, 14)}</td>
                  <td className="num">{b.tx_count}</td>
                  <td className="num">{bytes(b.block_size)}</td>
                  <td className="num">{bdx(b.reward)}</td>
                  <td className="num dim">{ago(b.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}

function NetworkPanel({ s }) {
  const info = s.info || {}
  const fees = s.fees || {}
  const bnsTotal = Array.isArray(info.bns_counts)
    ? info.bns_counts.reduce((a, b) => a + b, 0)
    : info.bns_counts
  return (
    <Panel title="Network">
      <div>
        <div className="kv"><div className="k">Network type</div><div className="v">{info.nettype ?? '—'}</div></div>
        <div className="kv"><div className="k">Daemon version</div><div className="v">{info.version ?? '—'}</div></div>
        <div className="kv"><div className="k">Top block hash</div><div className="v mono-sm">{info.top_block_hash ? <HexLink to={`/block/${info.top_block_hash}`} hash={info.top_block_hash} n={16} /> : '—'}</div></div>
        <div className="kv"><div className="k">Fee per byte</div><div className="v">{fees.fee_per_byte !== undefined ? `${num(fees.fee_per_byte)} atomic` : '—'}</div></div>
        <div className="kv"><div className="k">Fee per output</div><div className="v">{bdx(fees.fee_per_output, { digits: 6 })}</div></div>
        <div className="kv"><div className="k">Flash fee (fixed)</div><div className="v">{bdx(fees.flash_fee_fixed, { digits: 6 })}</div></div>
        <div className="kv"><div className="k">BNS records</div><div className="v">{num(bnsTotal)}</div></div>
        <div className="kv"><div className="k">Database size</div><div className="v">{bytes(info.database_size)}</div></div>
        <div className="kv">
          <div className="k">Quick links</div>
          <div className="v" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link className="btn ghost sm" to="/master_nodes">MASTER NODES</Link>
            <Link className="btn ghost sm" to="/txpool">MEMPOOL</Link>
            <Link className="btn ghost sm" to="/quorums">QUORUMS</Link>
            <Link className="btn ghost sm" to="/tokens">TOKENS</Link>
          </div>
        </div>
      </div>
    </Panel>
  )
}

export default function Home() {
  const { data: s, loading, error } = useFetch(() => api.summary(), [], { refresh: 30 })

  return (
    <>
      <Hero />
      {loading && <Loading label="Connecting to Beldex network" />}
      {error && <div className="container"><ErrorBox>Cannot reach the explorer API</ErrorBox></div>}
      {s && (
        <>
          <Stats s={s} />
          <div className="container section-gap">
            <BlocksPanel />
          </div>
          <div className="container section-gap">
            <NetworkPanel s={s} />
          </div>
        </>
      )}
    </>
  )
}
