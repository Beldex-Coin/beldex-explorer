import { useState } from 'react'
import { api } from '../api/client'
import { useFetch } from '../hooks/useFetch'
import { Panel, Loading, ErrorBox, HexLink, StatCard } from '../components/ui'
import { ago, bdx, num, shortHash } from '../utils/format'

function MnTable({ mns, kind }) {
  if (!mns || mns.length === 0)
    return <div className="loading" style={{ padding: '40px 0' }}>None</div>
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th>Public key</th>
            <th>Operator</th>
            {kind === 'awaiting' ? (
              <>
                <th className="num">Contributed</th>
                <th className="num">Open for contribution</th>
              </>
            ) : (
              <>
                <th className="num">Stake</th>
                <th className="num">Last reward height</th>
              </>
            )}
            {kind === 'decommissioned' && <th className="num">Blocks to deregister</th>}
            <th className="num">Last uptime proof</th>
          </tr>
        </thead>
        <tbody>
          {mns.map((m) => (
            <tr key={m.master_node_pubkey}>
              <td><HexLink to={`/mn/${m.master_node_pubkey}`} hash={m.master_node_pubkey} n={12} /></td>
              <td className="dim mono-sm" title={m.operator_address}>{shortHash(m.operator_address, 8)}</td>
              {kind === 'awaiting' ? (
                <>
                  <td className="num">{bdx(m.total_contributed)}</td>
                  <td className="num green">{bdx(m.contribution_open)}</td>
                </>
              ) : (
                <>
                  <td className="num">{bdx(m.staking_requirement)}</td>
                  <td className="num">{num(m.last_reward_block_height)}</td>
                </>
              )}
              {kind === 'decommissioned' && <td className="num red">{num(m.decomm_blocks_remaining)}</td>}
              <td className="num dim">{m.last_uptime_proof ? ago(m.last_uptime_proof) : 'never'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function MasterNodes() {
  const { data, loading, error } = useFetch(() => api.masterNodes(), [], { refresh: 60 })
  const [tab, setTab] = useState('active')

  return (
    <div className="container">
      <div className="page-head">
        <div className="eyebrow">Network backbone</div>
        <h1 className="display">Master Nodes</h1>
        <p className="sub">Staked nodes securing the Beldex network, powering BChat, BelNet and flash transactions.</p>
      </div>
      {loading && <Loading label="Loading master nodes" />}
      {error && <ErrorBox>Failed to load master nodes</ErrorBox>}
      {data && (
        <>
          <div className="stat-grid" style={{ marginBottom: 32 }}>
            <StatCard label="Active" value={num(data.active.length)} className="green" />
            <StatCard label="Awaiting contribution" value={num(data.awaiting.length)} />
            <StatCard label="Decommissioned" value={num(data.decommissioned.length)} />
            <StatCard label="Block height" value={num(data.height)} />
          </div>
          <Panel
            title="Nodes"
            right={
              <div style={{ display: 'flex', gap: 8 }}>
                {['active', 'awaiting', 'decommissioned'].map((k) => (
                  <button
                    key={k}
                    className="btn sm"
                    style={
                      tab === k
                        ? {}
                        : { background: 'transparent', color: 'var(--text-dim)', borderColor: 'var(--border-strong)' }
                    }
                    onClick={() => setTab(k)}
                  >
                    {k.toUpperCase()} ({data[k].length})
                  </button>
                ))}
              </div>
            }
          >
            <MnTable mns={data[tab]} kind={tab} />
          </Panel>
        </>
      )}
    </div>
  )
}
