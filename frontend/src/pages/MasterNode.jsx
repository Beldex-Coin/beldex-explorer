import { useParams } from 'react-router-dom'
import { api } from '../api/client'
import { useFetch } from '../hooks/useFetch'
import { Panel, KV, Loading, ErrorBox, Copy } from '../components/ui'
import { ago, bdx, num, shortHash } from '../utils/format'

export default function MasterNode() {
  const { pubkey } = useParams()
  const { data, loading, error } = useFetch(() => api.mn(pubkey), [pubkey])

  if (loading) return <Loading label="Loading master node" />
  if (error || !data?.mn)
    return <ErrorBox>{error?.notFound ? 'Master node not found' : 'Failed to load master node'}</ErrorBox>

  const mn = data.mn
  const status = mn.active ? ['ACTIVE', 'green'] : mn.funded ? ['DECOMMISSIONED', 'red'] : ['AWAITING CONTRIBUTION', 'amber']
  const filled = mn.total_contributed / mn.staking_requirement

  return (
    <div className="container">
      <div className="page-head">
        <div className="eyebrow">Master node</div>
        <h1 className="display" style={{ fontSize: 'clamp(15px, 2.2vw, 26px)', wordBreak: 'break-all' }}>
          {mn.master_node_pubkey}
        </h1>
        <p className="sub">
          <Copy text={mn.master_node_pubkey} /> <span className={`badge ${status[1]}`}>{status[0]}</span>
        </p>
      </div>

      <Panel title="Node details">
        <KV
          rows={[
            ['Operator address', <span className="mono-sm">{mn.operator_address}</span>],
            ['Ed25519 pubkey', mn.pubkey_ed25519 ? <span className="mono-sm dim">{mn.pubkey_ed25519}</span> : null],
            ['Staking requirement', bdx(mn.staking_requirement)],
            ['Total contributed', `${bdx(mn.total_contributed)} (${Math.round(filled * 100)}%)`],
            ['Contribution slots', `${num(mn.num_contributions)} filled · ${num(mn.num_open_spots)} open · ${num(mn.num_reserved_spots)} reserved`],
            ['Registered at height', num(mn.registration_height ?? mn.state_height)],
            ['Last reward height', num(mn.last_reward_block_height)],
            ['Last uptime proof', mn.last_uptime_proof ? `${ago(mn.last_uptime_proof)}` : 'never'],
            ['Earned downtime blocks', num(mn.earned_downtime_blocks)],
            ['Requested unlock height', mn.requested_unlock_height ? num(mn.requested_unlock_height) : 'none'],
            ['Swarm ID', mn.swarm_id !== undefined ? String(mn.swarm_id) : null],
            ['Version', Array.isArray(mn.master_node_version) ? mn.master_node_version.join('.') : null],
          ]}
        />
      </Panel>

      {mn.contributors?.length > 0 && (
        <Panel title={`Contributors (${mn.contributors.length})`} className="section-gap">
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Address</th>
                  <th className="num">Amount</th>
                  <th className="num">Reserved</th>
                  <th className="num">Locked contributions</th>
                </tr>
              </thead>
              <tbody>
                {mn.contributors.map((c, i) => (
                  <tr key={i}>
                    <td className="mono-sm" title={c.address}>{shortHash(c.address, 14)}</td>
                    <td className="num">{bdx(c.amount)}</td>
                    <td className="num dim">{bdx(c.reserved ?? c.amount)}</td>
                    <td className="num">{num(c.locked_contributions?.length ?? 0)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  )
}
