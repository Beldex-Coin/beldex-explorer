import { api } from '../api/client'
import { useFetch } from '../hooks/useFetch'
import { Panel, Loading, ErrorBox, HexLink } from '../components/ui'
import { num } from '../utils/format'

const LABELS = {
  obligation: 'Obligation quorums',
  checkpoint: 'Checkpoint quorums',
  flash: 'Flash quorums',
  POS: 'POS quorums',
}

function QuorumGroup({ label, list }) {
  return (
    <Panel title={`${label} (${list.length})`} className="section-gap">
      {list.length === 0 ? (
        <div className="loading" style={{ padding: '32px 0' }}>None in the recent window</div>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th className="num">Height</th>
                <th>Validators</th>
                <th>Workers</th>
              </tr>
            </thead>
            <tbody>
              {list.map((q, i) => (
                <tr key={i}>
                  <td className="num">
                    <HexLink to={`/block/${q.height}`} hash={num(q.height)} full />
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, maxWidth: 640 }}>
                      {(q.quorum?.validators ?? []).map((v) => (
                        <HexLink key={v} to={`/mn/${v}`} hash={v} n={5} />
                      ))}
                    </div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, maxWidth: 420 }}>
                      {(q.quorum?.workers ?? []).map((w) => (
                        <HexLink key={w} to={`/mn/${w}`} hash={w} n={5} />
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}

export default function Quorums() {
  const { data, loading, error } = useFetch(() => api.quorums(), [])

  return (
    <div className="container">
      <div className="page-head">
        <div className="eyebrow">Consensus</div>
        <h1 className="display">Quorums</h1>
        <p className="sub">Recent testing, checkpoint, flash and POS quorums drawn from the master node network.</p>
      </div>
      {loading && <Loading label="Loading quorums" />}
      {error && <ErrorBox>Failed to load quorums</ErrorBox>}
      {data &&
        Object.entries(LABELS).map(([key, label]) => (
          <QuorumGroup key={key} label={label} list={data.quorums?.[key] ?? []} />
        ))}
    </div>
  )
}
