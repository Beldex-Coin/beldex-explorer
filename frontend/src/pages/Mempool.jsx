import { api } from '../api/client'
import { useFetch } from '../hooks/useFetch'
import { Panel, Loading, ErrorBox } from '../components/ui'
import TxTable from '../components/TxTable'
import { bytes } from '../utils/format'

export default function Mempool() {
  const { data, loading, error } = useFetch(() => api.mempool(), [], { refresh: 15 })

  return (
    <div className="container">
      <div className="page-head">
        <div className="eyebrow">Pending</div>
        <h1 className="display">Mempool</h1>
        <p className="sub">Unconfirmed transactions waiting to be mined into a block. Auto-refreshes every 15s.</p>
      </div>
      {loading && <Loading label="Loading mempool" />}
      {error && <ErrorBox>Failed to load mempool</ErrorBox>}
      {data && (
        <Panel
          title={`Pool transactions (${data.txs.length})`}
          right={<span className="dim mono-sm">{bytes(data.txs.reduce((a, t) => a + (t.size || 0), 0))} total</span>}
        >
          <TxTable txs={data.txs} showHeight={false} emptyLabel="Mempool is empty" />
        </Panel>
      )}
    </div>
  )
}
