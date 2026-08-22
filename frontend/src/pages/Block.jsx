import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { useFetch } from '../hooks/useFetch'
import { Panel, KV, Loading, ErrorBox, HexLink, Copy } from '../components/ui'
import TxTable from '../components/TxTable'
import { ago, bdx, bytes, dateTime, num } from '../utils/format'

export default function Block() {
  const { id } = useParams()
  const { data, loading, error } = useFetch(() => api.block(id), [id])

  if (loading) return <Loading label="Loading block" />
  if (error || !data)
    return <ErrorBox>{error?.notFound ? 'Block not found' : 'Failed to load block'}</ErrorBox>

  const h = data.block_header
  return (
    <div className="container">
      <div className="page-head">
        <div className="eyebrow">Block</div>
        <h1 className="display">#{num(h.height)}</h1>
        <p className="sub mono-sm">
          {h.hash} <Copy text={h.hash} />
        </p>
        <div style={{ display: 'flex', gap: 12, marginTop: 20 }}>
          {h.height > 0 && <Link className="btn ghost sm" to={`/block/${h.height - 1}`}>◂ PREV</Link>}
          {data.next_height != null && <Link className="btn ghost sm" to={`/block/${data.next_height}`}>NEXT ▸</Link>}
        </div>
      </div>

      <Panel title="Block details">
        <KV
          rows={[
            ['Height', num(h.height)],
            ['Timestamp', `${dateTime(h.timestamp)} (${ago(h.timestamp)})`],
            ['Previous block', h.prev_hash ? <HexLink to={`/block/${h.prev_hash}`} hash={h.prev_hash} full /> : null],
            ['Size', bytes(h.block_size)],
            ['Transactions', `${num(data.transactions?.length ?? h.num_txes ?? 0)} + coinbase`],
            ['Reward', bdx(h.reward, { digits: 6 })],
            ['Difficulty', num(h.difficulty)],
            ['Cumulative difficulty', num(h.cumulative_difficulty)],
            ['Nonce', num(h.nonce)],
            ['Major / minor version', h.major_version !== undefined ? `${h.major_version} / ${h.minor_version ?? '—'}` : null],
            ['Depth', data.chain_height ? num(data.chain_height - 1 - h.height) : null],
          ]}
        />
      </Panel>

      {data.miner_tx && (
        <Panel title="Coinbase transaction" className="section-gap">
          <TxTable txs={[{ ...data.miner_tx, coinbase: true }]} showHeight={false} />
        </Panel>
      )}

      <Panel title={`Transactions (${data.transactions?.length ?? 0})`} className="section-gap">
        <TxTable txs={data.transactions} showHeight={false} emptyLabel="No transactions in this block" />
      </Panel>
    </div>
  )
}
