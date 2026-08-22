import { useParams } from 'react-router-dom'
import { api } from '../api/client'
import { useFetch } from '../hooks/useFetch'
import { Panel, KV, Loading, ErrorBox, HexLink, Copy } from '../components/ui'
import { ago, bdx, bytes, dateTime, num, txType } from '../utils/format'

export default function Tx() {
  const { txid } = useParams()
  const { data, loading, error } = useFetch(() => api.tx(txid), [txid])

  if (loading) return <Loading label="Loading transaction" />
  if (error || !data?.tx)
    return <ErrorBox>{error?.notFound ? 'Transaction not found' : 'Failed to load transaction'}</ErrorBox>

  const tx = data.tx
  const t = txType(tx)
  const inPool = tx.in_pool || tx.block_height === undefined || tx.block_height === null

  return (
    <div className="container">
      <div className="page-head">
        <div className="eyebrow">Transaction · {t}</div>
        <h1 className="display" style={{ fontSize: 'clamp(16px, 2.4vw, 28px)', wordBreak: 'break-all' }}>
          {tx.tx_hash}
        </h1>
        <p className="sub">
          <Copy text={tx.tx_hash} />{' '}
          {inPool ? <span className="badge amber">IN MEMPOOL</span> : <span className="badge green">CONFIRMED</span>}
        </p>
      </div>

      <Panel title="Transaction details">
        <KV
          rows={[
            ['Type', t],
            ['Block', !inPool ? <HexLink to={`/block/${tx.block_height}`} hash={num(tx.block_height)} full /> : 'pending'],
            ['Timestamp', tx.block_timestamp
              ? `${dateTime(tx.block_timestamp)} (${ago(tx.block_timestamp)})`
              : tx.received_timestamp
              ? `${dateTime(tx.received_timestamp)} (received ${ago(tx.received_timestamp)})`
              : null],
            ['Fee', t === 'coinbase' ? '— (coinbase)' : bdx(tx.fee ?? tx.rct_signatures?.txnFee, { digits: 9 })],
            ['Size', bytes(tx.size)],
            ['Version', tx.version],
            ['Unlock time', tx.unlock_time ? num(tx.unlock_time) : '0 (unlocked)'],
            ['Inputs', num(tx.vin?.length)],
            ['Outputs', num(tx.vout?.length)],
            ['Extra', tx.tx_extra_raw ? <span className="mono-sm dim">{tx.tx_extra_raw}</span> : null],
          ]}
        />
      </Panel>

      {tx.vout?.length > 0 && (
        <Panel title={`Outputs (${tx.vout.length})`} className="section-gap">
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th className="num">#</th>
                  <th>Output key</th>
                  <th className="num">Amount</th>
                </tr>
              </thead>
              <tbody>
                {tx.vout.map((o, i) => (
                  <tr key={i}>
                    <td className="num dim">{i}</td>
                    <td className="mono-sm dim">{o.target?.key ?? '—'}</td>
                    <td className="num">{o.amount ? bdx(o.amount, { digits: 9 }) : 'hidden (RingCT)'}</td>
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
