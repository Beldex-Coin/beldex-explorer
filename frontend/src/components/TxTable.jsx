import { HexLink } from './ui'
import { ago, bdx, bytes, num, txType } from '../utils/format'

const typeBadge = (t) =>
  ({ coinbase: 'blue', stake: 'green', 'state change': 'amber', BNS: 'green', token: 'blue' }[t] || '')

export default function TxTable({ txs, showHeight = true, emptyLabel = 'No transactions' }) {
  if (!txs || txs.length === 0)
    return <div className="loading" style={{ padding: '40px 0' }}>{emptyLabel}</div>

  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th>Transaction hash</th>
            <th>Type</th>
            {showHeight && <th className="num">Height</th>}
            <th className="num">Fee</th>
            <th className="num">Size</th>
            <th className="num">Age</th>
          </tr>
        </thead>
        <tbody>
          {txs.map((tx) => {
            const t = txType(tx)
            return (
              <tr key={tx.tx_hash}>
                <td><HexLink to={`/tx/${tx.tx_hash}`} hash={tx.tx_hash} n={12} /></td>
                <td><span className={`badge ${typeBadge(t)}`}>{t}</span></td>
                {showHeight && (
                  <td className="num">
                    {tx.block_height !== undefined && tx.block_height !== null
                      ? <HexLink to={`/block/${tx.block_height}`} hash={num(tx.block_height)} full />
                      : <span className="badge amber">pool</span>}
                  </td>
                )}
                <td className="num">{t === 'coinbase' ? '—' : bdx(tx.fee ?? tx.rct_signatures?.txnFee, { digits: 6 })}</td>
                <td className="num">{bytes(tx.size)}</td>
                <td className="num dim">{ago(tx.received_timestamp ?? tx.block_timestamp ?? tx.timestamp)}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
