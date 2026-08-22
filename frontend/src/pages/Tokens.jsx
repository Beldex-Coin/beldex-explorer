import { Fragment, useState } from 'react'
import { api } from '../api/client'
import { useFetch } from '../hooks/useFetch'
import { Panel, Loading, ErrorBox, Copy } from '../components/ui'
import { num, shortHash } from '../utils/format'

export default function Tokens() {
  const [offset, setOffset] = useState(0)
  const count = 20
  const { data, loading, error } = useFetch(() => api.tokens(offset, count), [offset])
  const [openId, setOpenId] = useState(null)

  return (
    <div className="container">
      <div className="page-head">
        <div className="eyebrow">Assets</div>
        <h1 className="display">Tokens</h1>
        <p className="sub">Tokens issued on the Beldex network.</p>
      </div>
      {loading && <Loading label="Loading tokens" />}
      {error && <ErrorBox>Failed to load tokens</ErrorBox>}
      {data && (
        <Panel
          title={`Tokens (${num(data.total_count)})`}
          right={
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn ghost sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - count))} style={{ opacity: offset === 0 ? 0.35 : 1 }}>
                ◂ PREV
              </button>
              <button
                className="btn ghost sm"
                disabled={offset + count >= data.total_count}
                onClick={() => setOffset(offset + count)}
                style={{ opacity: offset + count >= data.total_count ? 0.35 : 1 }}
              >
                NEXT ▸
              </button>
            </div>
          }
        >
          {data.tokens.length === 0 ? (
            <div className="loading" style={{ padding: '40px 0' }}>No tokens found</div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Ticker</th>
                    <th>Token ID</th>
                    <th className="num">Current supply</th>
                    <th className="num">Max supply</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {data.tokens.map((t) => (
                    <Fragment key={t.token_id}>
                      <tr>
                        <td>{t.name || <span className="faint">unnamed</span>}</td>
                        <td className="green">{t.ticker}</td>
                        <td className="mono-sm dim" title={t.token_id}>
                          {shortHash(t.token_id, 8)}
                          <Copy text={t.token_id} />
                        </td>
                        <td className="num">{t.current_supply || '—'}</td>
                        <td className="num">{t.total_max_supply || '—'}</td>
                        <td>
                          <button className="copy-btn" onClick={() => setOpenId(openId === t.token_id ? null : t.token_id)}>
                            {openId === t.token_id ? 'HIDE' : 'DETAILS'}
                          </button>
                        </td>
                      </tr>
                      {openId === t.token_id && (
                        <tr>
                          <td colSpan={6} style={{ whiteSpace: 'normal' }}>
                            <div className="mono-sm dim" style={{ display: 'grid', gap: 6 }}>
                              <span>Token ID: <span className="green">{t.token_id}</span></span>
                              <span>Owner: {t.owner || '—'}</span>
                              <span>Decimals: {t.decimal_point !== '' ? t.decimal_point : '—'}</span>
                              {t.meta_info && <span>Meta: {t.meta_info}</span>}
                              {t.social && <span>Social: {t.social}</span>}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}
    </div>
  )
}
