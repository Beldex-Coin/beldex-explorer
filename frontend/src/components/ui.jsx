import { Link } from 'react-router-dom'
import { shortHash } from '../utils/format'

export const Loading = ({ label = 'Syncing with chain' }) => (
  <div className="loading">
    <span className="pulse" />
    {label}
  </div>
)

export const ErrorBox = ({ children }) => <div className="error-box">{children}</div>

export const StatCard = ({ label, value, unit, note, className = '' }) => (
  <div className={`stat-card ${className}`}>
    <div className="label">{label}</div>
    <div className="value">
      {value}
      {unit && <span className="unit">{unit}</span>}
    </div>
    {note && <div className="note">{note}</div>}
  </div>
)

export const Panel = ({ title, right, children, className = '' }) => (
  <section className={`panel ${className}`}>
    {(title || right) && (
      <div className="panel-head">
        <span className="title">{title}</span>
        <span className="spacer" />
        {right}
      </div>
    )}
    {children}
  </section>
)

export const HexLink = ({ to, hash, n = 10, full = false }) => (
  <Link to={to} className="hexlink" title={hash}>
    {full ? hash : shortHash(hash, n)}
  </Link>
)

export const Copy = ({ text }) => (
  <button
    type="button"
    className="copy-btn"
    onClick={() => navigator.clipboard?.writeText(text)}
    title="Copy to clipboard"
  >
    COPY
  </button>
)

export const KV = ({ rows }) => (
  <div>
    {rows
      .filter(([, v]) => v !== undefined && v !== null && v !== '')
      .map(([k, v]) => (
        <div className="kv" key={k}>
          <div className="k">{k}</div>
          <div className="v">{v}</div>
        </div>
      ))}
  </div>
)
