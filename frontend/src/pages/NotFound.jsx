import { Link, useSearchParams } from 'react-router-dom'
import SearchBar from '../components/SearchBar'

export default function NotFound() {
  const [params] = useSearchParams()
  const q = params.get('q')
  return (
    <div className="container">
      <div className="page-head" style={{ paddingTop: 96 }}>
        <div className="eyebrow">404</div>
        <h1 className="display">Nothing found</h1>
        <p className="sub">
          {q
            ? `No block, transaction, master node or BNS name matches “${q}”.`
            : 'The page you are looking for does not exist on this chain.'}
        </p>
        <div style={{ marginTop: 32, maxWidth: 720 }}>
          <SearchBar />
        </div>
        <div style={{ marginTop: 24 }}>
          <Link className="btn ghost sm" to="/">◂ BACK TO EXPLORER</Link>
        </div>
      </div>
    </div>
  )
}
