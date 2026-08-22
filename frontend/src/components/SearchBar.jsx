import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'

export default function SearchBar({ autoFocus = false }) {
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  async function submit(e) {
    e.preventDefault()
    const v = value.trim()
    if (!v || busy) return
    setBusy(true)
    try {
      const r = await api.search(v)
      switch (r.type) {
        case 'block': navigate(`/block/${r.id}`); break
        case 'tx': navigate(`/tx/${r.id}`); break
        case 'mn': navigate(`/mn/${r.id}`); break
        case 'bns': navigate(`/bns/${r.id}`); break
        default: navigate(`/not_found?q=${encodeURIComponent(v)}`)
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="search" onSubmit={submit}>
      <input
        autoFocus={autoFocus}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="Search block height / block hash / tx hash / master node pubkey / BNS name"
        spellCheck={false}
      />
      <button type="submit">{busy ? '…' : 'SEARCH'}</button>
    </form>
  )
}
