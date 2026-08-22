import { useEffect, useState } from 'react'

// Small data-fetching hook with optional auto-refresh (seconds).
export function useFetch(fn, deps = [], { refresh = 0 } = {}) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    let timer
    const load = async (initial) => {
      if (initial) setLoading(true)
      try {
        const d = await fn()
        if (alive) {
          setData(d)
          setError(null)
        }
      } catch (e) {
        if (alive && initial) setError(e)
      } finally {
        if (alive && initial) setLoading(false)
      }
    }
    load(true)
    if (refresh > 0) timer = setInterval(() => load(false), refresh * 1000)
    return () => {
      alive = false
      if (timer) clearInterval(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return { data, error, loading }
}
