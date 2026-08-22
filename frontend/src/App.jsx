import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom'
import Layout from './components/Layout'
import Home from './pages/Home'
import Block from './pages/Block'
import Tx from './pages/Tx'
import Mempool from './pages/Mempool'
import MasterNodes from './pages/MasterNodes'
import MasterNode from './pages/MasterNode'
import Quorums from './pages/Quorums'
import Bns from './pages/Bns'
import Tokens from './pages/Tokens'
import NotFound from './pages/NotFound'

// Backwards-compatible redirect for old /master_node/<pubkey> URLs.
function LegacyMn() {
  const { pubkey } = useParams()
  return <Navigate to={`/mn/${pubkey}`} replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Home />} />
          <Route path="/block/:id" element={<Block />} />
          <Route path="/tx/:txid" element={<Tx />} />
          <Route path="/txpool" element={<Mempool />} />
          <Route path="/master_nodes" element={<MasterNodes />} />
          <Route path="/mn/:pubkey" element={<MasterNode />} />
          <Route path="/master_node/:pubkey" element={<LegacyMn />} />
          <Route path="/quorums" element={<Quorums />} />
          <Route path="/bns" element={<Bns />} />
          <Route path="/bns/:name" element={<Bns />} />
          <Route path="/tokens" element={<Tokens />} />
          <Route path="/not_found" element={<NotFound />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
