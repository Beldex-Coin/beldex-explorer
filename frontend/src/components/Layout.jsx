import { useState } from 'react'
import { NavLink, Link, Outlet } from 'react-router-dom'
import Logo from './Logo'

const NAV = [
  ['/', 'Explorer', true],
  ['/master_nodes', 'Master Nodes'],
  ['/txpool', 'Mempool'],
  ['/quorums', 'Quorums'],
  ['/tokens', 'Tokens'],
  ['/bns', 'BNS'],
]

export default function Layout() {
  const [open, setOpen] = useState(false)
  return (
    <>
      <header className="site-header">
        <div className="container inner">
          <Link to="/" className="brand">
            <Logo />
            BELDEX
          </Link>
          <button className="nav-toggle" onClick={() => setOpen(!open)} aria-label="Menu">
            ☰
          </button>
          <nav className={`nav${open ? ' open' : ''}`} onClick={() => setOpen(false)}>
            {NAV.map(([to, label, end]) => (
              <NavLink key={to} to={to} end={end} className={({ isActive }) => (isActive ? 'active' : '')}>
                {label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="dotfield page">
        <Outlet />
      </main>
      <footer className="site-footer">
        <div className="container inner">
          <span>BELDEX EXPLORER — Privacy, in every online interaction.</span>
          <div className="links">
            <a href="https://beldex.io" target="_blank" rel="noreferrer">beldex.io</a>
            <a href="https://x.com/BeldexCoin" target="_blank" rel="noreferrer">X</a>
            <a href="https://discord.gg/beldex" target="_blank" rel="noreferrer">Discord</a>
            <a href="https://www.instagram.com/beldexcoin" target="_blank" rel="noreferrer">Instagram</a>
          </div>
        </div>
      </footer>
    </>
  )
}
