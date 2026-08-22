// Mock data used when the Flask API is unreachable (VITE_USE_MOCK=1 or
// automatic fallback in dev). Shapes mirror /api/v2/* responses.

const now = Math.floor(Date.now() / 1000)
const hex = (seed) => {
  let s = ''
  let x = seed
  for (let i = 0; i < 64; i++) {
    x = (x * 48271) % 2147483647
    s += (x % 16).toString(16)
  }
  return s
}

const HEIGHT = 3421077

const mkBlock = (i) => ({
  height: HEIGHT - 1 - i,
  hash: hex(HEIGHT - i),
  timestamp: now - i * 30,
  block_size: 5300 + ((i * 977) % 12000),
  difficulty: 1834552 + ((i * 313) % 90000),
  reward: 10000000000 + ((i * 7919) % 2000000000),
  miner_tx_hash: hex(900000 + i),
  tx_count: i % 4,
  tx_hashes: Array.from({ length: i % 4 }, (_, j) => hex(i * 10 + j)),
  major_version: 17,
})

const mkTx = (i, coinbase = false) => ({
  tx_hash: hex(500000 + i),
  coinbase,
  block_height: HEIGHT - 1 - (i % 30),
  size: 1800 + ((i * 631) % 12000),
  version: 4,
  received_timestamp: now - i * 45,
  fee: coinbase ? 0 : 42640 + ((i * 97) % 20000),
  unlock_time: 0,
  vin: coinbase ? [{ gen: { height: HEIGHT - 1 - i } }] : [{ key: {} }, { key: {} }],
  vout: [{ amount: 0 }, { amount: 0 }],
  extra: {},
  in_pool: false,
})

const mkMn = (i, active = true, funded = true) => ({
  master_node_pubkey: hex(700000 + i),
  active,
  funded,
  operator_address: 'bxc' + hex(i).slice(0, 94),
  staking_requirement: 10000000000000,
  total_contributed: funded ? 10000000000000 : 4500000000000,
  total_reserved: funded ? 10000000000000 : 6000000000000,
  contribution_open: funded ? 0 : 4000000000000,
  contribution_required: funded ? 0 : 5500000000000,
  num_contributions: funded ? 2 + (i % 3) : 1,
  last_reward_block_height: HEIGHT - (i % 720),
  earned_downtime_blocks: active ? 1440 : 220,
  requested_unlock_height: 0,
  last_uptime_proof: now - (i % 3600),
  state_height: HEIGHT - 5000 - i * 17,
  swarm_id: 1229782938247303400 + i,
  ...(funded && !active ? { decomm_blocks_remaining: 220, decomm_blocks: 34 } : {}),
})

export const mock = {
  summary: {
    info: {
      height: HEIGHT,
      top_block_hash: hex(HEIGHT),
      difficulty: 1834552,
      target: 30,
      tx_count: 6392041,
      nettype: 'mainnet',
      version: '7.1.2',
      bns_counts: [412, 87, 231],
      database_size: 34359738368,
      status: 'OK',
    },
    stake: { height: HEIGHT, staking_requirement: 10000000000000 },
    fees: { fee_per_byte: 342, fee_per_output: 46000000, flash_fee_per_byte: 500, flash_fee_per_output: 60000000, flash_fee_fixed: 500000000 },
    hf: { version: 17, earliest_height: 3300000, enabled: true, state: 2 },
    emission: { emission_amount: 1052718344510000000, burn_amount: 189273541000000 },
    mempool: { tx_count: 3, bytes: 5642 },
    master_nodes: { active: 812, awaiting: 14, decommissioned: 6 },
  },

  blocks: (page = 0, perPage = 20) => ({
    height: HEIGHT,
    page,
    per_page: perPage,
    blocks: Array.from({ length: perPage }, (_, i) => mkBlock(page * perPage + i)),
  }),

  block: (id) => {
    const height = typeof id === 'number' || /^\d+$/.test(id) ? Number(id) : HEIGHT - 5
    const b = mkBlock(HEIGHT - 1 - height)
    return {
      block_header: {
        ...b,
        num_txes: b.tx_count,
        prev_hash: hex(height - 1),
        nonce: 1049507,
        cumulative_difficulty: 981237121237,
        depth: HEIGHT - 1 - height,
      },
      info: {},
      miner_tx: mkTx(height, true),
      transactions: Array.from({ length: b.tx_count }, (_, j) => mkTx(height * 7 + j)),
      next_height: height + 1 < HEIGHT ? height + 1 : null,
      chain_height: HEIGHT,
    }
  },

  tx: (txid) => ({
    tx: {
      ...mkTx(3),
      tx_hash: txid,
      info: {},
    },
  }),

  mempool: {
    txs: [mkTx(1), mkTx(2), mkTx(4)].map((t) => ({ ...t, in_pool: true, block_height: undefined })),
  },

  masterNodes: {
    height: HEIGHT,
    active: Array.from({ length: 24 }, (_, i) => mkMn(i, true, true)),
    awaiting: Array.from({ length: 4 }, (_, i) => mkMn(100 + i, false, false)),
    decommissioned: Array.from({ length: 2 }, (_, i) => mkMn(200 + i, false, true)),
  },

  mn: (pubkey) => ({
    height: HEIGHT,
    mn: {
      ...mkMn(7, true, true),
      master_node_pubkey: pubkey,
      pubkey_ed25519: hex(31337),
      contributors: [
        { address: 'bxc' + hex(11).slice(0, 94), amount: 6000000000000, reserved: 6000000000000, locked_contributions: [{ amount: 6000000000000 }] },
        { address: 'bxc' + hex(12).slice(0, 94), amount: 4000000000000, reserved: 4000000000000, locked_contributions: [{ amount: 4000000000000 }] },
      ],
      num_contributions: 2,
      num_reserved_spots: 0,
      num_open_spots: 0,
      portions_for_operator: 18446744073709551612,
      master_node_version: [7, 1, 2],
    },
  }),

  quorums: {
    height: HEIGHT,
    quorums: {
      obligation: Array.from({ length: 8 }, (_, i) => ({
        height: HEIGHT - 8 + i,
        quorum_type: 0,
        quorum: {
          validators: Array.from({ length: 10 }, (_, j) => hex(i * 100 + j)),
          workers: Array.from({ length: 5 }, (_, j) => hex(i * 100 + 50 + j)),
        },
      })),
      checkpoint: [],
      flash: [],
      POS: Array.from({ length: 3 }, (_, i) => ({
        height: HEIGHT - 3 + i,
        quorum_type: 3,
        quorum: {
          validators: Array.from({ length: 7 }, (_, j) => hex(i * 300 + j)),
          workers: [],
        },
      })),
    },
  },

  bns: (name) => ({
    bnsData: {
      name,
      available: name.length % 2 === 0,
      owner: name.length % 2 === 0 ? undefined : 'bxc' + hex(name.length).slice(0, 94),
      exp_height: HEIGHT + 100000,
      bchat: name.length % 2 === 0 ? '' : hex(name.length).slice(0, 66),
      belnet: '',
      wallet: name.length % 2 === 0 ? '' : 'bxc' + hex(name.length + 1).slice(0, 94),
      ethAddress: '',
    },
    status: 'ok',
  }),

  tokens: {
    offset: 0,
    count: 20,
    total_count: 2,
    tokens: [
      {
        token_id: hex(42),
        name: 'Example Token',
        ticker: 'EXT',
        total_max_supply: '1,000,000',
        current_supply: '250,000',
        decimal_point: 9,
        meta_info: '',
        owner: 'bxc' + hex(5).slice(0, 94),
        logo: '',
        social: '',
      },
      {
        token_id: hex(43),
        name: 'Demo Asset',
        ticker: 'DMA',
        total_max_supply: '21,000,000',
        current_supply: '18,930,112',
        decimal_point: 8,
        meta_info: '',
        owner: 'bxc' + hex(6).slice(0, 94),
        logo: '',
        social: '',
      },
    ],
  },

  search: (value) => {
    const v = (value || '').trim().replace(/\.bdx$/, '')
    if (/^\d{1,9}$/.test(v)) return { type: 'block', id: Number(v) }
    if (/^[0-9a-fA-F]{64}$/.test(v)) return { type: 'tx', id: v }
    if (v && v.length < 64 && /^[\w-]+$/.test(v)) return { type: 'bns', id: v }
    return { type: 'none', id: v }
  },
}
