const API_BASE = ''; // Proxy will handle this

const api = {
  onProofUpdate: null,
  
  async build({ foundation, source, seed }) {
    const r = await fetch(`${API_BASE}/api/build`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ foundation, source, seed })
    });
    return r.json();
  },

  async reduce({ foundation, source, target, seed, query }) {
    const r = await fetch(`${API_BASE}/api/reduce`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ foundation, source, target, seed, query })
    });
    return r.json();
  },

  async runDemo(pa, params) {
    const r = await fetch(`${API_BASE}/api/demo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pa, params })
    });
    return r.json();
  },

  async pa8Hash(message) {
    const r = await fetch(`${API_BASE}/api/pa8/hash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message })
    });
    return r.json();
  },

  async pa8CollisionStart() {
    const r = await fetch(`${API_BASE}/api/pa8/collision/start`, { method: 'POST' });
    return r.json();
  },

  async pa8CollisionStatus(huntId) {
    const r = await fetch(`${API_BASE}/api/pa8/collision/status/${huntId}`);
    return r.json();
  },

  async pa8CollisionStop(huntId) {
    const r = await fetch(`${API_BASE}/api/pa8/collision/stop/${huntId}`, { method: 'POST' });
    return r.json();
  },

  async pa9BirthdayStart(nBits) {
    const r = await fetch(`${API_BASE}/api/pa9/birthday/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ n_bits: nBits }),
    });
    return r.json();
  },

  async pa9BirthdayStatus(huntId) {
    const r = await fetch(`${API_BASE}/api/pa9/birthday/status/${huntId}`);
    return r.json();
  },

  async pa9BirthdayStop(huntId) {
    const r = await fetch(`${API_BASE}/api/pa9/birthday/stop/${huntId}`, { method: 'POST' });
    return r.json();
  },

  async pa10LengthExtension(suffix, hashMode = 'dlp') {
    const r = await fetch(`${API_BASE}/api/pa10/length_extension`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ suffix, hash_mode: hashMode }),
    });
    return r.json();
  },

  async pa10HMAC(message, keyHex = '', tagHex = '') {
    const r = await fetch(`${API_BASE}/api/pa10/hmac`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, key_hex: keyHex, tag_hex: tagHex }),
    });
    return r.json();
  },

  async pa10EufCma() {
    const r = await fetch(`${API_BASE}/api/pa10/euf_cma`, { method: 'POST' });
    return r.json();
  },

  async pa10MacCrhf() {
    const r = await fetch(`${API_BASE}/api/pa10/mac_crhf`, { method: 'POST' });
    return r.json();
  },

  async pa10EthEnc(message, keyEncHex = '', keyMacHex = '') {
    const r = await fetch(`${API_BASE}/api/pa10/eth_enc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, key_enc_hex: keyEncHex, key_mac_hex: keyMacHex }),
    });
    return r.json();
  },

  async pa10EthDec(keyEncHex, keyMacHex, nonceHex, ciphertextHex, tagHex, tamperByte = -1) {
    const r = await fetch(`${API_BASE}/api/pa10/eth_dec`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key_enc_hex: keyEncHex, key_mac_hex: keyMacHex,
        nonce_hex: nonceHex, ciphertext_hex: ciphertextHex,
        tag_hex: tagHex, tamper_byte: tamperByte,
      }),
    });
    return r.json();
  },

  async pa10Timing() {
    const r = await fetch(`${API_BASE}/api/pa10/timing`, { method: 'POST' });
    return r.json();
  },

  async pa10CcaGame(rounds = 30) {
    const r = await fetch(`${API_BASE}/api/pa10/cca_game`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rounds }),
    });
    return r.json();
  },

  // ── PA#11 Diffie-Hellman ──
  async pa11Exchange(a = null, b = null) {
    const r = await fetch(`${API_BASE}/api/pa11/exchange`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ a, b }),
    });
    return r.json();
  },

  async pa11Mitm(a = null, b = null) {
    const r = await fetch(`${API_BASE}/api/pa11/mitm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ a, b }),
    });
    return r.json();
  },

  async pa11Cdh(bits = 20) {
    const r = await fetch(`${API_BASE}/api/pa11/cdh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bits }),
    });
    return r.json();
  },

  // ── PA#18 Oblivious Transfer ──
  async pa18Play(b, m0, m1) {
    const r = await fetch(`${API_BASE}/api/pa18/ot/play`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ b, m0, m1 }),
    });
    return r.json();
  },

  async pa18Correctness() {
    const r = await fetch(`${API_BASE}/api/pa18/ot/correctness`, { method: 'POST' });
    return r.json();
  },

  async pa18Privacy() {
    const r = await fetch(`${API_BASE}/api/pa18/ot/privacy`, { method: 'POST' });
    return r.json();
  },
};

export default api;
