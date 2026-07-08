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

  async pa5EufInit() {
    const r = await fetch(`${API_BASE}/api/mac/euf_init`);
    return r.json();
  },

  async pa5EufVerify(sessionId, messageHex, tagHex) {
    const r = await fetch(`${API_BASE}/api/mac/euf_verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, message_hex: messageHex, tag_hex: tagHex }),
    });
    return r.json();
  },

  async pa5EufCheat(sessionId) {
    const r = await fetch(`${API_BASE}/api/mac/euf_cheat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId }),
    });
    return r.json();
  },

  async pa5LengthExtension(suffix) {
    const r = await fetch(`${API_BASE}/api/mac/length_extension`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ suffix }),
    });
    return r.json();
  },

  async pa6MalleabilityInit(message) {
    const r = await fetch(`${API_BASE}/api/cca_enc/malleability_init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    });
    return r.json();
  },

  async pa6MalleabilityFlip(payload) {
    const r = await fetch(`${API_BASE}/api/cca_enc/malleability_flip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return r.json();
  },

  async pa8Hash(message) {
    const r = await fetch(`${API_BASE}/api/dlp_crhf/hash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message })
    });
    return r.json();
  },

  async pa17MalleabilityInit(message) {
    const r = await fetch(`${API_BASE}/api/cca_pkc/malleability_init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: parseInt(message) || 42 }),
    });
    return r.json();
  },

  async pa17MalleabilityFlip(payload) {
    const r = await fetch(`${API_BASE}/api/cca_pkc/malleability_flip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return r.json();
  },
  async pa19SecureAnd(a, b) {
    const r = await fetch(`${API_BASE}/api/secure_and/gate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ a, b }),
    });
    return r.json();
  },

  async pa19TruthTable() {
    const r = await fetch(`${API_BASE}/api/secure_and/truth_table`, { method: 'POST' });
    return r.json();
  },

  async pa20Evaluate(alice_val, bob_val, mode = 'comparator', bits = 4) {
    const r = await fetch(`${API_BASE}/api/mpc/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alice_val, bob_val, bits, mode }),
    });
    return r.json();
  },

  async pa8CollisionStart() {
    const r = await fetch(`${API_BASE}/api/dlp_crhf/collision/start`, { method: 'POST' });
    return r.json();
  },

  async pa8CollisionStatus(huntId) {
    const r = await fetch(`${API_BASE}/api/dlp_crhf/collision/status/${huntId}`);
    return r.json();
  },

  async pa8CollisionStop(huntId) {
    const r = await fetch(`${API_BASE}/api/dlp_crhf/collision/stop/${huntId}`, { method: 'POST' });
    return r.json();
  },

  async pa9BirthdayStart(nBits) {
    const r = await fetch(`${API_BASE}/api/birthday/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ n_bits: nBits }),
    });
    return r.json();
  },

  async pa9BirthdayStatus(huntId) {
    const r = await fetch(`${API_BASE}/api/birthday/status/${huntId}`);
    return r.json();
  },

  async pa9BirthdayStop(huntId) {
    const r = await fetch(`${API_BASE}/api/birthday/stop/${huntId}`, { method: 'POST' });
    return r.json();
  },

  async pa10LengthExtension(suffix, hashMode = 'dlp') {
    const r = await fetch(`${API_BASE}/api/hmac/length_extension`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ suffix, hash_mode: hashMode }),
    });
    return r.json();
  },

  // ── Diffie-Hellman ──
  async pa11Exchange(a = null, b = null) {
    const r = await fetch(`${API_BASE}/api/diffie_hellman/exchange`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ a, b }),
    });
    return r.json();
  },

  async pa11Mitm(a = null, b = null) {
    const r = await fetch(`${API_BASE}/api/diffie_hellman/mitm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ a, b }),
    });
    return r.json();
  },

  async pa11Cdh(bits = 20) {
    const r = await fetch(`${API_BASE}/api/diffie_hellman/cdh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bits }),
    });
    return r.json();
  },

  // ── Oblivious Transfer ──
  async pa18Play(b, m0, m1) {
    const r = await fetch(`${API_BASE}/api/ot/play`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ b, m0, m1 }),
    });
    return r.json();
  },

  // ── IND-CPA Interactive Game ──
  async pa3Init(broken = false) {
    const r = await fetch(`${API_BASE}/api/cpa_enc/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ broken }),
    });
    return r.json();
  },

  async pa18Correctness() {
    const r = await fetch(`${API_BASE}/api/ot/correctness`, { method: 'POST' });
    return r.json();
  },

  async pa18Privacy() {
    const r = await fetch(`${API_BASE}/api/ot/privacy`, { method: 'POST' });
    return r.json();
  },

  async pa3Oracle(sessionId, message) {
    const r = await fetch(`${API_BASE}/api/cpa_enc/oracle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, message }),
    });
    return r.json();
  },

  async pa3Challenge(sessionId, m0, m1) {
    const r = await fetch(`${API_BASE}/api/cpa_enc/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, m0, m1 }),
    });
    return r.json();
  },

  async pa3Guess(sessionId, guess) {
    const r = await fetch(`${API_BASE}/api/cpa_enc/guess`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, guess }),
    });
    return r.json();
  },

  async pa3Simulate(rounds = 20, broken = false) {
    const r = await fetch(`${API_BASE}/api/cpa_enc/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rounds, broken }),
    });
    return r.json();
  },

  // ── Modes Visual Animator ──
  async pa4Animate(mode, message, keyHex = '', ivHex = '') {
    const r = await fetch(`${API_BASE}/api/modes/animate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, message, key_hex: keyHex, iv_hex: ivHex }),
    });
    return r.json();
  },

  async pa4Flip(mode, keyHex, ivHex, ciphertextHex, flipBlock) {
    const r = await fetch(`${API_BASE}/api/modes/flip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, key_hex: keyHex, iv_hex: ivHex, ciphertext_hex: ciphertextHex, flip_block: flipBlock }),
    });
    return r.json();
  },

  async pa4IvReuse(message1, message2, keyHex = '', ivHex = '') {
    const r = await fetch(`${API_BASE}/api/modes/iv_reuse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message1, message2, key_hex: keyHex, iv_hex: ivHex }),
    });
    return r.json();
  },
};

export default api;
