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
};

export default api;
