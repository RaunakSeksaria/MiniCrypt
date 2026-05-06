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
  }
};

export default api;
