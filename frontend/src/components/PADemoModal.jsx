import React, { useState, useEffect } from 'react';

const PA_DEFINITIONS = {
  1: { params: [] },
  2: { params: [] },
  3: { params: [{name: 'message', label: 'Plaintext Message', default: 'Hello CPA!'}] },
  4: { params: [{name: 'message', label: 'Plaintext Message', default: 'Modes of Operation test!'}] },
  5: { params: [{name: 'message', label: 'Message to Authenticate', default: 'Authenticate me!'}] },
  6: { params: [{name: 'message', label: 'Plaintext Message', default: 'CCA-secure message!'}] },
  7: { params: [{name: 'message', label: 'Message to Hash', default: 'Hello Hash!'}] },
  8: { params: [{name: 'message', label: 'Message to Hash', default: 'Test DLP Hash'}] },
  9: { params: [] },
  10: { params: [{name: 'message', label: 'Message to HMAC', default: 'HMAC test message'}] },
  11: { params: [] },
  12: { params: [{name: 'message_int', label: 'Textbook RSA Message (Int)', default: '42'}, {name: 'message_pkcs', label: 'PKCS#1 Message (Text)', default: 'RSA!'}] },
  13: { params: [{name: 'n', label: 'Number to Test Primality', default: '1009'}] },
  14: { params: [{name: 'residues', label: 'Residues (comma separated)', default: '2,3,2'}, {name: 'moduli', label: 'Moduli (comma separated)', default: '3,5,7'}] },
  15: { params: [{name: 'message', label: 'Message to Sign', default: 'Sign this!'}] },
  16: { params: [{name: 'message_int', label: 'ElGamal Message (Int)', default: '42'}] },
  17: { params: [{name: 'message_int', label: 'CCA-PKC Message (Int)', default: '42'}] },
  18: { params: [{name: 'm0', label: 'Message 0 (Int)', default: '42'}, {name: 'm1', label: 'Message 1 (Int)', default: '99'}, {name: 'b', label: 'Choice Bit (0 or 1)', default: '0'}] },
  19: { params: [{name: 'a', label: 'Alice Input (0 or 1)', default: '1'}, {name: 'b', label: 'Bob Input (0 or 1)', default: '1'}] },
  20: { params: [{name: 'alice_val', label: 'Alice Value (0-15)', default: '7'}, {name: 'bob_val', label: 'Bob Value (0-15)', default: '3'}] },
};

const PADemoModal = ({ pa, onClose, api }) => {
  const [params, setParams] = useState({});
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const def = PA_DEFINITIONS[pa.pa] || { params: [] };

  useEffect(() => {
    // Set initial params
    const initialParams = {};
    def.params.forEach(p => initialParams[p.name] = p.default);
    setParams(initialParams);

    // Auto-run if no params
    if (def.params.length === 0) {
      runDemo(initialParams);
    }
  }, [pa]);

  const runDemo = async (currentParams = params) => {
    setIsLoading(true);
    setResult(null);
    setError(null);
    try {
      const data = await api.runDemo(pa.pa, currentParams);
      if (data.detail) {
        setError(data.detail);
      } else {
        setResult(data);
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setIsLoading(false);
    }
  };

  const renderResult = (data) => {
    const kvRow = (k, v) => {
      const cls = v === true ? 'tag-true' : v === false ? 'tag-false' : '';
      const display = typeof v === 'boolean' ? (v ? '✓ True' : '✗ False') : String(v);
      return (
        <div className="kv" key={k}>
          <span className="k">{k}</span>
          <span className={`v ${cls}`}>{display}</span>
        </div>
      );
    };

    const renderSection = (title, obj) => {
      let items = [];
      if (typeof obj === 'object' && obj !== null) {
        for (const [k, v] of Object.entries(obj)) {
          if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
            items.push(
              <div key={k}>
                <h3 style={{ fontSize: '14px', fontWeight: '600', margin: '16px 0 8px', color: 'var(--accent3)' }}>{k}</h3>
                {renderSection(k, v)}
              </div>
            );
          } else if (Array.isArray(v)) {
            items.push(kvRow(k, JSON.stringify(v)));
          } else {
            items.push(kvRow(k, v));
          }
        }
      } else {
        items.push(<pre key="raw">{JSON.stringify(obj, null, 2)}</pre>);
      }
      return items;
    };

    return (
      <div className="demo-result">
        {Object.entries(data).map(([k, v]) => {
          if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
            return (
              <div key={k}>
                <h3 style={{ fontSize: '14px', fontWeight: '600', margin: '16px 0 8px', color: 'var(--accent3)' }}>{k}</h3>
                {renderSection(k, v)}
              </div>
            );
          } else {
            return kvRow(k, v);
          }
        })}
      </div>
    );
  };

  return (
    <div className="modal-overlay open" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">
          <h2>PA#{pa.pa} — {pa.title}</h2>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <div style={{ marginBottom: '20px', paddingBottom: '16px', borderBottom: '1px solid var(--border)' }}>
            <p style={{ color: 'var(--text2)', fontSize: '13px', marginBottom: '16px' }}>{pa.desc}</p>
            
            {def.params.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '16px' }}>
                {def.params.map(p => (
                  <div className="field" key={p.name} style={{ marginBottom: 0 }}>
                    <label>{p.label}</label>
                    <input 
                      type="text" 
                      value={params[p.name] || ''} 
                      onChange={(e) => setParams({ ...params, [p.name]: e.target.value })} 
                    />
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: 'var(--accent3)', fontSize: '12px', fontWeight: 500, marginBottom: '16px' }}>
                (No configurable parameters — uses random/default values)
              </p>
            )}
            
            <button className="btn btn-primary" style={{ width: '100%' }} onClick={() => runDemo()}>
              ▶ Run Demo
            </button>
          </div>

          <div id="demoOutputContainer">
            {isLoading && <div style={{ textAlign: 'center', padding: '20px' }}><div className="spinner"></div></div>}
            {error && <pre style={{ color: 'var(--red)' }}>{error}</pre>}
            {result && renderResult(result)}
          </div>
        </div>
      </div>
    </div>
  );
};

export default PADemoModal;
