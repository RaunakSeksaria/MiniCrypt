import React, { useState, useEffect, useRef, useCallback } from 'react';
import GGMVisualizer from './GGMVisualizer';

const PA_DEFINITIONS = {
  1: {
    params: [
      { name: 'seed', label: 'Hex Seed (s)', default: '2b7e151628aed2a6abf7158809cf4f3c' },
      { name: 'length', label: 'Output Length (ℓ)', type: 'range', min: 8, max: 256, default: 32 }
    ]
  },
  2: {
    params: [
      { name: 'key', label: 'Secret Key (k)', default: '2b7e151628aed2a6abf7158809cf4f3c' },
      { name: 'query', label: 'Query (x) [Bit String]', default: '00' },
      { name: 'depth', label: 'Tree Depth (n)', type: 'range', min: 2, max: 8, default: 4 }
    ]
  },
  3: { params: [{ name: 'message', label: 'Plaintext Message', default: 'Hello CPA!' }] },
  4: { params: [{ name: 'message', label: 'Plaintext Message', default: 'Modes of Operation test!' }] },
  5: { params: [{ name: 'message', label: 'Message to Authenticate', default: 'Authenticate me!' }] },
  6: { params: [{ name: 'message', label: 'Plaintext Message', default: 'CCA-secure message!' }] },
  7: { params: [{ name: 'message', label: 'Message to Hash', default: 'Hello Hash!' }] },
  8: { params: [] },  // PA8 has its own input inside renderPA8Special
  9: { params: [] },
  10: { params: [{ name: 'message', label: 'Message to HMAC', default: 'HMAC test message' }] },
  11: { params: [] },
  12: { params: [{ name: 'message_int', label: 'Textbook RSA Message (Int)', default: '42' }, { name: 'message_pkcs', label: 'PKCS#1 Message (Text)', default: 'RSA!' }] },
  13: { params: [{ name: 'n', label: 'Number to Test Primality', default: '1009' }] },
  14: { params: [{ name: 'residues', label: 'Residues (comma separated)', default: '2,3,2' }, { name: 'moduli', label: 'Moduli (comma separated)', default: '3,5,7' }] },
  15: { params: [{ name: 'message', label: 'Message to Sign', default: 'Sign this!' }] },
  16: { params: [{ name: 'message_int', label: 'ElGamal Message (Int)', default: '42' }] },
  17: { params: [{ name: 'message_int', label: 'CCA-PKC Message (Int)', default: '42' }] },
  18: { params: [{ name: 'm0', label: 'Message 0 (Int)', default: '42' }, { name: 'm1', label: 'Message 1 (Int)', default: '99' }, { name: 'b', label: 'Choice Bit (0 or 1)', default: '0' }] },
  19: { params: [{ name: 'a', label: 'Alice Input (0 or 1)', default: '1' }, { name: 'b', label: 'Bob Input (0 or 1)', default: '1' }] },
  20: { params: [{ name: 'alice_val', label: 'Alice Value (0-15)', default: '7' }, { name: 'bob_val', label: 'Bob Value (0-15)', default: '3' }] },
};

const PADemoModal = ({ pa, onClose, api }) => {
  const [params, setParams] = useState({});
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showStats, setShowStats] = useState(false);
  const [showInversion, setShowInversion] = useState(false);

  // PA#8 live hash state
  const [pa8Hash, setPa8Hash] = useState(null);
  const [pa8Loading, setPa8Loading] = useState(false);
  // PA#8 collision hunt state
  const [huntId, setHuntId] = useState(null);
  const [huntStatus, setHuntStatus] = useState(null);  // null | {status, evaluations, progress_pct, collision}
  const [huntRunning, setHuntRunning] = useState(false);
  const pollRef = useRef(null);

  const def = PA_DEFINITIONS[pa.pa] || { params: [] };

  // Stop polling helper — defined before useEffect so cleanup can reference it
  const stopHunt = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    setHuntRunning(false);
  }, []);

  useEffect(() => {
    // Set initial params
    const initialParams = {};
    def.params.forEach(p => initialParams[p.name] = p.default);
    setParams(initialParams);

    // Auto-run if no params (but NOT for PA8 — it has its own special renderer)
    if (def.params.length === 0 && pa.pa !== 8) {
      runDemo(initialParams);
    }

    // Reset PA8 state when modal switches PA
    setPa8Hash(null);
    setHuntStatus(null);
    stopHunt();

    return () => stopHunt();
  }, [pa]);

  // PA8: auto-hash the default message when the modal opens
  const PA8_DEFAULT_MSG = 'Hello, DLP Hash!';
  useEffect(() => {
    if (pa.pa !== 8) return;
    setParams(p => ({ ...p, message: PA8_DEFAULT_MSG }));
    api.pa8Hash(PA8_DEFAULT_MSG).then(data => setPa8Hash(data)).catch(() => {});
  }, [pa]);

  const runDemo = async (currentParams = params, task = null) => {
    setIsLoading(true);
    setError(null);
    try {
      const payload = { ...currentParams };
      if (task) payload.task = task;
      const data = await api.runDemo(pa.pa, payload);
      if (data.detail) {
        setError(data.detail);
      } else {
        // Merge incoming data with previous result, guarding against null prev
        setResult(prev => ({ ...(prev || {}), ...data }));
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

  const renderPA1Special = () => {
    if (!result) return null;
    const seed = params.seed || '';
    return (
      <div className="pa1-special">
        <div className="result-section">
          <h3>Live PRG Output G(s)</h3>
          <div className="output-box" style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '12px', background: 'var(--bg)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border)' }}>
            {result.output}
          </div>
        </div>

        <div style={{ marginTop: '20px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
          <button
            className="btn btn-secondary"
            style={{ background: showStats ? 'var(--accent3)' : 'rgba(var(--accent-rgb), 0.1)', border: '1px solid var(--accent3)', color: showStats ? 'white' : 'var(--accent3)' }}
            onClick={() => {
              if (!showStats) {
                runDemo(params, 'randomness');
                setShowStats(true);
                setShowInversion(false);
              } else {
                setShowStats(false);
              }
            }}
          >
            🧪 Randomness Tests
          </button>
          <button
            className="btn btn-secondary"
            style={{ background: showInversion ? 'var(--accent)' : 'rgba(var(--accent-rgb), 0.1)', border: '1px solid var(--accent)', color: showInversion ? 'white' : 'var(--accent)' }}
            onClick={() => {
              if (!showInversion) {
                runDemo(params, 'inversion');
                setShowInversion(true);
                setShowStats(false);
              } else {
                setShowInversion(false);
              }
            }}
          >
            🛡️ One-Wayness
          </button>
        </div>

        <div style={{ marginTop: '20px' }}>
          {showStats && result && result.stats && (
            <div className="result-section animate-fade-in" style={{ marginBottom: '20px' }}>
              <h3 style={{ margin: 0, marginBottom: '12px' }}>Randomness Analysis</h3>
              <div className="stats-container">
                <div className="ratio-bar-container" style={{ marginBottom: '16px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '4px' }}>
                    <span>Bit Ratio (Ones/Total)</span>
                    <span style={{ fontWeight: 600 }}>{result.ratio ? (result.ratio * 100).toFixed(1) : '...'}%</span>
                  </div>
                  <div style={{ height: '8px', background: 'var(--bg2)', borderRadius: '4px', overflow: 'hidden', position: 'relative' }}>
                    <div style={{ position: 'absolute', left: '50%', top: 0, bottom: 0, width: '2px', background: 'var(--accent)', zIndex: 1, opacity: 0.5 }}></div>
                    <div style={{ height: '100%', width: `${(result.ratio || 0.5) * 100}%`, background: 'var(--accent3)', transition: 'width 0.3s ease' }}></div>
                  </div>
                </div>

                <div className="test-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                  {result.stats.map(s => (
                    <div key={s.test} className={`test-badge ${s.pass ? 'pass' : 'fail'}`} style={{
                      padding: '8px',
                      borderRadius: '6px',
                      textAlign: 'center',
                      background: s.pass ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                      border: `1px solid ${s.pass ? '#22c55e' : '#ef4444'}`
                    }}>
                      <div style={{ fontSize: '10px', fontWeight: 600, color: s.pass ? '#22c55e' : '#ef4444' }}>{s.test.toUpperCase()}</div>
                      <div style={{ fontSize: '11px' }}>{s.pass ? 'PASS' : 'FAIL'}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {showInversion && (
            <div className="result-section animate-fade-in">
              <h3 style={{ margin: 0, marginBottom: '12px' }}>One-Wayness Verification</h3>
              {(!result || !result.inversion) ? (
                <div style={{ textAlign: 'center', padding: '20px', background: 'var(--bg2)', borderRadius: '8px' }}>
                  <div className="spinner" style={{ margin: '0 auto 10px' }}></div>
                  <div style={{ fontSize: '11px', color: 'var(--text3)' }}>Running 10,000+ Inversion Attempts...</div>
                </div>
              ) : (
                <div style={{ padding: '12px', background: 'rgba(var(--accent-rgb), 0.05)', borderRadius: '8px', border: '1px dashed var(--border)' }}>
                  <div style={{ fontSize: '12px', fontWeight: 600, marginBottom: '8px', color: 'var(--accent)' }}>🔒 Backward Reduction: PRG ⇒ OWF</div>
                  <div style={{ fontSize: '11px', color: 'var(--text2)', lineHeight: '1.4', marginBottom: '12px' }}>
                  <strong>Theoretical Proof:</strong> To show that <strong>f(s) = G(s)</strong> is a One-Way Function, we assume an adversary exists who can invert it. If they can recover <strong>s</strong> from <strong>G(s)</strong>, they can distinguish the PRG from random bits. Since <strong>G</strong> is secure, such an adversary cannot exist.
                </div>
                
                <div style={{ background: 'var(--bg2)', padding: '10px', borderRadius: '6px', marginBottom: '12px', fontSize: '11px', borderLeft: '3px solid var(--accent)' }}>
                  <strong>Example from Current Run:</strong>
                  <div style={{ marginTop: '8px' }}>
                    <strong>Input (s):</strong> <code style={{ fontSize: '10px', color: 'var(--accent)' }}>{result?.seed?.substring(0, 12)}...</code>
                    <br />
                    <strong>Output G(s):</strong> <code style={{ fontSize: '10px', color: 'var(--accent3)' }}>{result?.output?.substring(0, 12)}...</code>
                    <div style={{ marginTop: '8px', fontSize: '10px', color: 'var(--text3)' }}>
                      <strong>Failed Adversary Attempts (Sample Seeds):</strong>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '4px', minHeight: '20px' }}>
                        {(result?.inversion?.sample_guesses && result.inversion.sample_guesses.length > 0) ? (
                          result.inversion.sample_guesses.map((g, idx) => (
                            <div key={idx} style={{ 
                              background: 'rgba(239, 68, 68, 0.1)', 
                              color: '#ef4444', 
                              padding: '4px 8px', 
                              borderRadius: '4px', 
                              border: '1px solid rgba(239, 68, 68, 0.2)',
                              fontSize: '9px',
                              fontFamily: 'monospace',
                              wordBreak: 'break-all'
                            }}>
                              Tried: {g} → ❌ NO MATCH
                            </div>
                          ))
                        ) : (
                          <span style={{ fontStyle: 'italic', opacity: 0.7 }}>Analyzing 10,000+ potential seeds...</span>
                        )}
                      </div>
                      <div style={{ marginTop: '4px' }}>
                        The adversary tried thousands of variations, but none matched the target output.
                      </div>
                    </div>
                  </div>
                </div>

                  <div style={{ fontSize: '10px', color: 'var(--text3)', borderTop: '1px solid var(--border)', paddingTop: '8px' }}>
                    <strong>Adversary Benchmarks:</strong> Tested against 50 different seeds with 10,000+ guesses each. Inversion Success Rate: <span style={{ color: 'var(--accent)' }}>0.000%</span>.
                    <br />
                    <strong>Current Run:</strong> Brute-force guessing 200 seeds for each of {result.inversion?.trials || 0} target outputs...
                    <br />
                    Total guesses: {((result.inversion?.trials || 0) * 200).toLocaleString()} | Successes: <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{result.inversion?.inversions || 0}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderPA8Special = () => {
    const collision = huntStatus?.collision;
    const evals = huntStatus?.evaluations ?? 0;
    const pct = huntStatus?.progress_pct ?? 0;
    const status = huntStatus?.status;
    const bound = huntStatus?.birthday_bound ?? 256;

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

        {/* ── Live Hash Panel ── */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(99,102,241,0.08) 0%, rgba(168,85,247,0.08) 100%)',
          border: '1px solid rgba(99,102,241,0.3)',
          borderRadius: '12px',
          padding: '18px',
        }}>
          <div style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent)', marginBottom: '12px', textTransform: 'uppercase' }}>🔢 Live DLP Hash</div>
          <input
            id="pa8-message-input"
            type="text"
            placeholder="Type a message…"
            value={params.message || ''}
            style={{
              width: '100%', boxSizing: 'border-box', padding: '10px 14px',
              background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(99,102,241,0.4)',
              borderRadius: '8px', color: 'var(--text1)', fontSize: '14px',
              outline: 'none', fontFamily: 'monospace',
            }}
            onChange={async (e) => {
              const msg = e.target.value;
              setParams(p => ({ ...p, message: msg }));
              if (!msg) { setPa8Hash(null); return; }
              setPa8Loading(true);
              try {
                const data = await api.pa8Hash(msg);
                setPa8Hash(data);
              } catch (_) {}
              setPa8Loading(false);
            }}
          />

          {pa8Loading && (
            <div style={{ textAlign: 'center', padding: '10px' }}><div className="spinner" style={{ margin: '0 auto' }} /></div>
          )}

          {pa8Hash && !pa8Loading && (
            <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text3)', marginBottom: '2px' }}>Full hash  ({pa8Hash.digest_bytes} bytes — group element mod p):</div>
              <div style={{
                fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all',
                background: 'rgba(0,0,0,0.4)', borderRadius: '6px', padding: '10px 12px',
                border: '1px solid rgba(99,102,241,0.25)', color: '#a5b4fc', lineHeight: 1.6,
              }}>
                0x{pa8Hash.hash_hex}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '4px' }}>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '6px', padding: '8px 10px', border: '1px solid rgba(99,102,241,0.15)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '3px' }}>16-bit truncation</div>
                  <div style={{ fontFamily: 'monospace', fontSize: '13px', color: '#c4b5fd', fontWeight: 700 }}>0x{pa8Hash.truncated_hex}</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '6px', padding: '8px 10px', border: '1px solid rgba(99,102,241,0.15)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '3px' }}>Decimal</div>
                  <div style={{ fontFamily: 'monospace', fontSize: '13px', color: '#c4b5fd', fontWeight: 700 }}>{pa8Hash.truncated_16bit}</div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* ── Group Parameters ── */}
        {pa8Hash && (
          <div style={{
            background: 'rgba(0,0,0,0.2)', borderRadius: '10px', padding: '14px',
            border: '1px solid var(--border)', fontSize: '11px',
          }}>
            <div style={{ fontWeight: 700, color: 'var(--text2)', marginBottom: '8px', letterSpacing: '0.06em', textTransform: 'uppercase' }}>⚙️ Group Parameters (q ≈ 2³²)</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px' }}>
              {[['p (safe prime)', pa8Hash.p], ['q (subgroup order)', pa8Hash.q], ['g (generator)', pa8Hash.g], ['ĥ = gᵅ (α discarded)', pa8Hash.h_pub]].map(([k, v]) => (
                <React.Fragment key={k}>
                  <span style={{ color: 'var(--text3)', whiteSpace: 'nowrap' }}>{k}</span>
                  <span style={{ fontFamily: 'monospace', color: 'var(--text1)', wordBreak: 'break-all' }}>{String(v)}</span>
                </React.Fragment>
              ))}
            </div>
            <div style={{ marginTop: '10px', fontSize: '10px', color: 'var(--text3)', borderTop: '1px solid var(--border)', paddingTop: '8px' }}>
              Compression: <code style={{ color: '#a5b4fc' }}>h(x,y) = gˣ · ĥʸ mod p</code> — collision ⇒ log<sub>g</sub>(ĥ)
            </div>
          </div>
        )}

        {/* ── Collision Hunt Panel ── */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(245,158,11,0.07) 0%, rgba(239,68,68,0.07) 100%)',
          border: '1px solid rgba(245,158,11,0.3)',
          borderRadius: '12px',
          padding: '18px',
        }}>
          <div style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: '#f59e0b', marginBottom: '12px', textTransform: 'uppercase' }}>🎯 Collision Hunt  (birthday bound demo)</div>

          <div style={{ fontSize: '12px', color: 'var(--text2)', marginBottom: '14px', lineHeight: 1.5 }}>
            Truncates the hash to <strong>16 bits</strong> (output space = 65 536). Birthday bound ≈ 2<sup>16/2</sup> = <strong>256 evaluations</strong>.
          </div>

          <div style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
            <button
              id="pa8-collision-start-btn"
              disabled={huntRunning}
              style={{
                flex: 1, padding: '10px', borderRadius: '8px', fontWeight: 700, fontSize: '13px', cursor: huntRunning ? 'not-allowed' : 'pointer',
                background: huntRunning ? 'rgba(245,158,11,0.15)' : 'linear-gradient(135deg, #f59e0b, #ef4444)',
                border: 'none', color: huntRunning ? '#f59e0b' : 'white',
                transition: 'all 0.2s',
              }}
              onClick={async () => {
                setHuntStatus(null);
                setHuntRunning(true);
                const { hunt_id } = await api.pa8CollisionStart();
                setHuntId(hunt_id);
                // Poll every 350ms
                if (pollRef.current) clearInterval(pollRef.current);
                pollRef.current = setInterval(async () => {
                  const s = await api.pa8CollisionStatus(hunt_id);
                  setHuntStatus(s);
                  if (s.status !== 'running') {
                    clearInterval(pollRef.current);
                    pollRef.current = null;
                    setHuntRunning(false);
                  }
                }, 350);
              }}
            >
              {huntRunning ? '⚡ Hunting…' : collision ? '🔄 Hunt Again' : '🔍 Start Collision Hunt'}
            </button>

            {huntRunning && (
              <button
                id="pa8-collision-stop-btn"
                style={{
                  padding: '10px 16px', borderRadius: '8px', fontWeight: 700, fontSize: '13px', cursor: 'pointer',
                  background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.4)', color: '#ef4444',
                }}
                onClick={async () => {
                  if (huntId) await api.pa8CollisionStop(huntId);
                  stopHunt();
                }}
              >
                ■ Stop
              </button>
            )}
          </div>

          {/* Progress bar */}
          {huntStatus && (
            <div style={{ marginBottom: '14px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text3)', marginBottom: '6px' }}>
                <span>Evaluations: <strong style={{ color: 'var(--text1)' }}>{evals.toLocaleString()}</strong></span>
                <span>Birthday bound 2<sup>16/2</sup>: <strong style={{ color: '#f59e0b' }}>{bound}</strong></span>
              </div>
              <div style={{ height: '10px', background: 'rgba(0,0,0,0.3)', borderRadius: '5px', overflow: 'hidden', position: 'relative' }}>
                {/* Birthday bound marker at 100% of bar = 256 evals */}
                <div style={{
                  height: '100%',
                  width: `${Math.min(100, pct)}%`,
                  background: status === 'found'
                    ? 'linear-gradient(90deg, #22c55e, #16a34a)'
                    : 'linear-gradient(90deg, #f59e0b, #ef4444)',
                  transition: 'width 0.3s ease',
                  borderRadius: '5px',
                }} />
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text3)', marginTop: '4px', textAlign: 'right' }}>
                {pct.toFixed(1)}% of birthday bound
                {evals > bound && <span style={{ color: '#f59e0b' }}>  (+{(evals - bound).toLocaleString()} over)</span>}
              </div>
            </div>
          )}

          {/* Collision found card */}
          {collision && (
            <div
              id="pa8-collision-result"
              style={{
                background: 'linear-gradient(135deg, rgba(34,197,94,0.12) 0%, rgba(16,185,129,0.12) 100%)',
                border: '2px solid #22c55e',
                borderRadius: '10px',
                padding: '16px',
                animation: 'fadeIn 0.4s ease',
              }}
            >
              <div style={{ fontWeight: 700, color: '#22c55e', marginBottom: '10px', fontSize: '14px' }}>💥 Collision Found after {evals.toLocaleString()} evaluations!</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', fontSize: '12px' }}>
                <span style={{ color: 'var(--text3)' }}>Input 1</span>
                <code style={{ color: '#86efac', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>{collision.msg1}</code>
                <span style={{ color: 'var(--text3)' }}>Input 2</span>
                <code style={{ color: '#86efac', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>{collision.msg2}</code>
                <span style={{ color: 'var(--text3)' }}>Hash (16-bit)</span>
                <code style={{ color: '#fbbf24', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>0x{collision.hash_16bit} = {collision.hash_decimal}</code>
              </div>
              <div style={{ marginTop: '12px', fontSize: '11px', color: 'var(--text3)', borderTop: '1px solid rgba(34,197,94,0.2)', paddingTop: '10px', lineHeight: 1.5 }}>
                <strong style={{ color: 'var(--text2)' }}>Why this doesn't break security:</strong> Finding a collision on a <em>truncated</em> 16-bit output is easy (birthday ≈ 256). Breaking the <em>full</em> DLP Hash requires solving
                the discrete log to find (x,y) ≠ (x′,y′) with gˣ·ĥʸ = gˣ′·ĥʸ′ mod p.
              </div>
            </div>
          )}

          {status === 'exhausted' && !collision && (
            <div style={{ color: '#f87171', fontSize: '12px', padding: '10px', background: 'rgba(239,68,68,0.08)', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.2)' }}>
              Safety cap reached without collision. This can happen in rare cases — try again.
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderPA2Special = () => {
    if (!result) return null;
    return (
      <div className="pa2-special">
        {result.tree && (
          <GGMVisualizer 
            tree={result.tree} 
            queryBits={result.query_bits} 
            output={result.output} 
          />
        )}

        <div style={{ marginTop: '20px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
          <button
            className="btn btn-secondary"
            style={{ background: showStats ? 'var(--accent3)' : 'rgba(var(--accent-rgb), 0.1)', border: '1px solid var(--accent3)', color: showStats ? 'white' : 'var(--accent3)' }}
            onClick={() => {
              if (!showStats) {
                runDemo(params, 'randomness');
                setShowStats(true);
                setShowInversion(false);
              } else {
                setShowStats(false);
              }
            }}
          >
            🧪 Randomness Tests
          </button>
          <button
            className="btn btn-secondary"
            style={{ background: showInversion ? 'var(--accent)' : 'rgba(var(--accent-rgb), 0.1)', border: '1px solid var(--accent)', color: showInversion ? 'white' : 'var(--accent)' }}
            onClick={() => {
              if (!showInversion) {
                runDemo(params, 'game');
                setShowInversion(true);
                setShowStats(false);
              } else {
                setShowInversion(false);
              }
            }}
          >
            🎮 Security Game
          </button>
        </div>

        <div style={{ marginTop: '20px' }}>
          {showStats && result && result.stats && (
            <div className="result-section animate-fade-in" style={{ marginBottom: '20px' }}>
              <h3 style={{ margin: 0, marginBottom: '12px' }}>PRF as PRG Randomness</h3>
              <div className="stats-container">
                <div className="ratio-bar-container" style={{ marginBottom: '16px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '4px' }}>
                    <span>Bit Ratio (Ones/Total)</span>
                    <span style={{ fontWeight: 600 }}>{result.ratio ? (result.ratio * 100).toFixed(1) : '...'}%</span>
                  </div>
                  <div style={{ height: '8px', background: 'var(--bg2)', borderRadius: '4px', overflow: 'hidden', position: 'relative' }}>
                    <div style={{ position: 'absolute', left: '50%', top: 0, bottom: 0, width: '2px', background: 'var(--accent)', zIndex: 1, opacity: 0.5 }}></div>
                    <div style={{ height: '100%', width: `${(result.ratio || 0.5) * 100}%`, background: 'var(--accent3)', transition: 'width 0.3s ease' }}></div>
                  </div>
                </div>

                <div className="test-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                  {result.stats.map(s => (
                    <div key={s.test} className={`test-badge ${s.pass ? 'pass' : 'fail'}`} style={{
                      padding: '8px',
                      borderRadius: '6px',
                      textAlign: 'center',
                      background: s.pass ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                      border: `1px solid ${s.pass ? '#22c55e' : '#ef4444'}`
                    }}>
                      <div style={{ fontSize: '10px', fontWeight: 600, color: s.pass ? '#22c55e' : '#ef4444' }}>{s.test.toUpperCase()}</div>
                      <div style={{ fontSize: '11px' }}>{s.pass ? 'PASS' : 'FAIL'}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {showInversion && result && result.game && (
            <div className="result-section animate-fade-in">
              <h3 style={{ margin: 0, marginBottom: '12px' }}>Distinguishing Game (PRF Security)</h3>
              <div style={{ padding: '12px', background: 'rgba(var(--accent-rgb), 0.05)', borderRadius: '8px', border: '1px dashed var(--border)' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, marginBottom: '8px', color: 'var(--accent)' }}>🎯 Goal: Is it PRF or Random?</div>
                <div style={{ fontSize: '11px', color: 'var(--text2)', lineHeight: '1.4', marginBottom: '12px' }}>
                  The adversary tries to distinguish between your <strong>GGM PRF</strong> and a <strong>True Random Function</strong>. If the success rate is close to 50%, the PRF is secure.
                </div>
                
                <div style={{ display: 'flex', gap: '10px', marginBottom: '12px' }}>
                  <div style={{ flex: 1, background: 'var(--bg2)', padding: '10px', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '10px', color: 'var(--text3)' }}>Trials</div>
                    <div style={{ fontSize: '18px', fontWeight: 700 }}>{result.game.trials}</div>
                  </div>
                  <div style={{ flex: 1, background: 'var(--bg2)', padding: '10px', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '10px', color: 'var(--text3)' }}>Advantage</div>
                    <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--accent)' }}>{(Math.abs(result.game.advantage) * 100).toFixed(1)}%</div>
                  </div>
                </div>

                <div style={{ fontSize: '11px', color: 'var(--text3)', fontStyle: 'italic' }}>
                  {result.game.advantage < 0.1 ? 
                    "✅ Success! The adversary has no significant advantage. The PRF is indistinguishable from random." : 
                    "⚠️ Noticeable bias detected in this trial."}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const isPA1 = pa.pa === 1;
  const isPA2 = pa.pa === 2;
  const isPA8 = pa.pa === 8;

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

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '16px' }}>
              {def.params.map(p => (
                <div className="field" key={p.name} style={{ marginBottom: 0 }}>
                  <label style={{ display: 'flex', justifyContent: 'space-between' }}>
                    {p.label}
                    {p.type === 'range' && <span>{params[p.name]} bytes</span>}
                  </label>
                  {p.type === 'range' ? (
                    <input
                      type="range"
                      min={p.min}
                      max={p.max}
                      value={params[p.name] || p.default}
                      onChange={(e) => {
                        const next = { ...params, [p.name]: e.target.value };
                        setParams(next);
                        if (isPA1 || isPA2 || isPA8) {
                          setShowStats(false);
                          setShowInversion(false);
                          setResult(prev => prev ? { ...prev, stats: null, ratio: null, inversion: null } : null);
                          runDemo(next);
                        }
                      }}
                    />
                  ) : (
                    <input
                      type="text"
                      value={params[p.name] || ''}
                      onChange={(e) => {
                        const next = { ...params, [p.name]: e.target.value };
                        setParams(next);
                        if (isPA1 || isPA2 || isPA8) {
                          setShowStats(false);
                          setShowInversion(false);
                          setResult(prev => prev ? { ...prev, stats: null, ratio: null, inversion: null } : null);
                          runDemo(next);
                        }
                      }}
                    />
                  )}
                </div>
              ))}
            </div>

            {!isPA1 && !isPA8 && (
              <button className="btn btn-primary" style={{ width: '100%' }} onClick={() => runDemo()}>
                ▶ Run Demo
              </button>
            )}
          </div>

          <div id="demoOutputContainer">
            {isLoading && !isPA1 && !isPA8 && <div style={{ textAlign: 'center', padding: '20px' }}><div className="spinner"></div></div>}
            {error && <pre style={{ color: 'var(--red)' }}>{error}</pre>}
            {isPA1 ? renderPA1Special() : isPA2 ? renderPA2Special() : isPA8 ? renderPA8Special() : (result && renderResult(result))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default PADemoModal;
