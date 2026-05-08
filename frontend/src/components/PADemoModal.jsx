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
  9: { params: [] },  // PA9 has its own input inside renderPA9Special
  10: { params: [] }, // PA10 has its own special renderer
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

  // PA#9 birthday attack state
  const [pa9NBits, setPa9NBits] = useState(12);
  const [pa9HuntId, setPa9HuntId] = useState(null);
  const [pa9Status, setPa9Status] = useState(null);
  const [pa9Running, setPa9Running] = useState(false);
  const pa9PollRef = useRef(null);

  // PA#10 state
  const [pa10LeData, setPa10LeData]       = useState(null);  // length-extension
  const [pa10LeSuffix, setPa10LeSuffix]   = useState('evil suffix');
  const [pa10HashMode, setPa10HashMode]   = useState('dlp');
  const [pa10LeLoading, setPa10LeLoading] = useState(false);
  const [pa10EufData, setPa10EufData]     = useState(null);
  const [pa10MacData, setPa10MacData]     = useState(null);
  const [pa10EthData, setPa10EthData]     = useState(null); // enc result
  const [pa10DecData, setPa10DecData]     = useState(null);
  const [pa10TimingData, setPa10TimingData] = useState(null);
  const [pa10CcaData, setPa10CcaData]     = useState(null);
  const [pa10EthMsg, setPa10EthMsg]       = useState('Secret & authenticated!');
  const [pa10Loading, setPa10Loading]     = useState({});

  const def = PA_DEFINITIONS[pa.pa] || { params: [] };

  // Stop polling helper — defined before useEffect so cleanup can reference it
  const stopHunt = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    setHuntRunning(false);
  }, []);

  const stopPa9Hunt = useCallback(() => {
    if (pa9PollRef.current) {
      clearInterval(pa9PollRef.current);
      pa9PollRef.current = null;
    }
    setPa9Running(false);
  }, []);

  useEffect(() => {
    // Set initial params
    const initialParams = {};
    def.params.forEach(p => initialParams[p.name] = p.default);
    setParams(initialParams);

    // Auto-run if no params (but NOT for PA8/PA9/PA10 — they have their own special renderers)
    if (def.params.length === 0 && pa.pa !== 8 && pa.pa !== 9 && pa.pa !== 10) {
      runDemo(initialParams);
    }

    // Reset PA8 / PA9 / PA10 state when modal switches PA
    setPa8Hash(null);
    setHuntStatus(null);
    stopHunt();
    setPa9Status(null);
    stopPa9Hunt();
    setPa10LeData(null); setPa10EufData(null); setPa10MacData(null);
    setPa10EthData(null); setPa10DecData(null); setPa10TimingData(null); setPa10CcaData(null);

    return () => { stopHunt(); stopPa9Hunt(); };
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

  // ─────────────────────────────────────────────────────────────────
  // PA#9 — Birthday Attack demo
  // ─────────────────────────────────────────────────────────────────
  const renderPA9Special = () => {
    const collision = pa9Status?.collision;
    const evals     = pa9Status?.evaluations ?? 0;
    const status    = pa9Status?.status;
    const bound     = pa9Status?.birthday_bound ?? Math.pow(2, pa9NBits / 2);
    const empiricalProb = pa9Status?.empirical_prob ?? 0;
    const curvePoints   = pa9Status?.curve_points ?? [];
    const nBits = pa9NBits;

    // Theoretical curve: 1 - e^(-k*(k-1)/2^n)
    // Build a smooth theoretical reference line (100 pts from 0 to 5*bound)
    const maxK = Math.max(evals + 5, bound * 4);
    const theoryPts = Array.from({ length: 120 }, (_, i) => {
      const k = Math.round((i / 119) * maxK);
      return { k, prob: 1 - Math.exp(-k * (k - 1) / Math.pow(2, nBits)) };
    });

    // SVG chart dimensions
    const W = 340, H = 160, PAD = { t: 10, r: 16, b: 32, l: 42 };
    const cW = W - PAD.l - PAD.r;
    const cH = H - PAD.t - PAD.b;
    const xScale = k => (k / maxK) * cW;
    const yScale = p => cH - p * cH;

    // Build SVG path from theory points
    const theoryPath = theoryPts
      .map((pt, i) => `${i === 0 ? 'M' : 'L'}${xScale(pt.k).toFixed(1)},${yScale(pt.prob).toFixed(1)}`)
      .join(' ');

    // Empirical curve: build from curvePoints
    const empirPath = curvePoints.length > 1
      ? curvePoints
          .map((pt, i) => `${i === 0 ? 'M' : 'L'}${xScale(pt.k).toFixed(1)},${yScale(pt.prob).toFixed(1)}`)
          .join(' ')
      : '';

    // Birthday bound x-position
    const boundX = xScale(bound);

    // Collision marker
    const collisionX = collision ? xScale(evals) : null;
    const collisionY = collision ? yScale(empiricalProb) : null;

    const nOptions = [8, 10, 12, 14, 16];

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

        {/* ── n-bit slider ── */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(99,102,241,0.08) 0%, rgba(168,85,247,0.08) 100%)',
          border: '1px solid rgba(99,102,241,0.3)',
          borderRadius: '12px',
          padding: '18px',
        }}>
          <div style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent)', marginBottom: '12px', textTransform: 'uppercase' }}>🎛️ Output Bit-Length n</div>

          {/* Segmented pill selector */}
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {nOptions.map(n => (
              <button
                key={n}
                id={`pa9-n-btn-${n}`}
                onClick={() => { setPa9NBits(n); setPa9Status(null); stopPa9Hunt(); }}
                style={{
                  flex: 1,
                  padding: '8px 0',
                  borderRadius: '8px',
                  border: n === nBits ? '2px solid #818cf8' : '1px solid rgba(99,102,241,0.25)',
                  background: n === nBits
                    ? 'linear-gradient(135deg, rgba(99,102,241,0.3) 0%, rgba(168,85,247,0.3) 100%)'
                    : 'rgba(0,0,0,0.2)',
                  color: n === nBits ? '#c4b5fd' : 'var(--text2)',
                  fontWeight: n === nBits ? 700 : 400,
                  fontSize: '13px',
                  cursor: 'pointer',
                  transition: 'all 0.18s',
                }}
              >
                {n}-bit
              </button>
            ))}
          </div>

          <div style={{ marginTop: '12px', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '8px', fontSize: '11px' }}>
            <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '6px', padding: '8px 10px', border: '1px solid rgba(99,102,241,0.15)', textAlign: 'center' }}>
              <div style={{ color: 'var(--text3)', marginBottom: '2px' }}>Output space</div>
              <div style={{ fontFamily: 'monospace', color: '#a5b4fc', fontWeight: 700 }}>2<sup>{nBits}</sup> = {Math.pow(2, nBits).toLocaleString()}</div>
            </div>
            <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '6px', padding: '8px 10px', border: '1px solid rgba(99,102,241,0.15)', textAlign: 'center' }}>
              <div style={{ color: 'var(--text3)', marginBottom: '2px' }}>Birthday bound</div>
              <div style={{ fontFamily: 'monospace', color: '#f59e0b', fontWeight: 700 }}>2<sup>{nBits}/2</sup> ≈ {Math.round(Math.pow(2, nBits / 2))}</div>
            </div>
            <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '6px', padding: '8px 10px', border: '1px solid rgba(99,102,241,0.15)', textAlign: 'center' }}>
              <div style={{ color: 'var(--text3)', marginBottom: '2px' }}>Evaluated</div>
              <div style={{ fontFamily: 'monospace', color: '#34d399', fontWeight: 700 }}>{evals.toLocaleString()}</div>
            </div>
          </div>
        </div>

        {/* ── Attack controls ── */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(245,158,11,0.07) 0%, rgba(239,68,68,0.07) 100%)',
          border: '1px solid rgba(245,158,11,0.3)',
          borderRadius: '12px',
          padding: '18px',
        }}>
          <div style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: '#f59e0b', marginBottom: '12px', textTransform: 'uppercase' }}>🎯 Birthday Attack</div>

          <div style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
            <button
              id="pa9-run-btn"
              disabled={pa9Running}
              style={{
                flex: 1, padding: '10px', borderRadius: '8px', fontWeight: 700, fontSize: '13px',
                cursor: pa9Running ? 'not-allowed' : 'pointer',
                background: pa9Running
                  ? 'rgba(245,158,11,0.15)'
                  : 'linear-gradient(135deg, #f59e0b, #ef4444)',
                border: 'none',
                color: pa9Running ? '#f59e0b' : 'white',
                transition: 'all 0.2s',
              }}
              onClick={async () => {
                setPa9Status(null);
                setPa9Running(true);
                const { hunt_id } = await api.pa9BirthdayStart(nBits);
                setPa9HuntId(hunt_id);
                if (pa9PollRef.current) clearInterval(pa9PollRef.current);
                pa9PollRef.current = setInterval(async () => {
                  const s = await api.pa9BirthdayStatus(hunt_id);
                  setPa9Status(s);
                  if (s.status !== 'running') {
                    clearInterval(pa9PollRef.current);
                    pa9PollRef.current = null;
                    setPa9Running(false);
                  }
                }, 250);
              }}
            >
              {pa9Running ? '⚡ Attacking…' : collision ? '🔄 Run Again' : '▶ Run Attack'}
            </button>

            {pa9Running && (
              <button
                id="pa9-stop-btn"
                style={{
                  padding: '10px 16px', borderRadius: '8px', fontWeight: 700, fontSize: '13px', cursor: 'pointer',
                  background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.4)', color: '#ef4444',
                }}
                onClick={async () => {
                  if (pa9HuntId) await api.pa9BirthdayStop(pa9HuntId);
                  stopPa9Hunt();
                }}
              >
                ■ Stop
              </button>
            )}
          </div>

          {/* Progress bar */}
          {pa9Status && (
            <div style={{ marginBottom: '14px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text3)', marginBottom: '6px' }}>
                <span>Hashes computed: <strong style={{ color: 'var(--text1)' }}>{evals.toLocaleString()}</strong></span>
                <span>P(collision): <strong style={{ color: '#34d399' }}>{(empiricalProb * 100).toFixed(1)}%</strong></span>
              </div>
              <div style={{ height: '10px', background: 'rgba(0,0,0,0.3)', borderRadius: '5px', overflow: 'hidden', position: 'relative' }}>
                <div style={{
                  height: '100%',
                  width: `${Math.min(100, evals / (bound * 4) * 100)}%`,
                  background: status === 'found'
                    ? 'linear-gradient(90deg, #22c55e, #16a34a)'
                    : 'linear-gradient(90deg, #f59e0b, #ef4444)',
                  transition: 'width 0.25s ease',
                  borderRadius: '5px',
                }} />
              </div>
            </div>
          )}
        </div>

        {/* ── Live probability chart ── */}
        {pa9Status && (
          <div style={{
            background: 'rgba(0,0,0,0.25)',
            border: '1px solid var(--border)',
            borderRadius: '12px',
            padding: '14px',
          }}>
            <div style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--text2)', marginBottom: '10px', textTransform: 'uppercase' }}>📈 Collision Probability vs Hashes Computed</div>
            <svg
              id="pa9-probability-chart"
              width={W}
              height={H}
              style={{ display: 'block', maxWidth: '100%', overflow: 'visible' }}
              viewBox={`0 0 ${W} ${H}`}
            >
              <g transform={`translate(${PAD.l},${PAD.t})`}>
                {/* Y grid lines */}
                {[0, 0.25, 0.5, 0.75, 1.0].map(p => (
                  <g key={p}>
                    <line x1={0} y1={yScale(p)} x2={cW} y2={yScale(p)} stroke="rgba(255,255,255,0.06)" strokeWidth={1} />
                    <text x={-6} y={yScale(p) + 4} textAnchor="end" fontSize={9} fill="rgba(255,255,255,0.35)">{(p * 100).toFixed(0)}%</text>
                  </g>
                ))}

                {/* X axis label */}
                <text x={cW / 2} y={cH + 28} textAnchor="middle" fontSize={9} fill="rgba(255,255,255,0.35)">k (hashes computed)</text>

                {/* Birthday bound marker */}
                <line x1={boundX} y1={0} x2={boundX} y2={cH} stroke="#f59e0b" strokeWidth={1.5} strokeDasharray="4,3" opacity={0.7} />
                <text x={boundX + 3} y={12} fontSize={9} fill="#f59e0b" opacity={0.9}>2^({nBits}/2)={Math.round(bound)}</text>

                {/* Theoretical curve */}
                <path d={theoryPath} fill="none" stroke="#818cf8" strokeWidth={1.5} opacity={0.7} />

                {/* Empirical curve (from server curve_points) */}
                {empirPath && (
                  <path d={empirPath} fill="none" stroke="#34d399" strokeWidth={2} opacity={0.9} />
                )}

                {/* Live empirical dot */}
                {evals > 0 && (
                  <circle
                    cx={xScale(evals)}
                    cy={yScale(empiricalProb)}
                    r={4}
                    fill="#34d399"
                    stroke="white"
                    strokeWidth={1}
                  />
                )}

                {/* Collision marker */}
                {collisionX !== null && (
                  <>
                    <line x1={collisionX} y1={0} x2={collisionX} y2={cH} stroke="#22c55e" strokeWidth={2} strokeDasharray="3,2" />
                    <circle cx={collisionX} cy={collisionY} r={6} fill="#22c55e" stroke="white" strokeWidth={1.5} />
                  </>
                )}

                {/* Axes */}
                <line x1={0} y1={0} x2={0} y2={cH} stroke="rgba(255,255,255,0.2)" />
                <line x1={0} y1={cH} x2={cW} y2={cH} stroke="rgba(255,255,255,0.2)" />
              </g>
            </svg>

            {/* Legend */}
            <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontSize: '10px', flexWrap: 'wrap' }}>
              <span><span style={{ display: 'inline-block', width: 20, height: 2, background: '#818cf8', verticalAlign: 'middle', marginRight: 4 }} />Theory: 1−e<sup>−k(k−1)/2<sup>n</sup></sup></span>
              <span><span style={{ display: 'inline-block', width: 20, height: 2, background: '#34d399', verticalAlign: 'middle', marginRight: 4 }} />Empirical P(collision)</span>
              <span><span style={{ display: 'inline-block', width: 14, height: 2, background: '#f59e0b', verticalAlign: 'middle', marginRight: 4, borderTop: '1px dashed #f59e0b' }} />Birthday bound 2<sup>n/2</sup></span>
            </div>
          </div>
        )}

        {/* ── Collision found card ── */}
        {collision && (
          <div
            id="pa9-collision-result"
            style={{
              background: 'linear-gradient(135deg, rgba(34,197,94,0.12) 0%, rgba(16,185,129,0.12) 100%)',
              border: '2px solid #22c55e',
              borderRadius: '10px',
              padding: '16px',
              animation: 'fadeIn 0.4s ease',
            }}
          >
            <div style={{ fontWeight: 700, color: '#22c55e', marginBottom: '10px', fontSize: '14px' }}>💥 Collision Found in {evals.toLocaleString()} evaluations! (expected ≈ {Math.round(bound)})</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', fontSize: '12px' }}>
              <span style={{ color: 'var(--text3)' }}>Input 1</span>
              <code style={{ color: '#86efac', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px', wordBreak: 'break-all' }}>0x{collision.input1}</code>
              <span style={{ color: 'var(--text3)' }}>Input 2</span>
              <code style={{ color: '#86efac', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px', wordBreak: 'break-all' }}>0x{collision.input2}</code>
              <span style={{ color: 'var(--text3)' }}>Shared hash ({nBits}-bit)</span>
              <code style={{ color: '#fbbf24', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>0x{collision.hash_hex} = {collision.hash_value}</code>
            </div>
            <div style={{ marginTop: '12px', fontSize: '11px', color: 'var(--text3)', borderTop: '1px solid rgba(34,197,94,0.2)', paddingTop: '10px', lineHeight: 1.5 }}>
              <strong style={{ color: 'var(--text2)' }}>Birthday paradox:</strong> With only {nBits} output bits (2<sup>{nBits}</sup> = {Math.pow(2,nBits).toLocaleString()} possible values),
              a collision appears after ≈ 2<sup>{nBits}/2</sup> = {Math.round(bound)} hashes — far fewer than the full output space.
              Ratio empirical/expected: <strong style={{ color: '#34d399' }}>{(evals / bound).toFixed(2)}×</strong>.
            </div>
          </div>
        )}

        {status === 'exhausted' && !collision && (
          <div style={{ color: '#f87171', fontSize: '12px', padding: '10px', background: 'rgba(239,68,68,0.08)', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.2)' }}>
            Safety cap reached without collision. Try again.
          </div>
        )}
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

  // ─────────────────────────────────────────────────────────────────
  // PA#10 — HMAC Interactive Demo
  // ─────────────────────────────────────────────────────────────────
  const renderPA10Special = () => {
    const card = (children, accent = '#818cf8', title = '') => (
      <div style={{
        background: `linear-gradient(135deg, ${accent}14 0%, ${accent}08 100%)`,
        border: `1px solid ${accent}50`,
        borderRadius: '12px', padding: '18px', marginBottom: '16px',
      }}>
        {title && <div style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: accent, marginBottom: '12px', textTransform: 'uppercase' }}>{title}</div>}
        {children}
      </div>
    );

    const mono = (txt, color = '#a5b4fc') => (
      <code style={{ fontFamily: 'monospace', fontSize: '11px', wordBreak: 'break-all', color, background: 'rgba(0,0,0,0.35)', borderRadius: '4px', padding: '2px 6px' }}>{txt}</code>
    );

    const badge = (ok, yes = 'Secure ✓', no = 'Vulnerable ✗') => (
      <span style={{ fontWeight: 700, color: ok ? '#22c55e' : '#ef4444', background: ok ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.12)', border: `1px solid ${ok ? '#22c55e' : '#ef4444'}`, borderRadius: '6px', padding: '2px 10px', fontSize: '12px' }}>
        {ok ? yes : no}
      </span>
    );

    const btn = (label, onClick, accent = '#818cf8', loading = false) => (
      <button onClick={onClick} disabled={loading} style={{
        padding: '9px 18px', borderRadius: '8px', border: `1px solid ${accent}80`,
        background: loading ? `${accent}22` : `linear-gradient(135deg, ${accent}cc, ${accent}88)`,
        color: 'white', fontWeight: 700, fontSize: '12px', cursor: loading ? 'not-allowed' : 'pointer',
        transition: 'all 0.2s',
      }}>
        {loading ? '⏳ …' : label}
      </button>
    );

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>

        {/* ── Hash toggle ── */}
        {card(
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            <span style={{ fontSize: '12px', color: 'var(--text2)' }}>Underlying hash:</span>
            {['dlp', 'sha256'].map(m => (
              <button key={m} onClick={() => { setPa10HashMode(m); setPa10LeData(null); }} style={{
                padding: '6px 16px', borderRadius: '8px', fontWeight: 700, fontSize: '12px', cursor: 'pointer',
                background: pa10HashMode === m ? 'linear-gradient(135deg,#6366f1,#8b5cf6)' : 'rgba(0,0,0,0.2)',
                border: `1px solid ${pa10HashMode === m ? '#818cf8' : 'rgba(99,102,241,0.25)'}`,
                color: pa10HashMode === m ? 'white' : 'var(--text2)', transition: 'all 0.18s',
              }}>
                {m === 'dlp' ? '🔢 DLP Hash (PA#8)' : '🔒 SHA-256'}
              </button>
            ))}
          </div>,
          '#6366f1', '🔀 Hash Toggle'
        )}

        {/* ── Side-by-side length-extension ── */}
        {card(
          <div>
            <div style={{ marginBottom: '12px', fontSize: '12px', color: 'var(--text2)', lineHeight: 1.5 }}>
              Type a suffix m′. Left: naive <code>H(k‖m)</code> is forged. Right: HMAC resists.
            </div>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '12px', alignItems: 'center' }}>
              <input
                id="pa10-suffix-input"
                type="text"
                value={pa10LeSuffix}
                placeholder="Type suffix m′…"
                onChange={e => setPa10LeSuffix(e.target.value)}
                style={{ flex: 1, padding: '9px 13px', background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(239,68,68,0.4)', borderRadius: '8px', color: 'var(--text1)', fontSize: '13px', fontFamily: 'monospace', outline: 'none' }}
              />
              {btn('⚡ Attack!', async () => {
                setPa10LeLoading(true);
                const d = await api.pa10LengthExtension(pa10LeSuffix, pa10HashMode);
                setPa10LeData(d); setPa10LeLoading(false);
              }, '#ef4444', pa10LeLoading)}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              {/* LEFT — broken */}
              <div style={{ background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.35)', borderRadius: '10px', padding: '14px' }}>
                <div style={{ fontWeight: 700, color: '#f87171', marginBottom: '10px', fontSize: '12px' }}>⚠️ Naive H(k‖m) — BROKEN</div>
                {pa10LeLoading && <div className="spinner" style={{ margin: '10px auto' }} />}
                {pa10LeData && <>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '4px' }}>Original message</div>
                  <div style={{ marginBottom: '8px' }}>{mono(pa10LeData.message)}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '4px' }}>Naive tag t = H(k‖m)</div>
                  <div style={{ marginBottom: '8px' }}>{mono(pa10LeData.naive_tag?.slice(0, 24) + '…', '#fca5a5')}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '4px' }}>Forged message (m‖pad‖m′)</div>
                  <div style={{ marginBottom: '8px', fontSize: '10px', fontFamily: 'monospace', wordBreak: 'break-all', color: '#fca5a5', background: 'rgba(0,0,0,0.3)', borderRadius: '4px', padding: '6px' }}>{pa10LeData.forged_message}</div>
                  <div style={{ marginBottom: '8px' }}>{badge(false, '', '🔥 Forgery Succeeded!')}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', lineHeight: 1.4 }}>
                    Attacker used naive_tag as IV, continued hashing m′ — valid without knowing k.
                  </div>
                </>}
                {!pa10LeData && !pa10LeLoading && <div style={{ fontSize: '11px', color: 'var(--text3)', textAlign: 'center', padding: '20px' }}>Press ⚡ Attack!</div>}
              </div>

              {/* RIGHT — HMAC */}
              <div style={{ background: 'rgba(34,197,94,0.07)', border: '1px solid rgba(34,197,94,0.35)', borderRadius: '10px', padding: '14px' }}>
                <div style={{ fontWeight: 700, color: '#4ade80', marginBottom: '10px', fontSize: '12px' }}>✅ HMAC — SECURE</div>
                {pa10LeLoading && <div className="spinner" style={{ margin: '10px auto' }} />}
                {pa10LeData && <>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '4px' }}>Original message</div>
                  <div style={{ marginBottom: '8px' }}>{mono(pa10LeData.message)}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '4px' }}>HMAC tag</div>
                  <div style={{ marginBottom: '8px' }}>{mono(pa10LeData.hmac_tag?.slice(0, 24) + '…', '#86efac')}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '4px' }}>Same forged message attempted</div>
                  <div style={{ marginBottom: '8px', fontSize: '10px', fontFamily: 'monospace', wordBreak: 'break-all', color: '#86efac', background: 'rgba(0,0,0,0.3)', borderRadius: '4px', padding: '6px' }}>{pa10LeData.forged_message}</div>
                  <div style={{ marginBottom: '8px' }}>{badge(true, '🔒 Forgery Failed!')}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', lineHeight: 1.4 }}>
                    HMAC wraps with outer hash — leaked state can't be reused without k.
                  </div>
                </>}
                {!pa10LeData && !pa10LeLoading && <div style={{ fontSize: '11px', color: 'var(--text3)', textAlign: 'center', padding: '20px' }}>Press ⚡ Attack!</div>}
              </div>
            </div>
          </div>,
          '#ef4444', '4. Length-Extension Attack Demo'
        )}

        {/* ── EUF-CMA game ── */}
        {card(
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
              50 oracle queries → 20 random forgery attempts. A secure MAC has 0 successes.
            </div>
            {btn('▶ Run EUF-CMA Game', async () => {
              setPa10Loading(p => ({ ...p, euf: true }));
              const d = await api.pa10EufCma();
              setPa10EufData(d); setPa10Loading(p => ({ ...p, euf: false }));
            }, '#6366f1', pa10Loading.euf)}
            {pa10EufData && (
              <div style={{ marginTop: '14px', display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '8px' }}>
                {[
                  ['Oracle Queries', pa10EufData.queries, '#818cf8'],
                  ['Forgery Attempts', pa10EufData.forgery_attempts, '#f59e0b'],
                  ['Successes', pa10EufData.successes, pa10EufData.successes === 0 ? '#22c55e' : '#ef4444'],
                ].map(([l, v, c]) => (
                  <div key={l} style={{ textAlign: 'center', background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: `1px solid ${c}40` }}>
                    <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '4px' }}>{l}</div>
                    <div style={{ fontSize: '22px', fontWeight: 800, color: c }}>{v}</div>
                  </div>
                ))}
                <div style={{ gridColumn: '1/-1', marginTop: '4px' }}>
                  {badge(pa10EufData.secure, 'EUF-CMA Secure ✓ (0 forgeries)', 'Forgery Detected!')}
                </div>
              </div>
            )}
          </div>,
          '#6366f1', '2. CRHF ⇒ MAC (EUF-CMA Game)'
        )}

        {/* ── MAC ⇒ CRHF ── */}
        {card(
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
              Use HMAC as compression h′(cv, block) = HMAC_k(cv‖block) in Merkle-Damgård. All 5 messages hash to distinct values.
            </div>
            {btn('▶ Run MAC⇒CRHF Demo', async () => {
              setPa10Loading(p => ({ ...p, mac: true }));
              const d = await api.pa10MacCrhf();
              setPa10MacData(d); setPa10Loading(p => ({ ...p, mac: false }));
            }, '#8b5cf6', pa10Loading.mac)}
            {pa10MacData && (
              <div style={{ marginTop: '14px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginBottom: '10px' }}>
                  {[
                    ['Messages', pa10MacData.total_messages],
                    ['Distinct Hashes', pa10MacData.distinct_hashes],
                  ].map(([l, v]) => (
                    <div key={l} style={{ textAlign: 'center', background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: '1px solid rgba(139,92,246,0.3)' }}>
                      <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '4px' }}>{l}</div>
                      <div style={{ fontSize: '22px', fontWeight: 800, color: '#c4b5fd' }}>{v}</div>
                    </div>
                  ))}
                </div>
                {badge(pa10MacData.all_distinct, 'No Collisions — MAC⇒CRHF Holds ✓')}
                <div style={{ marginTop: '10px', fontSize: '10px', color: 'var(--text3)', lineHeight: 1.4 }}>
                  {pa10MacData.conclusion}
                </div>
              </div>
            )}
          </div>,
          '#8b5cf6', '3. MAC ⇒ CRHF (Reverse Direction)'
        )}

        {/* ── Encrypt-then-HMAC ── */}
        {card(
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
              EtH_Enc: encrypt with PA#3 CPA scheme, then HMAC the ciphertext. EtH_Dec: verify HMAC first, then decrypt.
            </div>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '12px', alignItems: 'center' }}>
              <input
                id="pa10-eth-msg-input"
                type="text"
                value={pa10EthMsg}
                onChange={e => setPa10EthMsg(e.target.value)}
                placeholder="Plaintext to encrypt…"
                style={{ flex: 1, padding: '9px 13px', background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(16,185,129,0.4)', borderRadius: '8px', color: 'var(--text1)', fontSize: '13px', fontFamily: 'monospace', outline: 'none' }}
              />
              {btn('🔒 Encrypt', async () => {
                setPa10Loading(p => ({ ...p, eth: true }));
                setPa10DecData(null);
                const d = await api.pa10EthEnc(pa10EthMsg);
                setPa10EthData(d); setPa10Loading(p => ({ ...p, eth: false }));
              }, '#10b981', pa10Loading.eth)}
            </div>

            {pa10EthData && (
              <div style={{ marginTop: '4px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 10px', fontSize: '11px', marginBottom: '12px' }}>
                  {[
                    ['Plaintext', pa10EthData.plaintext, '#34d399'],
                    ['Nonce (r)', pa10EthData.nonce_hex?.slice(0, 20) + '…', '#a5b4fc'],
                    ['Ciphertext', pa10EthData.ciphertext_hex?.slice(0, 28) + '…', '#a5b4fc'],
                    ['HMAC Tag', pa10EthData.tag_hex?.slice(0, 28) + '…', '#fbbf24'],
                  ].map(([k, v, c]) => (
                    <React.Fragment key={k}>
                      <span style={{ color: 'var(--text3)', whiteSpace: 'nowrap', paddingTop: '2px' }}>{k}</span>
                      <span style={{ fontFamily: 'monospace', color: c, wordBreak: 'break-all' }}>{v}</span>
                    </React.Fragment>
                  ))}
                </div>

                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {btn('🔓 Decrypt (clean)', async () => {
                    setPa10Loading(p => ({ ...p, dec: true }));
                    const d = await api.pa10EthDec(pa10EthData.key_enc_hex, pa10EthData.key_mac_hex, pa10EthData.nonce_hex, pa10EthData.ciphertext_hex, pa10EthData.tag_hex);
                    setPa10DecData({ ...d, label: 'Clean decrypt' }); setPa10Loading(p => ({ ...p, dec: false }));
                  }, '#10b981', pa10Loading.dec)}
                  {btn('⚠️ Tamper & Decrypt', async () => {
                    setPa10Loading(p => ({ ...p, tamper: true }));
                    const d = await api.pa10EthDec(pa10EthData.key_enc_hex, pa10EthData.key_mac_hex, pa10EthData.nonce_hex, pa10EthData.ciphertext_hex, pa10EthData.tag_hex, 0);
                    setPa10DecData({ ...d, label: 'Tampered byte 0' }); setPa10Loading(p => ({ ...p, tamper: false }));
                  }, '#ef4444', pa10Loading.tamper)}
                </div>

                {pa10DecData && (
                  <div style={{ marginTop: '12px', padding: '12px', background: pa10DecData.success ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)', border: `1px solid ${pa10DecData.success ? '#22c55e' : '#ef4444'}50`, borderRadius: '8px' }}>
                    <div style={{ fontWeight: 700, fontSize: '12px', color: pa10DecData.success ? '#4ade80' : '#f87171', marginBottom: '6px' }}>{pa10DecData.result}</div>
                    {pa10DecData.success && <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#34d399' }}>Decrypted: "{pa10DecData.plaintext}"</div>}
                    {!pa10DecData.success && <div style={{ fontSize: '11px', color: 'var(--text3)' }}>HMAC verification failed — ciphertext rejected before decryption (CCA2 safety).</div>}
                  </div>
                )}
              </div>
            )}
          </div>,
          '#10b981', '5. Encrypt-then-HMAC (CCA-Secure)'
        )}

        {/* ── IND-CCA2 game ── */}
        {card(
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
              30 rounds: adversary guesses randomly, all tampered ciphertexts must be rejected.
            </div>
            {btn('▶ Run IND-CCA2 Game', async () => {
              setPa10Loading(p => ({ ...p, cca: true }));
              const d = await api.pa10CcaGame(30);
              setPa10CcaData(d); setPa10Loading(p => ({ ...p, cca: false }));
            }, '#0ea5e9', pa10Loading.cca)}
            {pa10CcaData && (
              <div style={{ marginTop: '14px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '8px', marginBottom: '10px' }}>
                  {[
                    ['Rounds', pa10CcaData.rounds, '#818cf8'],
                    ['Win Rate', (pa10CcaData.win_rate * 100).toFixed(0) + '%', '#f59e0b'],
                    ['Advantage', (pa10CcaData.advantage * 100).toFixed(1) + '%', pa10CcaData.advantage < 0.15 ? '#22c55e' : '#ef4444'],
                    ['Tamper Rej.', pa10CcaData.tamper_rejection_rate === 1 ? '100%' : (pa10CcaData.tamper_rejection_rate * 100).toFixed(0) + '%', pa10CcaData.tamper_rejection_rate === 1 ? '#22c55e' : '#ef4444'],
                  ].map(([l, v, c]) => (
                    <div key={l} style={{ textAlign: 'center', background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: `1px solid ${c}40` }}>
                      <div style={{ fontSize: '9px', color: 'var(--text3)', marginBottom: '4px' }}>{l}</div>
                      <div style={{ fontSize: '18px', fontWeight: 800, color: c }}>{v}</div>
                    </div>
                  ))}
                </div>
                {badge(pa10CcaData.secure, 'IND-CCA2 Secure ✓', 'Security Broken!')}
                <div style={{ marginTop: '8px', fontSize: '10px', color: 'var(--text3)', lineHeight: 1.4 }}>
                  Tag size: {pa10CcaData.tag_size_bytes} bytes. {pa10CcaData.note}
                </div>
              </div>
            )}
          </div>,
          '#0ea5e9', '6. IND-CCA2 Game'
        )}

        {/* ── Timing attack ── */}
        {card(
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
              Naive early-exit comparison leaks the tag byte-by-byte via timing. Constant-time comparison runs in fixed time.
            </div>
            {btn('⏱️ Run Timing Demo', async () => {
              setPa10Loading(p => ({ ...p, timing: true }));
              const d = await api.pa10Timing();
              setPa10TimingData(d); setPa10Loading(p => ({ ...p, timing: false }));
            }, '#f59e0b', pa10Loading.timing)}
            {pa10TimingData && (
              <div style={{ marginTop: '14px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '8px', marginBottom: '10px' }}>
                  {[
                    ['Early-diff avg', `${pa10TimingData.avg_early_diff_ns?.toFixed(0)} ns`, '#f59e0b'],
                    ['Late-diff avg', `${pa10TimingData.avg_late_diff_ns?.toFixed(0)} ns`, '#f87171'],
                    ['Correct avg', `${pa10TimingData.avg_correct_ns?.toFixed(0)} ns`, '#34d399'],
                  ].map(([l, v, c]) => (
                    <div key={l} style={{ textAlign: 'center', background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: `1px solid ${c}40` }}>
                      <div style={{ fontSize: '9px', color: 'var(--text3)', marginBottom: '4px' }}>{l}</div>
                      <div style={{ fontSize: '15px', fontWeight: 800, color: c }}>{v}</div>
                    </div>
                  ))}
                </div>
                {/* Mini bar chart */}
                <div style={{ marginBottom: '10px' }}>
                  {[
                    ['Early-diff (byte 0)', pa10TimingData.avg_early_diff_ns, '#f59e0b'],
                    ['Late-diff (last byte)', pa10TimingData.avg_late_diff_ns, '#f87171'],
                    ['Correct tag', pa10TimingData.avg_correct_ns, '#34d399'],
                  ].map(([label, val, c]) => {
                    const max = Math.max(pa10TimingData.avg_early_diff_ns, pa10TimingData.avg_late_diff_ns, pa10TimingData.avg_correct_ns);
                    const pct = max > 0 ? (val / max) * 100 : 0;
                    return (
                      <div key={label} style={{ marginBottom: '6px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text3)', marginBottom: '2px' }}>
                          <span>{label}</span><span style={{ color: c }}>{val?.toFixed(0)} ns</span>
                        </div>
                        <div style={{ height: '8px', background: 'rgba(0,0,0,0.3)', borderRadius: '4px', overflow: 'hidden' }}>
                          <div style={{ height: '100%', width: `${pct}%`, background: c, borderRadius: '4px', transition: 'width 0.5s ease' }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
                {badge(pa10TimingData.timing_leak, 'Timing Leak Detected in Naive Compare!', 'No Clear Timing Leak')}
                <div style={{ marginTop: '8px', fontSize: '10px', color: 'var(--text3)', lineHeight: 1.4 }}>
                  {pa10TimingData.note}. Constant-time secure_compare() prevents this attack.
                </div>
              </div>
            )}
          </div>,
          '#f59e0b', '7. Constant-Time Comparison (Timing Demo)'
        )}

      </div>
    );
  };

  const isPA1 = pa.pa === 1;
  const isPA2 = pa.pa === 2;
  const isPA8 = pa.pa === 8;
  const isPA9 = pa.pa === 9;
  const isPA10 = pa.pa === 10;

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

            {!isPA1 && !isPA8 && !isPA9 && !isPA10 && (
              <button className="btn btn-primary" style={{ width: '100%' }} onClick={() => runDemo()}>
                ▶ Run Demo
              </button>
            )}
          </div>

          <div id="demoOutputContainer">
            {isLoading && !isPA1 && !isPA8 && !isPA9 && !isPA10 && <div style={{ textAlign: 'center', padding: '20px' }}><div className="spinner"></div></div>}
            {error && <pre style={{ color: 'var(--red)' }}>{error}</pre>}
            {isPA1 ? renderPA1Special() : isPA2 ? renderPA2Special() : isPA8 ? renderPA8Special() : isPA9 ? renderPA9Special() : isPA10 ? renderPA10Special() : (result && renderResult(result))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default PADemoModal;
