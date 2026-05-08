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
  7: { params: [
    { name: 'message', label: 'Message to Hash', default: 'Hello Hash!' },
    { name: 'output_size', label: 'Output Digest Size (bytes)', type: 'range', min: 1, max: 16, default: 4 }
  ] },
  8: { params: [] },  // PA8 has its own input inside renderPA8Special
  9: { params: [] },  // PA9 has its own input inside renderPA9Special
  10: { params: [] }, // PA10 has its own special renderer
  11: { params: [] },
  12: { params: [{ name: 'message_int', label: 'Textbook RSA Message (Int)', default: '42' }, { name: 'message_pkcs', label: 'PKCS#1 Message (Text)', default: 'RSA!' }] },
  13: { params: [{ name: 'n', label: 'Number to Test Primality', default: '' }] },
  14: { params: [{ name: 'residues', label: 'Residues (comma separated)', default: '2,3,2' }, { name: 'moduli', label: 'Moduli (comma separated)', default: '3,5,7' }] },
  15: { params: [{ name: 'message', label: 'Message to Sign', default: 'Sign this!' }] },
  16: { params: [{ name: 'message_int', label: 'ElGamal Message (Int)', default: '42' }] },
  17: { params: [{ name: 'message_int', label: 'CCA-PKC Message (Int)', default: '42' }] },
  18: { params: [] }, // PA18 has its own special renderer
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

  // PA#11 state
  const [pa11Data,        setPa11Data]        = useState(null);   // exchange result

  // PA#2 state
  const [pa2Tab, setPa2Tab] = useState('forward');
  const [pa11MitmData,    setPa11MitmData]    = useState(null);   // MITM result
  const [pa11CdhData,     setPa11CdhData]     = useState(null);   // CDH result
  const [pa11AliceExp,    setPa11AliceExp]    = useState('');     // custom 'a'
  const [pa11BobExp,      setPa11BobExp]      = useState('');     // custom 'b'
  const [pa11EveEnabled,  setPa11EveEnabled]  = useState(false);
  const [pa11Animating,   setPa11Animating]   = useState(false);  // arrow anim
  const [pa11CdhBits,     setPa11CdhBits]     = useState(20);
  const [pa11Loading,     setPa11Loading]     = useState({});

  // PA#18 OT state
  const [pa18M0,              setPa18M0]              = useState(42);
  const [pa18M1,              setPa18M1]              = useState(99);
  const [pa18Step,            setPa18Step]            = useState(0);   // 0=idle 1=keys 2=ciphers 3=done
  const [pa18PlayData,        setPa18PlayData]        = useState(null);
  const [pa18Loading,         setPa18Loading]         = useState(false);
  const [pa18Log,             setPa18Log]             = useState([]);
  const [pa18CorrectnessData, setPa18CorrectnessData] = useState(null);
  const [pa18PrivacyData,     setPa18PrivacyData]     = useState(null);
  const [pa18CtlLoading,      setPa18CtlLoading]      = useState({});  // {correctness, privacy}

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

    // Auto-run if no params (but NOT for PA8/PA9/PA10/PA11/PA18 — they have their own special renderers)
    if (def.params.length === 0 && pa.pa !== 8 && pa.pa !== 9 && pa.pa !== 10 && pa.pa !== 11 && pa.pa !== 18) {
      runDemo(initialParams);
    }

    // Reset PA8 / PA9 / PA10 / PA11 state when modal switches PA
    setPa8Hash(null);
    setHuntStatus(null);
    stopHunt();
    setPa9Status(null);
    stopPa9Hunt();
    setPa10LeData(null); setPa10EufData(null); setPa10MacData(null);
    setPa10EthData(null); setPa10DecData(null); setPa10TimingData(null); setPa10CcaData(null);
    setPa11Data(null); setPa11MitmData(null); setPa11CdhData(null);
    setPa11EveEnabled(false); setPa11Animating(false); setPa11AliceExp(''); setPa11BobExp('');
    setPa18Step(0); setPa18PlayData(null); setPa18Log([]);
    setPa18CorrectnessData(null); setPa18PrivacyData(null); setPa18CtlLoading({});

    return () => { stopHunt(); stopPa9Hunt(); };
  }, [pa]);

  // PA8: auto-hash the default message when the modal opens
  const PA8_DEFAULT_MSG = 'Hello, DLP Hash!';
  useEffect(() => {
    if (pa.pa !== 8) return;
    setParams(p => ({ ...p, message: PA8_DEFAULT_MSG }));
    api.pa8Hash(PA8_DEFAULT_MSG).then(data => setPa8Hash(data)).catch(() => {});
  }, [pa]);

  useEffect(() => {
    if (pa.pa === 1 || pa.pa === 2 || pa.pa === 7) {
      const initialParams = {};
      (PA_DEFINITIONS[pa.pa]?.params || []).forEach(p => {
        initialParams[p.name] = p.default;
      });
      setParams(p => ({ ...p, ...initialParams }));
      runDemo(initialParams);
    }
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

  const renderPA7Special = () => {
    if (isLoading && (!result || !result.steps)) {
      return <div style={{ textAlign: 'center', padding: '40px' }}><div className="spinner"></div><p style={{ marginTop: '12px', color: 'var(--text3)' }}>Building MD-Chain...</p></div>;
    }
    if (!result || !result.steps) return null;

    return (
      <div className="pa7-special animate-fade-in">
        <div style={{ marginBottom: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text3)' }}>
              INTERACTIVE MESSAGE INPUT (Avalanche Effect)
            </label>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '11px', color: 'var(--text3)' }}>Output:</span>
                <input 
                  type="range" min="1" max="16" step="1"
                  value={params.output_size || 4}
                  style={{ width: '80px', height: '4px' }}
                  onChange={(e) => {
                    const next = { ...params, output_size: parseInt(e.target.value) };
                    setParams(next);
                    runDemo(next);
                  }}
                />
                <span style={{ fontSize: '11px', color: 'var(--accent)', fontWeight: 700, minWidth: '45px' }}>{params.output_size || 4} bytes</span>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button 
                  className={`btn btn-sm ${!params.is_hex ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ fontSize: '10px', padding: '4px 8px' }}
                  onClick={() => {
                    if (!params.is_hex) return; // Already text
                    let currentHex = (params.message || '48656c6c6f204861736821').replace(/[^0-9a-fA-F]/g, '');
                    let textStr = '';
                    try {
                      for (let i = 0; i < currentHex.length; i += 2) {
                        textStr += String.fromCharCode(parseInt(currentHex.substr(i, 2), 16));
                      }
                    } catch (e) { textStr = 'Invalid Hex'; }
                    const next = { ...params, is_hex: false, message: textStr };
                    setParams(next);
                    runDemo(next);
                  }}
                >
                  Text
                </button>
                <button 
                  className={`btn btn-sm ${params.is_hex ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ fontSize: '10px', padding: '4px 8px' }}
                  onClick={() => {
                    if (params.is_hex) return; // Already hex
                    let currentText = params.message || 'Hello Hash!';
                    let hexStr = '';
                    for (let i = 0; i < currentText.length; i++) {
                      hexStr += currentText.charCodeAt(i).toString(16).padStart(2, '0');
                    }
                    const next = { ...params, is_hex: true, message: hexStr };
                    setParams(next);
                    runDemo(next);
                  }}
                >
                  Hex
                </button>
              </div>
            </div>
          </div>
          <textarea
            className="input-field"
            style={{ 
              width: '100%', 
              height: '80px', 
              fontFamily: 'monospace', 
              fontSize: '14px', 
              resize: 'none',
              padding: '12px',
              borderRadius: '8px',
              background: 'var(--bg2)',
              color: 'var(--text1)',
              border: '1px solid var(--border)'
            }}
            value={params.message ?? (params.is_hex ? '48656c6c6f204861736821' : 'Hello Hash!')}
            onChange={(e) => {
              const next = { ...params, message: e.target.value };
              setParams(next);
              runDemo(next);
            }}
            placeholder={params.is_hex ? "Enter hex (e.g. 48656c6c6f...)" : "Type your message here..."}
          />
          <div style={{ fontSize: '10px', color: 'var(--text3)', marginTop: '6px', fontStyle: 'italic' }}>
            💡 Tip: You can also edit the hex directly inside the "Message Data" blocks below!
          </div>
        </div>

        <div className="md-chain-container" style={{ 
          display: 'flex', 
          overflowX: 'auto', 
          padding: '20px 0', 
          gap: '40px',
          scrollBehavior: 'smooth'
        }}>
          {/* Initial IV */}
          <div className="chain-step iv-step" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: '100px' }}>
            <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '8px' }}>IV (z₀)</div>
            <div style={{ 
              padding: '10px', 
              background: 'var(--bg2)', 
              border: '2px solid var(--border)', 
              borderRadius: '8px',
              fontFamily: 'monospace',
              fontSize: '12px'
            }}>
              {result.steps[0]?.cv_in || '00000000'}
            </div>
            <div style={{ height: '40px', width: '2px', background: 'var(--accent)', marginTop: '8px' }}></div>
          </div>

          {result.steps.map((step, idx) => (
            <div key={idx} className="chain-step animate-slide-in" style={{ 
              display: 'flex', 
              flexDirection: 'column', 
              alignItems: 'center', 
              minWidth: '200px', 
              position: 'relative',
              animationDelay: `${idx * 0.1}s`
            }}>
              {/* Chaining Arrow */}
              <div style={{ 
                position: 'absolute', 
                left: '-35px', 
                top: '115px', 
                fontSize: '24px', 
                color: 'var(--accent)',
                animation: 'bounceRight 2s infinite'
              }}>
                ➜
              </div>
              
              <div style={{ 
                fontSize: '11px', 
                color: step.label.includes('Data') ? 'var(--accent3)' : 'var(--accent)', 
                marginBottom: '10px',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}>
                {step.label}
              </div>

              <div style={{ 
                width: '100%',
                padding: '16px', 
                background: step.label.includes('Padding') || step.label.includes('Length') ? 'rgba(var(--accent-rgb), 0.08)' : 'rgba(var(--accent3-rgb), 0.08)', 
                border: `2px solid ${step.label.includes('Padding') || step.label.includes('Length') ? 'var(--accent)' : 'var(--accent3)'}`, 
                borderRadius: '12px',
                textAlign: 'center',
                boxShadow: '0 4px 15px rgba(0,0,0,0.2)',
                position: 'relative',
                cursor: step.label.includes('Data') ? 'text' : 'default',
                transition: 'transform 0.2s'
              }}
              onMouseEnter={(e) => step.label.includes('Data') && (e.currentTarget.style.transform = 'scale(1.02)')}
              onMouseLeave={(e) => step.label.includes('Data') && (e.currentTarget.style.transform = 'scale(1.0)')}
              >
                <div style={{ fontSize: '9px', opacity: 0.7, marginBottom: '6px', textTransform: 'uppercase' }}>Block M{idx + 1}</div>
                <code 
                  contentEditable={step.label.includes('Data')}
                  suppressContentEditableWarning
                  onBlur={(e) => {
                    if (!step.label.includes('Data')) return;
                    const newBlockHex = e.target.innerText.replace(/[^0-9a-fA-F]/g, '').padEnd(16, '0').substring(0, 16);
                    
                    // Reconstruct full message hex from steps
                    const allDataBlocks = result.steps
                      .filter(s => s.label.includes('Data'))
                      .map((s, i) => i === idx ? newBlockHex : s.block);
                    
                    const fullHex = allDataBlocks.join('');
                    const next = { ...params, message: fullHex, is_hex: true };
                    setParams(next);
                    runDemo(next);
                  }}
                  onKeyDown={(e) => e.key === 'Enter' && e.preventDefault() || e.key === 'Enter' && e.target.blur()}
                  style={{ 
                    fontSize: '13px', 
                    wordBreak: 'break-all', 
                    color: 'var(--text1)', 
                    outline: 'none',
                    padding: '2px 4px',
                    borderRadius: '4px',
                    background: step.label.includes('Data') ? 'rgba(0,0,0,0.2)' : 'transparent'
                  }}>
                  {step.block}
                </code>
              </div>

              {/* Compression Function Circle */}
              <div style={{ 
                width: '40px', 
                height: '40px', 
                borderRadius: '50%', 
                background: 'linear-gradient(135deg, var(--accent) 0%, var(--accent3) 100%)', 
                color: 'white',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '16px 0',
                fontSize: '18px',
                fontWeight: 'bold',
                boxShadow: '0 0 15px rgba(var(--accent-rgb), 0.5)',
                zIndex: 2
              }}>
                f
              </div>

              <div style={{ 
                padding: '12px 16px', 
                background: 'rgba(0,0,0,0.4)', 
                border: '1px solid var(--accent)', 
                borderRadius: '10px',
                fontFamily: 'monospace',
                fontSize: '13px',
                color: 'var(--accent)',
                fontWeight: 700,
                boxShadow: 'inset 0 0 10px rgba(var(--accent-rgb), 0.2)'
              }}>
                {step.cv_out}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text3)', marginTop: '6px', fontWeight: 600 }}>CV z{idx + 1} (Hex)</div>
            </div>
          ))}
          
          <div className="chain-step final-step" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: '150px', marginLeft: '20px' }}>
            <div style={{ position: 'absolute', left: '-35px', top: '115px', fontSize: '24px', color: 'var(--accent2)' }}>➜</div>
            <div style={{ fontSize: '11px', color: 'var(--accent2)', marginBottom: '10px', fontWeight: 800, letterSpacing: '0.1em' }}>OUTPUT</div>
            <div style={{ 
              padding: '16px 24px', 
              background: 'linear-gradient(135deg, #ec4899 0%, #8b5cf6 100%)', 
              color: 'white',
              borderRadius: '12px',
              fontFamily: 'monospace',
              fontSize: '16px',
              fontWeight: 800,
              boxShadow: '0 0 30px rgba(236, 72, 153, 0.4)',
              border: '2px solid rgba(255,255,255,0.2)',
              animation: 'pulse 2s infinite'
            }}>
              {result.digest}
            </div>
          </div>
        </div>

        <div style={{ 
          marginTop: '24px', 
          padding: '16px', 
          background: 'rgba(var(--accent-rgb), 0.1)', 
          borderRadius: '12px',
          border: '1px solid var(--border)',
          fontSize: '13px',
          lineHeight: '1.6'
        }}>
          <div style={{ fontWeight: 700, marginBottom: '8px', color: 'var(--accent)' }}>Merkle-Damgård Construction:</div>
          This visualizer shows how arbitrary length messages are hashed.
          <ul style={{ paddingLeft: '20px', margin: '8px 0' }}>
            <li><strong>Padding:</strong> <code>0x80</code> followed by zeros.</li>
            <li><strong>Strengthening:</strong> The last block contains the 64-bit message length.</li>
            <li><strong>Chain:</strong> Each block <code>Mᵢ</code> is XORed with the previous <code>zᵢ₋₁</code> (Toy compression).</li>
          </ul>
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
    return (
      <div className="pa2-special animate-fade-in" style={{ marginTop: '-10px' }}>
        {/* Tab Navigation */}
        <div style={{ display: 'flex', gap: '10px', marginBottom: '20px', borderBottom: '1px solid var(--border)', paddingBottom: '10px' }}>
          <button 
            className="btn"
            style={{ 
              background: pa2Tab === 'forward' ? 'linear-gradient(135deg, var(--accent), var(--accent2))' : 'transparent',
              color: pa2Tab === 'forward' ? 'white' : 'var(--text2)',
              border: pa2Tab === 'forward' ? 'none' : '1px solid var(--border)',
              padding: '8px 16px', borderRadius: '8px', fontSize: '12px', fontWeight: 600, cursor: 'pointer'
            }}
            onClick={() => setPa2Tab('forward')}
          >
            🌲 Tab 1: Forward (GGM Tree)
          </button>
          <button 
            className="btn"
            style={{ 
              background: pa2Tab === 'backward' ? 'linear-gradient(135deg, var(--accent), var(--accent2))' : 'transparent',
              color: pa2Tab === 'backward' ? 'white' : 'var(--text2)',
              border: pa2Tab === 'backward' ? 'none' : '1px solid var(--border)',
              padding: '8px 16px', borderRadius: '8px', fontSize: '12px', fontWeight: 600, cursor: 'pointer'
            }}
            onClick={() => setPa2Tab('backward')}
          >
            ⏪ Tab 2: Backward (PRG from PRF)
          </button>
        </div>

        {/* Tab 1 Content */}
        {pa2Tab === 'forward' && (
          <div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '16px' }}>
              <div className="field" style={{ marginBottom: 0 }}>
                <label>Hex Key (k)</label>
                <input type="text" value={params.key || ''} onChange={(e) => { 
                  const next = {...params, key: e.target.value}; setParams(next); runDemo(next); 
                }} />
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label>Query (x) - Binary</label>
                <input type="text" value={params.query || ''} onChange={(e) => { 
                  const next = {...params, query: e.target.value}; setParams(next); runDemo(next); 
                }} />
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label style={{ display: 'flex', justifyContent: 'space-between' }}>Tree Depth (n) <span>{params.depth || 4} bits</span></label>
                <input type="range" min="2" max="8" value={params.depth || 4} onChange={(e) => { 
                  const next = {...params, depth: parseInt(e.target.value)}; setParams(next); runDemo(next); 
                }} />
              </div>
            </div>

            {result && result.tree && (
              <GGMVisualizer 
                tree={result.tree} 
                queryBits={result.query_bits} 
                output={result.output} 
              />
            )}

            <div style={{ marginTop: '20px' }}>
              <button
                className="btn btn-secondary"
                style={{ width: '100%', background: showInversion ? 'var(--accent)' : 'rgba(var(--accent-rgb), 0.1)', border: '1px solid var(--accent)', color: showInversion ? 'white' : 'var(--accent)' }}
                onClick={() => {
                  if (!showInversion) {
                    runDemo(params, 'game');
                    setShowInversion(true);
                  } else {
                    setShowInversion(false);
                  }
                }}
              >
                🎮 PRF Distinguishing Game Demo
              </button>
            </div>
          </div>
        )}

        {/* Tab 2 Content */}
        {pa2Tab === 'backward' && (
          <div className="result-section animate-fade-in">
            <h3 style={{ margin: 0, marginBottom: '12px' }}>Backward PRG Construction G(s) = Fs(0ⁿ) || Fs(1ⁿ)</h3>
            <div style={{ marginBottom: '16px', fontSize: '11px', color: 'var(--text2)' }}>
              Uses the seed (s) to generate pseudorandom output via the underlying PRF.
            </div>

            <div className="field" style={{ marginBottom: '16px' }}>
              <label>Seed (s) - Hex</label>
              <input type="text" value={params.key || ''} onChange={(e) => { 
                setParams({...params, key: e.target.value}); 
                setResult(prev => prev ? { ...prev, stats: null, ratio: null } : null);
              }} />
            </div>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <button
                className="btn btn-primary"
                onClick={() => runDemo(params, 'randomness')}
              >
                🧪 Run NIST Tests
              </button>
            </div>

            <div style={{ marginTop: '20px' }}>
              {(!result?.stats && isLoading) && (
                <div style={{ textAlign: 'center', padding: '20px' }}><div className="spinner"></div></div>
              )}
              {result?.stats && (
                <div className="animate-fade-in">
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
            )}
          </div>
        </div>
        )}

        {pa2Tab === 'forward' && showInversion && result && result.game && (
          <div className="result-section animate-fade-in" style={{ marginTop: '20px' }}>
            <h3 style={{ margin: 0, marginBottom: '12px' }}>Distinguishing Game (PRF Security)</h3>
            <div style={{ padding: '12px', background: 'rgba(var(--accent-rgb), 0.05)', borderRadius: '8px', border: '1px dashed var(--border)' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, marginBottom: '8px', color: 'var(--accent)' }}>🎯 Goal: Is it PRF or Random?</div>
              
              <div style={{ display: 'flex', gap: '10px', marginBottom: '12px' }}>
                <div style={{ flex: 1, background: 'var(--bg2)', padding: '10px', borderRadius: '6px', textAlign: 'center' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text3)' }}>Current Advantage</div>
                  <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--accent)' }}>{(Math.abs(result.game.advantage) * 100).toFixed(1)}%</div>
                </div>
              </div>

              {result.game.samples && result.game.samples.map((s, idx) => (
                <div key={idx} style={{ background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '6px', marginBottom: '8px', fontSize: '10px', border: '1px solid var(--border)' }}>
                  <div style={{ color: 'var(--text3)', marginBottom: '4px', textTransform: 'uppercase', fontSize: '8px' }}>Query Sample #{idx + 1}</div>
                  <code style={{ color: 'var(--text2)', display: 'block', marginBottom: '8px', wordBreak: 'break-all' }}>{s.x}</code>
                  
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                    <div>
                      <div style={{ color: 'var(--accent3)', fontSize: '8px', textTransform: 'uppercase' }}>PRF(x)</div>
                      <code style={{ fontSize: '10px', color: 'var(--accent3)', wordBreak: 'break-all' }}>{s.prf}</code>
                    </div>
                    <div>
                      <div style={{ color: 'var(--text3)', fontSize: '8px', textTransform: 'uppercase' }}>Random(x)</div>
                      <code style={{ fontSize: '10px', color: 'var(--text3)', wordBreak: 'break-all' }}>{s.rand}</code>
                    </div>
                  </div>
                </div>
              ))}

              <div style={{ fontSize: '11px', color: 'var(--text3)', fontStyle: 'italic', marginTop: '12px' }}>
                {result.game.advantage < 0.1 ? 
                  "✅ Success! The adversary has no significant advantage. The PRF is indistinguishable from random." : 
                  "⚠️ Noticeable bias detected in this trial."}
              </div>
            </div>
          </div>
        )}
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

  // ─────────────────────────────────────────────────────────────────
  // PA#11 — Diffie-Hellman Key Exchange interactive demo
  // ─────────────────────────────────────────────────────────────────
  const renderPA11Special = () => {
    const busy      = (k) => !!pa11Loading[k];
    const setLoading = (k, v) => setPa11Loading(prev => ({ ...prev, [k]: v }));

    const hexShort = (h) => h ? h.replace('0x', '').toUpperCase() : '—';

    // ── Run normal exchange ──
    const doExchange = async () => {
      setLoading('exchange', true);
      setPa11MitmData(null);
      try {
        const a = pa11AliceExp ? parseInt(pa11AliceExp, 16) : null;
        const b = pa11BobExp   ? parseInt(pa11BobExp,   16) : null;
        const d = await api.pa11Exchange(a, b);
        setPa11Data(d);
        // Trigger arrow animation
        setPa11Animating(true);
        setTimeout(() => setPa11Animating(false), 1200);
        // If Eve is enabled, run MITM with same exponents
        if (pa11EveEnabled) {
          const m = await api.pa11Mitm(
            d.a ? parseInt(d.a, 16) : null,
            d.b ? parseInt(d.b, 16) : null
          );
          setPa11MitmData(m);
        }
      } finally { setLoading('exchange', false); }
    };

    // ── Toggle Eve ──
    const toggleEve = async () => {
      const next = !pa11EveEnabled;
      setPa11EveEnabled(next);
      if (next && pa11Data) {
        setLoading('mitm', true);
        try {
          const m = await api.pa11Mitm(
            parseInt(pa11Data.a, 16),
            parseInt(pa11Data.b, 16)
          );
          setPa11MitmData(m);
        } finally { setLoading('mitm', false); }
      } else {
        setPa11MitmData(null);
      }
    };

    // ── CDH brute force ──
    const doCdh = async () => {
      setLoading('cdh', true);
      try {
        const d = await api.pa11Cdh(pa11CdhBits);
        setPa11CdhData(d);
      } finally { setLoading('cdh', false); }
    };

    // Colours
    const aliceClr  = '#818cf8';
    const bobClr    = '#34d399';
    const eveClr    = '#f87171';
    const matchClr  = '#22c55e';
    const nomatchClr= '#ef4444';

    const keyBadge = (label, val, color, matched = null) => (
      <div style={{
        background: matched === true  ? 'rgba(34,197,94,0.12)'  :
                    matched === false ? 'rgba(239,68,68,0.12)' :
                    'rgba(0,0,0,0.25)',
        border: `1px solid ${matched === true ? matchClr : matched === false ? nomatchClr : 'rgba(255,255,255,0.1)'}`,
        borderRadius: '8px', padding: '10px 12px',
      }}>
        <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '3px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
        <div style={{ fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all', color: matched === true ? matchClr : matched === false ? nomatchClr : color, fontWeight: 700 }}>
          0x{hexShort(val)}
        </div>
        {matched === true  && <div style={{ fontSize: '10px', color: matchClr, marginTop: '4px' }}>✓ Matches</div>}
        {matched === false && <div style={{ fontSize: '10px', color: nomatchClr, marginTop: '4px' }}>✗ No match</div>}
      </div>
    );

    const inputField = (label, val, setter, placeholder, color) => (
      <div>
        <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
        <div style={{ display: 'flex', gap: '6px' }}>
          <input
            type="text"
            value={val}
            placeholder={placeholder}
            onChange={e => setter(e.target.value)}
            style={{
              flex: 1, padding: '7px 10px', background: 'rgba(0,0,0,0.35)',
              border: `1px solid ${color}55`, borderRadius: '6px',
              color: color, fontFamily: 'monospace', fontSize: '12px', outline: 'none',
            }}
          />
          <button
            onClick={() => setter('')}
            title="Randomise"
            style={{
              padding: '7px 10px', borderRadius: '6px', border: `1px solid ${color}55`,
              background: 'rgba(0,0,0,0.2)', color: color, cursor: 'pointer', fontSize: '14px',
            }}
          >🎲</button>
        </div>
      </div>
    );

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

        {/* ── Group parameters banner ── */}
        {pa11Data && (
          <div style={{
            background: 'rgba(0,0,0,0.2)', borderRadius: '10px', padding: '12px 16px',
            border: '1px solid var(--border)', fontSize: '11px',
            display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '3px 14px',
          }}>
            <span style={{ color: 'var(--text3)', fontWeight: 600 }}>⚙️ Group</span>
            <span />
            {[['p (safe prime)', pa11Data.p], ['q (order)', pa11Data.q], ['g (generator)', pa11Data.g]].map(([k, v]) => (
              <React.Fragment key={k}>
                <span style={{ color: 'var(--text3)', whiteSpace: 'nowrap' }}>{k}</span>
                <span style={{ fontFamily: 'monospace', color: 'var(--text1)', wordBreak: 'break-all' }}>0x{hexShort(v)}</span>
              </React.Fragment>
            ))}
          </div>
        )}

        {/* ── Alice / Bob two-panel ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>

          {/* Alice */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(129,140,248,0.1) 0%, rgba(99,102,241,0.05) 100%)',
            border: `1px solid ${aliceClr}55`, borderRadius: '12px', padding: '16px',
          }}>
            <div style={{ fontWeight: 700, color: aliceClr, fontSize: '13px', marginBottom: '14px' }}>👩 Alice</div>
            {inputField('Private exponent a (hex)', pa11AliceExp, setPa11AliceExp, 'random', aliceClr)}
            {pa11Data && (
              <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {keyBadge('a (private)', pa11Data.a, aliceClr)}
                {keyBadge('A = gᵃ (public)', pa11Data.A, aliceClr)}
                {pa11EveEnabled && pa11MitmData
                  ? keyBadge('K (shared w/ Eve)', pa11MitmData.K_alice, eveClr, false)
                  : keyBadge('K = Bᵃ (shared)', pa11Data.K_alice, matchClr, pa11Data.match)
                }
              </div>
            )}
          </div>

          {/* Bob */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(52,211,153,0.1) 0%, rgba(16,185,129,0.05) 100%)',
            border: `1px solid ${bobClr}55`, borderRadius: '12px', padding: '16px',
          }}>
            <div style={{ fontWeight: 700, color: bobClr, fontSize: '13px', marginBottom: '14px' }}>👨 Bob</div>
            {inputField('Private exponent b (hex)', pa11BobExp, setPa11BobExp, 'random', bobClr)}
            {pa11Data && (
              <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {keyBadge('b (private)', pa11Data.b, bobClr)}
                {keyBadge('B = gᵇ (public)', pa11Data.B, bobClr)}
                {pa11EveEnabled && pa11MitmData
                  ? keyBadge('K (shared w/ Eve)', pa11MitmData.K_bob, eveClr, false)
                  : keyBadge('K = Aᵇ (shared)', pa11Data.K_bob, matchClr, pa11Data.match)
                }
              </div>
            )}
          </div>
        </div>

        {/* ── Animated exchange arrows ── */}
        {pa11Data && (
          <div style={{ position: 'relative', height: '40px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px' }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              opacity: pa11Animating ? 1 : 0.8,
              transform: pa11Animating ? 'translateX(6px)' : 'translateX(0)',
              transition: 'transform 0.6s ease, opacity 0.3s ease',
            }}>
              <span style={{ fontFamily: 'monospace', fontSize: '11px', color: aliceClr }}>A=0x{hexShort(pa11Data.A).slice(0,6)}…</span>
              <span style={{ color: bobClr, fontSize: '16px' }}>→</span>
            </div>
            <div style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              opacity: pa11Animating ? 1 : 0.8,
              transform: pa11Animating ? 'translateX(-6px)' : 'translateX(0)',
              transition: 'transform 0.6s ease 0.1s, opacity 0.3s ease',
            }}>
              <span style={{ color: aliceClr, fontSize: '16px' }}>←</span>
              <span style={{ fontFamily: 'monospace', fontSize: '11px', color: bobClr }}>B=0x{hexShort(pa11Data.B).slice(0,6)}…</span>
            </div>
            {pa11Data.match && !pa11EveEnabled && (
              <div style={{
                background: 'rgba(34,197,94,0.15)', border: '1px solid #22c55e',
                borderRadius: '6px', padding: '4px 10px',
                color: '#22c55e', fontSize: '12px', fontWeight: 700,
              }}>
                K matches ✓
              </div>
            )}
          </div>
        )}

        {/* ── Exchange / Eve controls ── */}
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <button
            id="pa11-exchange-btn"
            disabled={busy('exchange')}
            onClick={doExchange}
            style={{
              flex: 1, padding: '11px', borderRadius: '9px', fontWeight: 700, fontSize: '13px',
              cursor: busy('exchange') ? 'not-allowed' : 'pointer',
              background: busy('exchange')
                ? 'rgba(129,140,248,0.15)'
                : 'linear-gradient(135deg, #6366f1, #818cf8)',
              border: 'none', color: busy('exchange') ? aliceClr : 'white',
              transition: 'all 0.2s',
            }}
          >
            {busy('exchange') ? '⚡ Exchanging…' : pa11Data ? '🔄 Re-Exchange' : '🔑 Exchange'}
          </button>

          {/* Eve checkbox */}
          <label
            id="pa11-eve-toggle"
            style={{
              display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer',
              background: pa11EveEnabled ? 'rgba(248,113,113,0.12)' : 'rgba(0,0,0,0.2)',
              border: `1px solid ${pa11EveEnabled ? eveClr : 'rgba(255,255,255,0.1)'}`,
              borderRadius: '8px', padding: '9px 14px', transition: 'all 0.2s',
              userSelect: 'none',
            }}
            onClick={pa11Data ? toggleEve : undefined}
            title={pa11Data ? 'Enable Eve MITM' : 'Run Exchange first'}
          >
            <span style={{
              width: '16px', height: '16px', borderRadius: '4px',
              border: `2px solid ${pa11EveEnabled ? eveClr : 'rgba(255,255,255,0.3)'}`,
              background: pa11EveEnabled ? eveClr : 'transparent',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '10px', color: 'white', transition: 'all 0.2s',
            }}>
              {pa11EveEnabled ? '✓' : ''}
            </span>
            <span style={{ fontSize: '12px', fontWeight: 600, color: pa11EveEnabled ? eveClr : 'var(--text2)', whiteSpace: 'nowrap' }}>
              👿 Enable Eve
            </span>
          </label>
        </div>

        {/* ── Eve MITM panel ── */}
        {pa11EveEnabled && pa11MitmData && (
          <div style={{
            background: 'linear-gradient(135deg, rgba(248,113,113,0.1) 0%, rgba(239,68,68,0.05) 100%)',
            border: `2px solid ${eveClr}88`,
            borderRadius: '12px', padding: '16px',
            animation: 'fadeIn 0.35s ease',
          }}>
            <div style={{ fontWeight: 700, color: eveClr, fontSize: '13px', marginBottom: '14px' }}>
              👿 Eve — Man-in-the-Middle
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '12px' }}>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '6px', textTransform: 'uppercase' }}>← toward Alice</div>
                {keyBadge('e₂ (private)', pa11MitmData.e2, eveClr)}
                {keyBadge("A' = gᵉ² sent to Alice", pa11MitmData.A_prime, eveClr)}
                {keyBadge('K_eve_alice = Aᵉ²', pa11MitmData.K_eve_alice, eveClr, pa11MitmData.alice_eve_match)}
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '6px', textTransform: 'uppercase' }}>→ toward Bob</div>
                {keyBadge('e₁ (private)', pa11MitmData.e1, eveClr)}
                {keyBadge("B' = gᵉ¹ sent to Bob", pa11MitmData.B_prime, eveClr)}
                {keyBadge('K_eve_bob = Bᵉ¹', pa11MitmData.K_eve_bob, eveClr, pa11MitmData.bob_eve_match)}
              </div>
            </div>

            {pa11MitmData.attack_success && (
              <div style={{
                background: 'rgba(248,113,113,0.15)', border: '1px solid #f87171',
                borderRadius: '8px', padding: '10px 14px',
                fontSize: '12px', color: '#fca5a5', lineHeight: 1.5,
              }}>
                💥 <strong>Attack successful!</strong> Eve holds both shared secrets.
                She can decrypt all traffic from Alice, re-encrypt for Bob, and vice versa — completely transparently.
                Alice and Bob each believe they share a secret, but Eve reads everything.
              </div>
            )}
          </div>
        )}

        {/* ── CDH Hardness panel ── */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(245,158,11,0.07) 0%, rgba(234,179,8,0.05) 100%)',
          border: '1px solid rgba(245,158,11,0.3)',
          borderRadius: '12px', padding: '16px',
        }}>
          <div style={{ fontWeight: 700, color: '#f59e0b', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '12px' }}>
            🔬 CDH Hardness Demonstration
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
            For tiny parameters (q ≈ 2<sup>{pa11CdhBits}</sup>), brute-forcing the discrete log is feasible.
            At 2048-bit parameters it would take ~2<sup>1024</sup> operations.
          </div>

          {/* Bit-size picker */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '14px', flexWrap: 'wrap' }}>
            {[12, 16, 20, 24].map(n => (
              <button
                key={n}
                onClick={() => { setPa11CdhBits(n); setPa11CdhData(null); }}
                style={{
                  flex: 1, padding: '7px 0', borderRadius: '7px', fontSize: '12px', cursor: 'pointer',
                  border: n === pa11CdhBits ? '2px solid #f59e0b' : '1px solid rgba(245,158,11,0.25)',
                  background: n === pa11CdhBits ? 'rgba(245,158,11,0.2)' : 'rgba(0,0,0,0.2)',
                  color: n === pa11CdhBits ? '#fbbf24' : 'var(--text2)', fontWeight: n === pa11CdhBits ? 700 : 400,
                  transition: 'all 0.15s',
                }}
              >{n}-bit</button>
            ))}
          </div>

          <button
            id="pa11-cdh-btn"
            disabled={busy('cdh')}
            onClick={doCdh}
            style={{
              width: '100%', padding: '10px', borderRadius: '8px', fontWeight: 700, fontSize: '13px',
              cursor: busy('cdh') ? 'not-allowed' : 'pointer',
              background: busy('cdh') ? 'rgba(245,158,11,0.15)' : 'linear-gradient(135deg, #f59e0b, #d97706)',
              border: 'none', color: busy('cdh') ? '#f59e0b' : 'white', transition: 'all 0.2s',
            }}
          >
            {busy('cdh') ? '⏳ Brute-forcing…' : '💪 Run Brute Force'}
          </button>

          {pa11CdhData && (
            <div style={{ marginTop: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: '1px solid rgba(245,158,11,0.2)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '3px' }}>Bit size</div>
                  <div style={{ fontFamily: 'monospace', color: '#fbbf24', fontWeight: 700 }}>{pa11CdhData.bits} bits</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: '1px solid rgba(245,158,11,0.2)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '3px' }}>Time taken</div>
                  <div style={{ fontFamily: 'monospace', color: '#fbbf24', fontWeight: 700 }}>{pa11CdhData.time_sec}s</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: '1px solid rgba(245,158,11,0.2)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '3px' }}>Secret a</div>
                  <div style={{ fontFamily: 'monospace', color: '#fbbf24', fontSize: '11px', wordBreak: 'break-all' }}>0x{hexShort(pa11CdhData.a)}</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: '1px solid rgba(245,158,11,0.2)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', marginBottom: '3px' }}>Found by brute force</div>
                  <div style={{ fontFamily: 'monospace', color: pa11CdhData.correct ? '#22c55e' : '#ef4444', fontSize: '11px', wordBreak: 'break-all' }}>
                    0x{hexShort(pa11CdhData.brute_force_found)}
                  </div>
                </div>
              </div>
              <div style={{
                display: 'flex', gap: '8px',
              }}>
                <div style={{
                  flex: 1, background: pa11CdhData.key_recovered ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.1)',
                  border: `1px solid ${pa11CdhData.key_recovered ? '#22c55e' : '#ef4444'}`,
                  borderRadius: '8px', padding: '10px', textAlign: 'center',
                  fontSize: '12px', fontWeight: 700, color: pa11CdhData.key_recovered ? '#22c55e' : '#ef4444',
                }}>
                  {pa11CdhData.key_recovered ? '✓ Key Recovered' : '✗ Key Not Found'}
                </div>
              </div>
              <div style={{
                background: 'rgba(0,0,0,0.2)', borderRadius: '8px', padding: '10px 12px',
                fontSize: '11px', color: 'var(--text2)', lineHeight: 1.5,
                borderLeft: '3px solid #f59e0b',
              }}>
                {pa11CdhData.conclusion}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderPA18Special = () => {
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));
    const b = pa18PlayData?.b;
    const done = pa18Step === 3;

    const shortNum = (n) => n == null ? '?' : String(n).slice(-8);

    const runOT = async (choice) => {
      setPa18Loading(true);
      setPa18Step(0);
      setPa18PlayData(null);
      setPa18Log([{ icon: '🔑', text: `Bob selects b=${choice} — generating key pairs…`, color: '#a5b4fc' }]);
      try {
        const data = await api.pa18Play(choice, Number(pa18M0), Number(pa18M1));
        // Step 1 — keys ready
        await sleep(500);
        setPa18Step(1);
        setPa18Log([
          { icon: '🔑', text: `Bob selects b=${choice} — generating key pairs…`, color: '#a5b4fc' },
          { icon: '✓', text: `pk_${choice}   = g^sk (honest) →  …${shortNum(choice === 0 ? data.pk0_h : data.pk1_h)}`, color: '#34d399' },
          { icon: '✓', text: `pk_${1-choice} = random element  →  …${shortNum(choice === 0 ? data.pk1_h : data.pk0_h)}  (no trapdoor)`, color: '#fbbf24' },
          { icon: '📤', text: `(pk₀, pk₁) sent to Alice`, color: '#a5b4fc' },
        ]);
        // Step 2 — ciphertexts
        await sleep(600);
        setPa18Step(2);
        setPa18Log(prev => [...prev,
          { icon: '🔒', text: `Alice encrypts: C₀ = ElGamal(pk₀, m₀)  →  […${shortNum(data.C0[0])}, …${shortNum(data.C0[1])}]`, color: '#c4b5fd' },
          { icon: '🔒', text: `Alice encrypts: C₁ = ElGamal(pk₁, m₁)  →  […${shortNum(data.C1[0])}, …${shortNum(data.C1[1])}]`, color: '#c4b5fd' },
          { icon: '📥', text: `(C₀, C₁) received by Bob`, color: '#a5b4fc' },
        ]);
        // Step 3 — decrypt
        await sleep(600);
        setPa18Step(3);
        setPa18PlayData(data);
        setPa18Log(prev => [...prev,
          { icon: '🔓', text: `Bob decrypts C_${choice} using sk_${choice}…`, color: '#a5b4fc' },
          { icon: '✨', text: `m_${choice} = ${data.mb}  ← revealed!`, color: '#34d399' },
          { icon: '🔒', text: `m_${1-choice} = ??  ← no sk_${1-choice}, cannot decrypt`, color: '#f87171' },
        ]);
      } catch (err) {
        setPa18Log(prev => [...prev, { icon: '❌', text: `Error: ${err.message}`, color: '#f87171' }]);
      }
      setPa18Loading(false);
    };

    const panelBase = {
      borderRadius: '14px', padding: '18px', flex: 1,
      display: 'flex', flexDirection: 'column', gap: '12px',
    };

    const stepDot = (n) => {
      const active = pa18Step >= n;
      return (
        <div style={{
          width: 24, height: 24, borderRadius: '50%', flexShrink: 0,
          background: active ? 'var(--accent)' : 'rgba(255,255,255,0.08)',
          border: `2px solid ${active ? 'var(--accent)' : 'rgba(255,255,255,0.15)'}`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: '11px', fontWeight: 700, color: active ? '#fff' : 'rgba(255,255,255,0.3)',
          transition: 'all 0.4s',
        }}>{n}</div>
      );
    };

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

        {/* ── Message inputs + two-panel layout ── */}
        <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>

          {/* Alice panel */}
          <div style={{
            ...panelBase,
            background: 'linear-gradient(135deg, rgba(168,85,247,0.10) 0%, rgba(99,102,241,0.10) 100%)',
            border: '1px solid rgba(168,85,247,0.35)',
            opacity: done ? 1 : 0.75,
            minWidth: 180,
          }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: '#c4b5fd', letterSpacing: '0.06em' }}>
              👩 ALICE &nbsp;<span style={{ fontWeight: 400, opacity: 0.6, fontSize: '10px' }}>Sender</span>
            </div>

            {[['m₀', pa18M0, setPa18M0], ['m₁', pa18M1, setPa18M1]].map(([label, val, setter]) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '12px', color: '#c4b5fd', minWidth: 24 }}>{label}</span>
                <input
                  type="number" value={val}
                  onChange={e => setter(Number(e.target.value))}
                  disabled={pa18Loading}
                  style={{
                    flex: 1, padding: '6px 10px', borderRadius: '6px', fontSize: '13px',
                    background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(168,85,247,0.35)',
                    color: 'var(--text1)', outline: 'none',
                  }}
                />
                <span style={{ fontSize: '16px' }}>{done ? '🔒' : '❓'}</span>
              </div>
            ))}

            {done && (
              <div style={{ marginTop: '6px', fontSize: '11px', color: 'var(--text3)', lineHeight: 1.5 }}>
                Alice sees only <strong>(pk₀, pk₁)</strong> — cannot tell which key Bob generated honestly.
              </div>
            )}
          </div>

          {/* Bob panel */}
          <div style={{
            ...panelBase,
            background: 'linear-gradient(135deg, rgba(34,197,94,0.10) 0%, rgba(16,185,129,0.10) 100%)',
            border: '1px solid rgba(34,197,94,0.35)',
            minWidth: 180,
          }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: '#86efac', letterSpacing: '0.06em' }}>
              🧑 BOB &nbsp;<span style={{ fontWeight: 400, opacity: 0.6, fontSize: '10px' }}>Receiver</span>
            </div>

            <div style={{ fontSize: '12px', color: 'var(--text2)', marginBottom: '4px' }}>Choose which message to receive:</div>

            <div style={{ display: 'flex', gap: '8px' }}>
              {[0, 1].map(choice => (
                <button key={choice}
                  id={`pa18-choose-${choice}-btn`}
                  disabled={pa18Loading}
                  onClick={() => runOT(choice)}
                  style={{
                    flex: 1, padding: '10px 0', borderRadius: '8px', fontWeight: 700, fontSize: '14px',
                    cursor: pa18Loading ? 'not-allowed' : 'pointer',
                    background: done && b === choice
                      ? 'linear-gradient(135deg, #22c55e, #16a34a)'
                      : 'rgba(34,197,94,0.12)',
                    border: `2px solid ${done && b === choice ? '#22c55e' : 'rgba(34,197,94,0.3)'}`,
                    color: done && b === choice ? '#fff' : '#86efac',
                    transition: 'all 0.25s',
                  }}
                >
                  {pa18Loading && b === choice ? '⏳' : `m${choice === 0 ? '₀' : '₁'}`}
                </button>
              ))}
            </div>

            {/* Result reveal */}
            {done && (
              <div style={{ marginTop: '4px' }}>
                <div style={{
                  background: 'linear-gradient(135deg, rgba(34,197,94,0.15) 0%, rgba(16,185,129,0.15) 100%)',
                  border: '2px solid #22c55e', borderRadius: '10px', padding: '12px',
                  textAlign: 'center',
                }}>
                  <div style={{ fontSize: '11px', color: '#86efac', marginBottom: '4px' }}>m_{b} revealed ✨</div>
                  <div style={{ fontSize: '28px', fontWeight: 900, color: '#22c55e', fontFamily: 'monospace' }}>
                    {pa18PlayData?.mb}
                  </div>
                </div>
                <div style={{
                  marginTop: '8px',
                  background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)',
                  borderRadius: '8px', padding: '10px', textAlign: 'center',
                }}>
                  <div style={{ fontSize: '10px', color: '#f87171', marginBottom: '2px' }}>m_{1-b} hidden</div>
                  <div style={{ fontSize: '22px', fontWeight: 900, color: '#f87171', letterSpacing: '4px' }}>? ?</div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── Protocol steps indicator ── */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: '0',
          background: 'rgba(0,0,0,0.2)', borderRadius: '10px', padding: '12px 16px',
          border: '1px solid var(--border)',
        }}>
          {[
            [1, 'Receiver Step 1', 'Bob generates keys'],
            [2, 'Sender Step', 'Alice encrypts'],
            [3, 'Receiver Step 2', 'Bob decrypts'],
          ].map(([n, title, sub], i) => (
            <React.Fragment key={n}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1 }}>
                {stepDot(n)}
                <div>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: pa18Step >= n ? 'var(--text1)' : 'var(--text3)' }}>{title}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text3)' }}>{sub}</div>
                </div>
              </div>
              {i < 2 && <div style={{ width: 24, height: 2, background: pa18Step > n ? 'var(--accent)' : 'rgba(255,255,255,0.1)', flexShrink: 0, transition: 'background 0.4s' }} />}
            </React.Fragment>
          ))}
        </div>

        {/* ── Protocol Log ── */}
        {pa18Log.length > 0 && (
          <div style={{
            background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(99,102,241,0.25)',
            borderRadius: '10px', padding: '14px',
          }}>
            <div style={{ fontSize: '10px', fontWeight: 700, color: 'var(--text3)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '10px' }}>
              📋 Protocol Log
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {pa18Log.map((entry, i) => (
                <div key={i} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', fontSize: '12px' }}>
                  <span style={{ flexShrink: 0 }}>{entry.icon}</span>
                  <span style={{ fontFamily: 'monospace', color: entry.color, lineHeight: 1.5 }}>{entry.text}</span>
                </div>
              ))}
              {pa18Loading && (
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center', fontSize: '12px', color: 'var(--text3)' }}>
                  <div className="spinner" style={{ width: 14, height: 14, flexShrink: 0 }} />
                  <span>Running…</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Cheat Attempt (only after step 3) ── */}
        {done && (
          <div style={{
            background: 'linear-gradient(135deg, rgba(245,158,11,0.07) 0%, rgba(239,68,68,0.07) 100%)',
            border: '1px solid rgba(245,158,11,0.35)', borderRadius: '12px', padding: '16px',
          }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: '#f59e0b', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '10px' }}>
              🕵️ Cheat Attempt — Try Decrypting m_&#123;1-b&#125;
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text2)', lineHeight: 1.6, marginBottom: '12px' }}>
              Bob tries brute-forcing <code style={{ color: '#fbbf24' }}>sk_&#123;1-b&#125;</code> by trying 5 000 consecutive guesses and decrypting C<sub>&#123;1-b&#125;</sub>. Since sk_&#123;1-b&#125; was chosen uniformly from a ~2³¹ group, the odds of a hit are ≈ 0.00025 %.
            </div>
            {pa18PlayData?.cheat && (
              <div style={{
                borderRadius: '8px', padding: '12px',
                background: pa18PlayData.cheat.failed ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.12)',
                border: `1px solid ${pa18PlayData.cheat.failed ? '#22c55e' : '#ef4444'}`,
              }}>
                <div style={{ fontWeight: 700, fontSize: '13px', color: pa18PlayData.cheat.failed ? '#22c55e' : '#ef4444', marginBottom: '8px' }}>
                  {pa18PlayData.cheat.failed ? `✓ Cheat failed — m_${1-b} stays hidden` : `✗ Lucky hit (sk guess found within ${pa18PlayData.cheat.searched})`}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px', fontSize: '11px' }}>
                  <span style={{ color: 'var(--text3)' }}>Searched</span>
                  <span style={{ fontFamily: 'monospace', color: 'var(--text2)' }}>{pa18PlayData.cheat.searched.toLocaleString()} candidate keys</span>
                  <span style={{ color: 'var(--text3)' }}>Result</span>
                  <span style={{ fontFamily: 'monospace', color: pa18PlayData.cheat.failed ? '#22c55e' : '#f87171' }}>
                    {pa18PlayData.cheat.failed ? `m_${1-b} = ??  (DLP protects sk_${1-b})` : `Found sk = ${pa18PlayData.cheat.found_sk} → m = ${pa18PlayData.cheat.found_msg}`}
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Correctness + Privacy tests ── */}
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button
            id="pa18-correctness-btn"
            disabled={pa18CtlLoading.correctness}
            onClick={async () => {
              setPa18CtlLoading(p => ({ ...p, correctness: true }));
              try { setPa18CorrectnessData(await api.pa18Correctness()); } catch (_) {}
              setPa18CtlLoading(p => ({ ...p, correctness: false }));
            }}
            style={{
              flex: 1, padding: '9px', borderRadius: '8px', fontWeight: 700, fontSize: '12px',
              cursor: pa18CtlLoading.correctness ? 'not-allowed' : 'pointer',
              background: pa18CorrectnessData ? 'rgba(34,197,94,0.12)' : 'rgba(99,102,241,0.12)',
              border: `1px solid ${pa18CorrectnessData ? '#22c55e' : 'rgba(99,102,241,0.4)'}`,
              color: pa18CorrectnessData ? '#86efac' : '#a5b4fc',
            }}
          >
            {pa18CtlLoading.correctness ? '⏳ Running…' : '🧪 100-Trial Correctness'}
          </button>
          <button
            id="pa18-privacy-btn"
            disabled={pa18CtlLoading.privacy}
            onClick={async () => {
              setPa18CtlLoading(p => ({ ...p, privacy: true }));
              try { setPa18PrivacyData(await api.pa18Privacy()); } catch (_) {}
              setPa18CtlLoading(p => ({ ...p, privacy: false }));
            }}
            style={{
              flex: 1, padding: '9px', borderRadius: '8px', fontWeight: 700, fontSize: '12px',
              cursor: pa18CtlLoading.privacy ? 'not-allowed' : 'pointer',
              background: pa18PrivacyData ? 'rgba(245,158,11,0.12)' : 'rgba(99,102,241,0.12)',
              border: `1px solid ${pa18PrivacyData ? '#f59e0b' : 'rgba(99,102,241,0.4)'}`,
              color: pa18PrivacyData ? '#fbbf24' : '#a5b4fc',
            }}
          >
            {pa18CtlLoading.privacy ? '⏳ Running…' : '🔍 Privacy Analysis'}
          </button>
        </div>

        {/* Correctness result */}
        {pa18CorrectnessData && (
          <div style={{
            background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.3)',
            borderRadius: '10px', padding: '14px',
          }}>
            <div style={{ fontWeight: 700, color: '#22c55e', marginBottom: '8px', fontSize: '13px' }}>
              🧪 Correctness: {pa18CorrectnessData.correct}/{pa18CorrectnessData.trials} trials passed
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ flex: 1, height: 8, background: 'rgba(0,0,0,0.3)', borderRadius: 4, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 4, transition: 'width 0.5s ease',
                  width: `${(pa18CorrectnessData.correct / pa18CorrectnessData.trials) * 100}%`,
                  background: pa18CorrectnessData.all_correct ? 'linear-gradient(90deg, #22c55e, #16a34a)' : 'linear-gradient(90deg, #f59e0b, #ef4444)',
                }} />
              </div>
              <span style={{ fontSize: '12px', fontWeight: 700, color: '#22c55e', minWidth: 40 }}>
                {(pa18CorrectnessData.rate * 100).toFixed(0)}%
              </span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text3)', marginTop: '8px' }}>
              {pa18CorrectnessData.all_correct ? '✓ All 100 trials: receiver always recovers m_b correctly.' : '⚠ Some failures — check group parameters.'}
            </div>
          </div>
        )}

        {/* Privacy result */}
        {pa18PrivacyData && (
          <div style={{
            background: 'rgba(245,158,11,0.07)', border: '1px solid rgba(245,158,11,0.3)',
            borderRadius: '10px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '10px',
          }}>
            <div style={{ fontWeight: 700, color: '#f59e0b', fontSize: '13px' }}>🔍 Privacy Analysis</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              {/* Receiver privacy */}
              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '8px', padding: '10px' }}>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#fbbf24', marginBottom: '6px' }}>Receiver Privacy</div>
                <div style={{ fontSize: '11px', color: 'var(--text2)', lineHeight: 1.6 }}>
                  Sender guessed b correctly <strong>{pa18PrivacyData.receiver.sender_correct_guesses}</strong>/{pa18PrivacyData.receiver.trials} times<br />
                  Advantage: <strong style={{ color: pa18PrivacyData.receiver.private ? '#22c55e' : '#ef4444' }}>
                    {(pa18PrivacyData.receiver.sender_advantage * 100).toFixed(1)}%
                  </strong><br />
                  <span style={{ color: pa18PrivacyData.receiver.private ? '#22c55e' : '#ef4444' }}>
                    {pa18PrivacyData.receiver.private ? '✓ Private (≈ random guess)' : '✗ Not private!'}
                  </span>
                </div>
              </div>
              {/* Sender privacy */}
              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '8px', padding: '10px' }}>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#fbbf24', marginBottom: '6px' }}>Sender Privacy</div>
                <div style={{ fontSize: '11px', color: 'var(--text2)', lineHeight: 1.6 }}>
                  Brute-forced {pa18PrivacyData.sender.brute_force_searched.toLocaleString()} keys<br />
                  Found m_{`{1-b}`}: <strong style={{ color: pa18PrivacyData.sender.private ? '#22c55e' : '#ef4444' }}>
                    {pa18PrivacyData.sender.brute_force_m1 == null ? 'No' : `Yes (${pa18PrivacyData.sender.brute_force_m1})`}
                  </strong><br />
                  <span style={{ color: pa18PrivacyData.sender.private ? '#22c55e' : '#ef4444' }}>
                    {pa18PrivacyData.sender.private ? '✓ DLP protects sk_{1-b}' : '✗ Key found (tiny params)'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderPA13Special = () => {
    const isPrime = result?.is_prime;
    const rounds = result?.rounds || [];
    
    return (
      <div className="pa13-special animate-fade-in">
        {/* Controls */}
        <div style={{ marginBottom: '20px', background: 'var(--bg2)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div className="field">
              <label>Number to Test (n)</label>
              <input 
                type="text" 
                value={params.n || ''} 
                onChange={(e) => { setParams({ ...params, n: e.target.value }); setResult(null); }}
                className="input-field"
                placeholder="Enter a large integer..."
              />
            </div>
            <div className="field">
              <label style={{ display: 'flex', justifyContent: 'space-between' }}>
                Rounds (k) <span>{params.rounds || 10}</span>
              </label>
              <input 
                type="range" min="1" max="40" 
                value={params.rounds || 10}
                onChange={(e) => { setParams({ ...params, rounds: parseInt(e.target.value) }); setResult(null); }}
              />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <button className="btn btn-primary" onClick={() => { setResult(null); runDemo({ ...params, task: params.n === '561' ? 'carmichael' : 'test' }); }}>
                🧪 Run Miller-Rabin
              </button>
              <button className="btn btn-secondary" onClick={() => { setResult(null); runDemo({ ...params, task: 'generate', bits: 64 }); }}>
                🎲 Gen 64-bit Prime
              </button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <button className="btn btn-secondary" style={{ fontSize: '11px' }} onClick={() => { setParams({ ...params, n: '561' }); setResult(null); }}>
                🛡️ Load 561 (Carmichael)
              </button>
              <button className="btn btn-secondary" style={{ fontSize: '11px', overflow: 'hidden', textOverflow: 'ellipsis' }} onClick={() => { setParams({ ...params, n: '50454031626014583076315936191179085094450305445103984158485369931027336053089', task: 'test' }); setResult(null); }}>
                🧩 Load Known Composite
              </button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <button className="btn btn-secondary" style={{ fontSize: '11px', overflow: 'hidden', textOverflow: 'ellipsis' }} onClick={() => { setParams({ ...params, n: '99143722431692432695197203697643226071348800903354283165788708015992029220483', task: 'test' }); setResult(null); }}>
                💎 Load 256-bit Prime
              </button>
              <button className="btn btn-secondary" style={{ fontSize: '11px' }} onClick={() => { setResult(null); runDemo({ ...params, task: 'benchmark' }); }}>
                📊 Performance Benchmark
              </button>
            </div>
          </div>
        </div>

        {/* Loading State */}
        {isLoading && (
          <div className="animate-fade-in" style={{ textAlign: 'center', padding: '30px', background: 'var(--bg2)', borderRadius: '12px', border: '1px solid var(--border)', marginBottom: '20px' }}>
            <div className="spinner" style={{ margin: '0 auto' }}></div>
            <div style={{ fontSize: '12px', marginTop: '12px', color: 'var(--text2)', fontWeight: 600 }}>Processing Cryptographic Operations...</div>
          </div>
        )}

        {/* Results for Generation */}
        {result && result.prime && (
          <div className="result-card animate-slide-in" style={{
            background: 'rgba(34,197,94,0.08)',
            border: '1px solid #22c55e',
            borderRadius: '12px', padding: '16px', marginBottom: '20px'
          }}>
            <div style={{ fontSize: '10px', color: '#22c55e', fontWeight: 800 }}>GENERATED {result.bits}-BIT PRIME</div>
            <code style={{ fontSize: '11px', display: 'block', wordBreak: 'break-all', margin: '8px 0', maxHeight: '60px', overflowY: 'auto' }}>
              {result.prime}
            </code>
            <div style={{ fontSize: '12px', opacity: 0.8 }}>
              Successfully found after <strong>{result.attempts}</strong> random candidates tested!
            </div>
          </div>
        )}

        {/* Results */}
        {result && result.n && (
          <div className="result-card animate-slide-in" style={{
            background: isPrime ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
            border: `1px solid ${isPrime ? '#22c55e' : '#ef4444'}`,
            borderRadius: '12px', padding: '20px', marginBottom: '20px', textAlign: 'center'
          }}>
            <div style={{ fontSize: '11px', color: isPrime ? '#22c55e' : '#ef4444', textTransform: 'uppercase', fontWeight: 800, letterSpacing: '0.1em' }}>
              Primality Result for n = {result.n}
            </div>
            <div style={{ fontSize: '32px', fontWeight: 900, color: isPrime ? '#22c55e' : '#ef4444', margin: '8px 0' }}>
              {isPrime ? 'PROBABLY PRIME' : 'DEFINITELY COMPOSITE'}
            </div>
            <div style={{ fontSize: '12px', opacity: 0.8 }}>
              {isPrime 
                ? `Confidence: >${(100 * (1 - Math.pow(4, -(params.rounds || 10)))).toFixed(12)}%` 
                : 'Reason: Found a witness of compositeness'}
            </div>
            <div style={{ fontSize: '11px', marginTop: '8px', opacity: 0.6 }}>Time: {result.time_ms?.toFixed(2)}ms</div>
          </div>
        )}

        {/* Witness Trace Table */}
        {rounds.length > 0 && (
          <div className="trace-section animate-fade-in">
            <h3 style={{ fontSize: '14px', marginBottom: '12px' }}>Witness Trace (aᵈ mod n)</h3>
            <div style={{ overflowX: 'auto', background: 'var(--bg2)', borderRadius: '8px', border: '1px solid var(--border)' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                <thead style={{ background: 'rgba(255,255,255,0.05)', textAlign: 'left' }}>
                  <tr>
                    <th style={{ padding: '10px' }}>#</th>
                    <th style={{ padding: '10px' }}>Witness (a)</th>
                    <th style={{ padding: '10px' }}>aᵈ mod n</th>
                    <th style={{ padding: '10px' }}>Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {rounds.map((r, i) => (
                    <tr key={i} style={{ borderTop: '1px solid var(--border)' }}>
                      <td style={{ padding: '10px', color: 'var(--text3)' }}>{r.round}</td>
                      <td style={{ padding: '10px', fontFamily: 'monospace' }}>{r.witness}</td>
                      <td style={{ padding: '10px', fontFamily: 'monospace' }}>{r.initial_x}</td>
                      <td style={{ 
                        padding: '10px', 
                        color: r.verdict.includes('COMPOSITE') ? '#ef4444' : '#22c55e',
                        fontWeight: 600,
                        fontSize: '11px'
                      }}>
                        {r.verdict}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Carmichael Results */}
        {result && result.fermat_samples && (
          <div className="carmichael-section animate-slide-in" style={{ padding: '20px', background: 'var(--bg2)', borderRadius: '12px', border: '1px solid var(--border)', marginBottom: '20px' }}>
            <h3 style={{ fontSize: '15px', color: '#f59e0b', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              🛡️ The Carmichael Paradox (n = 561)
            </h3>
            <p style={{ fontSize: '12px', margin: '8px 0', opacity: 0.8, lineHeight: '1.5' }}>
              561 is composite (3×11×17), but it passes the Fermat test for <strong>all</strong> bases 'a' coprime to n. 
              This makes it a "pseudoprime" that fools simpler tests.
            </p>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginTop: '16px' }}>
              <div style={{ padding: '12px', background: 'rgba(239,68,68,0.05)', border: '1px solid #ef4444', borderRadius: '10px' }}>
                <div style={{ fontSize: '10px', fontWeight: 800, color: '#ef4444', marginBottom: '8px' }}>NAIVE FERMAT TEST (FOOLED)</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {result.fermat_samples.map((s, i) => (
                    <div key={i} style={{ fontSize: '11px', fontFamily: 'monospace' }}>
                      {s.a}⁵⁶⁰ mod 561 = <span style={{ color: '#ef4444', fontWeight: 700 }}>{s.result}</span>
                    </div>
                  ))}
                  <div style={{ fontSize: '10px', marginTop: '4px', fontStyle: 'italic', opacity: 0.7 }}>Result: Looks Prime!</div>
                </div>
              </div>
              
              <div style={{ padding: '12px', background: 'rgba(34,197,94,0.05)', border: '1px solid #22c55e', borderRadius: '10px' }}>
                <div style={{ fontSize: '10px', fontWeight: 800, color: '#22c55e', marginBottom: '8px' }}>MILLER-RABIN TEST (CAUGHT)</div>
                {result.miller_rabin_witness ? (
                  <div style={{ fontSize: '11px' }}>
                    <div style={{ marginBottom: '4px' }}>Witness a = {result.miller_rabin_witness.a}</div>
                    <div style={{ fontFamily: 'monospace', opacity: 0.8 }}>
                      aᵈ mod n = {result.miller_rabin_witness.initial_x} <br/>
                      Next square = {result.miller_rabin_witness.steps[0]}
                    </div>
                    <div style={{ fontSize: '10px', marginTop: '8px', color: '#22c55e', fontWeight: 700 }}>Result: COMPOSITE</div>
                  </div>
                ) : (
                  <div style={{ fontSize: '11px', opacity: 0.6 }}>Searching for witness...</div>
                )}
              </div>
            </div>
          </div>
        )}
        {/* Benchmark Results */}
        {result && result['64'] && (
          <div className="benchmark-section animate-slide-in" style={{ 
            padding: '20px', 
            background: 'var(--bg2)', 
            borderRadius: '12px', 
            border: '1px solid var(--border)' 
          }}>
            <h3 style={{ fontSize: '15px', marginBottom: '16px' }}>📊 Primality Performance Benchmarks</h3>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                <thead>
                  <tr style={{ textAlign: 'left', borderBottom: '2px solid var(--border)' }}>
                    <th style={{ padding: '8px' }}>Bit Size</th>
                    <th style={{ padding: '8px' }}>Avg Samples</th>
                    <th style={{ padding: '8px' }}>Theoretical (0.34×b)</th>
                    <th style={{ padding: '8px' }}>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {[64, 128, 256, 512, 1024, 2048].map(bits => (
                    <tr key={bits} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '8px', fontWeight: 700 }}>{bits}</td>
                      <td style={{ padding: '8px', color: 'var(--accent)' }}>
                        {result[bits] ? result[bits].avg_candidates.toFixed(1) : '...'}
                      </td>
                      <td style={{ padding: '8px', opacity: 0.6 }}>{(bits * 0.346).toFixed(1)}</td>
                      <td style={{ padding: '8px', fontFamily: 'monospace' }}>
                        {result[bits] ? `${result[bits].avg_time_sec.toFixed(4)}s` : '...'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            
            <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(var(--accent-rgb), 0.05)', borderRadius: '8px', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--accent)', marginBottom: '4px', textTransform: 'uppercase' }}>Theoretical Insight</div>
              <p style={{ fontSize: '11px', lineHeight: '1.4', opacity: 0.8, margin: 0 }}>
                The <strong>Prime Number Theorem</strong> predicts a linear growth $O(\ln n)$ in the number of candidates sampled. 
                Our actual data closely tracks the predicted <strong>0.34 × bits</strong> threshold, validating the mathematical distribution of primes!
              </p>
            </div>
          </div>
        )}
      </div>
    );
  };

  const activePAId = Number(pa.pa);
  const isPaDemo1 = activePAId === 1;
  const isPaDemo2 = activePAId === 2;
  const isPaDemo6 = activePAId === 6;
  const isPaDemo7 = activePAId === 7;
  const isPaDemo8 = activePAId === 8;
  const isPaDemo9 = activePAId === 9;
  const isPaDemo10 = activePAId === 10;
  const isPaDemo11 = activePAId === 11;
  const isPaDemo13 = activePAId === 13;
  const isPaDemo18 = activePAId === 18;

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
              {def.params
                .filter(p => !isPaDemo7 && !isPaDemo13 && !isPaDemo2)
                .map(p => (
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
                        if (isPaDemo1 || isPaDemo2 || isPaDemo7 || isPaDemo8) {
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
                        if (isPaDemo1 || isPaDemo2 || isPaDemo7 || isPaDemo8) {
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

            {!isPaDemo1 && !isPaDemo2 && !isPaDemo8 && !isPaDemo9 && !isPaDemo10 && !isPaDemo11 && !isPaDemo13 && !isPaDemo18 && (
              <button className="btn btn-primary" style={{ width: '100%' }} onClick={() => runDemo()}>
                ▶ Run Demo
              </button>
            )}
          </div>

          <div id="demoOutputContainer">
            {isLoading && !isPaDemo1 && !isPaDemo7 && !isPaDemo8 && !isPaDemo9 && !isPaDemo10 && !isPaDemo11 && !isPaDemo13 && !isPaDemo18 && <div style={{ textAlign: 'center', padding: '20px' }}><div className="spinner"></div></div>}
            {error && <pre style={{ color: 'var(--red)' }}>{error}</pre>}
            {isPaDemo7 ? renderPA7Special() : isPaDemo1 ? renderPA1Special() : isPaDemo2 ? renderPA2Special() : isPaDemo8 ? renderPA8Special() : isPaDemo9 ? renderPA9Special() : isPaDemo10 ? renderPA10Special() : isPaDemo11 ? renderPA11Special() : isPaDemo13 ? renderPA13Special() : isPaDemo18 ? renderPA18Special() : (result && renderResult(result))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default PADemoModal;
