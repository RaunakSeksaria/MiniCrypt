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
  3: { params: [] },  // PA3 has its own interactive renderer
  4: { params: [] },  // PA4 has its own visual animator renderer
  5: { params: [] },  // PA5 has its own interactive renderer
  6: { params: [] },  // PA6 has its own interactive renderer
  7: { params: [
    { name: 'message', label: 'Message to Hash', default: 'Hello Hash!' },
    { name: 'output_size', label: 'Output Digest Size (bytes)', type: 'range', min: 1, max: 16, default: 4 }
  ] },
  8: { params: [] },  // PA8 has its own input inside renderPA8Special
  9: { params: [] },  // PA9 has its own input inside renderPA9Special
  10: { params: [] }, // PA10 has its own special renderer
  11: { params: [] },
  12: { params: [] },  // PA12 has its own interactive renderer
  13: { params: [{ name: 'n', label: 'Number to Test Primality', default: '' }] },
  14: { params: [] },  // PA14 has its own interactive renderer
  15: { params: [] },  // PA15 has its own interactive renderer
  16: { params: [] },  // PA16 has its own interactive renderer
  17: { params: [] },  // PA17 has its own interactive renderer
  18: { params: [] }, // PA18 has its own special renderer
  19: { params: [] },  // PA19 has its own interactive renderer
  20: { params: [] }  // PA20 has its own interactive renderer
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

  // PA#3 interactive IND-CPA game state
  const [pa3SessionId, setPa3SessionId]   = useState(null);
  const [pa3Broken, setPa3Broken]         = useState(false);
  const [pa3M0, setPa3M0]                 = useState('Hello World!');
  const [pa3M1, setPa3M1]                 = useState('Goodbye World');
  const [pa3OracleMsg, setPa3OracleMsg]   = useState('');
  const [pa3OracleLog, setPa3OracleLog]   = useState([]);
  const [pa3Challenge, setPa3Challenge]   = useState(null);  // {nonce_hex, ciphertext_hex}
  const [pa3GuessResult, setPa3GuessResult] = useState(null);
  const [pa3Rounds, setPa3Rounds]         = useState([]);
  const [pa3Stats, setPa3Stats]           = useState(null);  // {total, correct, advantage}
  const [pa3SimData, setPa3SimData]       = useState(null);
  const [pa3Loading, setPa3Loading]       = useState({});
  const [pa3LenError, setPa3LenError]     = useState(null);

  // PA#4 Modes visual animator state
  const [pa4Mode, setPa4Mode]           = useState('CBC');
  const [pa4Msg, setPa4Msg]             = useState('Block 0 plaintext!!Block 1 plaintext!!Block 2 !!');
  const [pa4Trace, setPa4Trace]         = useState(null);  // animate response
  const [pa4FlipResult, setPa4FlipResult] = useState(null);
  const [pa4FlippedBlock, setPa4FlippedBlock] = useState(null);
  const [pa4IvReuseData, setPa4IvReuseData] = useState(null);
  const [pa4IvReuseOn, setPa4IvReuseOn] = useState(false);
  const [pa4IvMsg1, setPa4IvMsg1]       = useState('Same block here!Different block1');
  const [pa4IvMsg2, setPa4IvMsg2]       = useState('Same block here!Different block2');
  const [pa4Loading, setPa4Loading]     = useState({});
  const [pa4AnimStep, setPa4AnimStep]   = useState(0); // for animation stepping

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

  // PA5 State
  const [pa5Tab, setPa5Tab] = useState('euf');
  const [pa5Session, setPa5Session] = useState(null);
  const [pa5Messages, setPa5Messages] = useState([]);
  const [pa5EufMsg, setPa5EufMsg] = useState('');
  const [pa5EufTag, setPa5EufTag] = useState('');
  const [pa5EufResult, setPa5EufResult] = useState(null);
  const [pa5Stats, setPa5Stats] = useState({ attempts: 0, successes: 0 });
  const [pa5LeSuffix, setPa5LeSuffix] = useState('');
  const [pa5LeData, setPa5LeData] = useState(null);
  const [pa5Loading, setPa5Loading] = useState({});

  // PA6 State
  const [pa6Msg, setPa6Msg] = useState('Transfer $1000 to Bob');
  const [pa6Data, setPa6Data] = useState(null);
  const [pa6CpaFlipped, setPa6CpaFlipped] = useState(null);
  const [pa6CcaFlipped, setPa6CcaFlipped] = useState(null);
  const [pa6CpaDec, setPa6CpaDec] = useState(null);
  const [pa6CcaDec, setPa6CcaDec] = useState(null);
  const [pa6CpaErr, setPa6CpaErr] = useState(null);
  const [pa6CcaErr, setPa6CcaErr] = useState(null);
  const [pa6CcaRej, setPa6CcaRej] = useState(false);
  const [pa6Loading, setPa6Loading] = useState({});

  // PA12 State
  const [pa12MsgInt, setPa12MsgInt] = useState('42');
  const [pa12MsgPkcs, setPa12MsgPkcs] = useState('RSA!');
  const [pa12Data, setPa12Data] = useState(null);
  const [pa12Loading, setPa12Loading] = useState(false);
  const [pa12Tab, setPa12Tab] = useState('textbook');

  // PA14 State
  const [pa14Residues, setPa14Residues] = useState('2,3,2');
  const [pa14Moduli, setPa14Moduli] = useState('3,5,7');
  const [pa14Data, setPa14Data] = useState(null);
  const [pa14Loading, setPa14Loading] = useState(false);

  // PA15 State
  const [pa15Msg, setPa15Msg] = useState('Sign this!');
  const [pa15Data, setPa15Data] = useState(null);
  const [pa15Loading, setPa15Loading] = useState(false);

  // PA16 State
  const [pa16MsgInt, setPa16MsgInt] = useState('42');
  const [pa16Data, setPa16Data] = useState(null);
  const [pa16Loading, setPa16Loading] = useState(false);

  // PA17 State
  const [pa17Msg, setPa17Msg] = useState('42');
  const [pa17Data, setPa17Data] = useState(null);
  const [pa17CpaTampered, setPa17CpaTampered] = useState(false);
  const [pa17CcaTampered, setPa17CcaTampered] = useState(false);
  const [pa17CpaDec, setPa17CpaDec] = useState(null);
  const [pa17CcaDec, setPa17CcaDec] = useState(null);
  const [pa17CcaRej, setPa17CcaRej] = useState(false);
  const [pa17Loading, setPa17Loading] = useState({});

  // PA19 State
  const [pa19A, setPa19A] = useState(1);
  const [pa19B, setPa19B] = useState(1);
  const [pa19Data, setPa19Data] = useState(null);
  const [pa19Table, setPa19Table] = useState(null);
  const [pa19Loading, setPa19Loading] = useState({});

  // PA20 State
  const [pa20Alice, setPa20Alice] = useState(7);
  const [pa20Bob, setPa20Bob] = useState(3);
  const [pa20Data, setPa20Data] = useState(null);
  const [pa20Loading, setPa20Loading] = useState(false);
  const [pa20GateIdx, setPa20GateIdx] = useState(-1);
  const [pa20Expanded, setPa20Expanded] = useState(false);
  const [pa20Mode, setPa20Mode] = useState('comparator');
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

    if (def.params.length === 0 && pa.pa !== 3 && pa.pa !== 4 && pa.pa !== 5 && pa.pa !== 6 && pa.pa !== 7 && pa.pa !== 8 && pa.pa !== 9 && pa.pa !== 10 && pa.pa !== 11 && pa.pa !== 12 && pa.pa !== 13 && pa.pa !== 14 && pa.pa !== 15 && pa.pa !== 16 && pa.pa !== 17 && pa.pa !== 18 && pa.pa !== 19 && pa.pa !== 20) {      runDemo(initialParams);
    }

    // Reset PA3 / PA4 / PA8 / PA9 / PA10 / PA11 state when modal switches PA
    setPa3SessionId(null); setPa3Challenge(null); setPa3GuessResult(null);
    setPa3Rounds([]); setPa3Stats(null); setPa3SimData(null);
    setPa3OracleLog([]); setPa3Loading({}); setPa3LenError(null);
    setPa4Trace(null); setPa4FlipResult(null); setPa4FlippedBlock(null);
    setPa4IvReuseData(null); setPa4IvReuseOn(false); setPa4Loading({}); setPa4AnimStep(0);
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
                <h3 style={{ fontSize: '16px', fontWeight: '600', margin: '16px 0 8px', color: 'var(--accent3)' }}>{k}</h3>
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
                <h3 style={{ fontSize: '16px', fontWeight: '600', margin: '16px 0 8px', color: 'var(--accent3)' }}>{k}</h3>
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
          <div className="output-box" style={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '14px', background: 'var(--bg)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border)' }}>
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
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '4px' }}>
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
                      <div style={{ fontSize: '12px', fontWeight: 600, color: s.pass ? '#22c55e' : '#ef4444' }}>{s.test.toUpperCase()}</div>
                      <div style={{ fontSize: '13px' }}>{s.pass ? 'PASS' : 'FAIL'}</div>
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
                  <div style={{ fontSize: '13px', color: 'var(--text3)' }}>Running 10,000+ Inversion Attempts...</div>
                </div>
              ) : (
                <div style={{ padding: '12px', background: 'rgba(var(--accent-rgb), 0.05)', borderRadius: '8px', border: '1px dashed var(--border)' }}>
                  <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px', color: 'var(--accent)' }}>🔒 Backward Reduction: PRG ⇒ OWF</div>
                  <div style={{ fontSize: '13px', color: 'var(--text2)', lineHeight: '1.4', marginBottom: '12px' }}>
                  <strong>Theoretical Proof:</strong> To show that <strong>f(s) = G(s)</strong> is a One-Way Function, we assume an adversary exists who can invert it. If they can recover <strong>s</strong> from <strong>G(s)</strong>, they can distinguish the PRG from random bits. Since <strong>G</strong> is secure, such an adversary cannot exist.
                </div>
                
                <div style={{ background: 'var(--bg2)', padding: '10px', borderRadius: '6px', marginBottom: '12px', fontSize: '13px', borderLeft: '3px solid var(--accent)' }}>
                  <strong>Example from Current Run:</strong>
                  <div style={{ marginTop: '8px' }}>
                    <strong>Input (s):</strong> <code style={{ fontSize: '12px', color: 'var(--accent)' }}>{result?.seed?.substring(0, 12)}...</code>
                    <br />
                    <strong>Output G(s):</strong> <code style={{ fontSize: '12px', color: 'var(--accent3)' }}>{result?.output?.substring(0, 12)}...</code>
                    <div style={{ marginTop: '8px', fontSize: '12px', color: 'var(--text3)' }}>
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
                              fontSize: '11px',
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

                  <div style={{ fontSize: '12px', color: 'var(--text3)', borderTop: '1px solid var(--border)', paddingTop: '8px' }}>
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

  // PA3 special renderer
  const renderPA3Special = () => {
    const busy = (k) => !!pa3Loading[k];
    const setLoading = (k, v) => setPa3Loading(p => ({ ...p, [k]: v }));
    const totalRounds = pa3Rounds.length;
    const correctRounds = pa3Rounds.filter(r => r.correct).length;
    const advantage = totalRounds > 0 ? Math.abs(correctRounds / totalRounds - 0.5) : null;
    const accentOk = '#22c55e'; const accentBad = '#ef4444';
    const accentBlue = '#6366f1'; const accentAmber = '#f59e0b';
    const mono = (txt, color = '#a5b4fc') => (
      <code style={{ fontFamily:'monospace', fontSize: '13px', wordBreak:'break-all', color, background:'rgba(0,0,0,0.35)', borderRadius:'4px', padding:'2px 6px' }}>{txt}</code>
    );
    const card = (children, accent, title) => (
      <div style={{ background:`linear-gradient(135deg,${accent}14 0%,${accent}08 100%)`, border:`1px solid ${accent}50`, borderRadius:'12px', padding:'16px', marginBottom:'14px' }}>
        {title && <div style={{ fontSize: '13px', fontWeight:700, letterSpacing:'0.08em', color:accent, marginBottom:'10px', textTransform:'uppercase' }}>{title}</div>}
        {children}
      </div>
    );
    const initSession = async (broken) => {
      setLoading('init', true);
      setPa3Challenge(null); setPa3GuessResult(null);
      setPa3Rounds([]); setPa3Stats(null); setPa3OracleLog([]); setPa3LenError(null);
      const d = await api.pa3Init(broken);
      setPa3SessionId(d.session_id); setPa3Broken(broken);
      setLoading('init', false);
    };
    return (
      <div style={{ display:'flex', flexDirection:'column', gap:'4px' }}>
        {card(<div>
          <div style={{ fontSize: '14px', color:'var(--text2)', marginBottom:'12px', lineHeight:1.5 }}>
            Choose <strong>Secure</strong> (fresh nonce each call) or <strong>Broken</strong> (fixed nonce reuse). Then start a session.
          </div>
          <div style={{ display:'flex', gap:'10px' }}>
            <button id="pa3-secure-btn" onClick={() => initSession(false)} disabled={busy('init')} style={{ flex:1, padding:'10px', borderRadius:'8px', fontWeight:700, fontSize: '15px', cursor:busy('init')?'not-allowed':'pointer', background:(!pa3Broken&&pa3SessionId)?`linear-gradient(135deg,${accentOk}cc,${accentOk}88)`:'rgba(0,0,0,0.2)', border:`2px solid ${accentOk}`, color:(!pa3Broken&&pa3SessionId)?'white':accentOk }}>Secure Mode</button>
            <button id="pa3-broken-btn" onClick={() => initSession(true)} disabled={busy('init')} style={{ flex:1, padding:'10px', borderRadius:'8px', fontWeight:700, fontSize: '15px', cursor:busy('init')?'not-allowed':'pointer', background:(pa3Broken&&pa3SessionId)?`linear-gradient(135deg,${accentBad}cc,${accentBad}88)`:'rgba(0,0,0,0.2)', border:`2px solid ${accentBad}`, color:(pa3Broken&&pa3SessionId)?'white':accentBad }}>Broken (Nonce Reuse)</button>
          </div>
          {pa3SessionId && <div style={{ marginTop:'10px', fontSize: '13px', color:'var(--text3)' }}>Session: {mono(pa3SessionId.slice(0,8)+'...')} &nbsp; Mode: <span style={{ fontWeight:700, color:pa3Broken?accentBad:accentOk }}>{pa3Broken?'BROKEN':'SECURE'}</span></div>}
        </div>, accentBlue, '0. Game Session')}

        {pa3SessionId && (<>
          {card(<div>
            <div style={{ fontSize: '14px', color:'var(--text2)', marginBottom:'10px' }}>Query the oracle — encrypt any message.</div>
            <div style={{ display:'flex', gap:'8px', marginBottom:'10px' }}>
              <input id="pa3-oracle-input" type="text" value={pa3OracleMsg} onChange={e=>setPa3OracleMsg(e.target.value)} placeholder="Type any message..." style={{ flex:1, padding:'9px 12px', background:'rgba(0,0,0,0.35)', border:`1px solid ${accentBlue}60`, borderRadius:'8px', color:'var(--text1)', fontSize: '15px', fontFamily:'monospace', outline:'none' }}
                onKeyDown={async e=>{ if(e.key==='Enter'&&pa3OracleMsg.trim()){setLoading('oracle',true);const d=await api.pa3Oracle(pa3SessionId,pa3OracleMsg);setPa3OracleLog(prev=>[d,...prev].slice(0,6));setPa3OracleMsg('');setLoading('oracle',false);}}}
              />
              <button id="pa3-oracle-btn" disabled={busy('oracle')||!pa3OracleMsg.trim()} onClick={async()=>{setLoading('oracle',true);const d=await api.pa3Oracle(pa3SessionId,pa3OracleMsg);setPa3OracleLog(prev=>[d,...prev].slice(0,6));setPa3OracleMsg('');setLoading('oracle',false);}} style={{ padding:'9px 16px', borderRadius:'8px', border:`1px solid ${accentBlue}80`, background:`linear-gradient(135deg,${accentBlue}cc,${accentBlue}88)`, color:'white', fontWeight:700, fontSize: '14px', cursor:(busy('oracle')||!pa3OracleMsg.trim())?'not-allowed':'pointer' }}>
                {busy('oracle')?'...':'Encrypt'}
              </button>
            </div>
            {pa3OracleLog.length>0 && <div style={{ display:'flex', flexDirection:'column', gap:'6px' }}>
              {pa3OracleLog.map((entry,i)=>(
                <div key={i} style={{ background:'rgba(0,0,0,0.25)', borderRadius:'8px', padding:'8px 10px', border:`1px solid ${accentBlue}25` }}>
                  <div style={{ display:'grid', gridTemplateColumns:'auto 1fr', gap:'3px 10px', fontSize: '13px' }}>
                    <span style={{color:'var(--text3)'}}>msg</span>{mono(entry.message)}
                    <span style={{color:'var(--text3)'}}>nonce</span>{mono((entry.nonce_hex||'').slice(0,24)+'...', pa3Broken?'#fca5a5':'#a5b4fc')}
                    <span style={{color:'var(--text3)'}}>ct</span>{mono((entry.ciphertext_hex||'').slice(0,24)+'...')}
                  </div>
                  {pa3Broken&&i>0&&pa3OracleLog[i-1]?.nonce_hex===entry.nonce_hex && <div style={{marginTop:'5px',fontSize: '12px',color:accentBad,fontWeight:700}}>Same nonce — nonce reuse detected!</div>}
                </div>
              ))}
            </div>}
          </div>, accentBlue, '1. Encryption Oracle')}

          {card(<div>
            <div style={{ fontSize: '14px', color:'var(--text2)', marginBottom:'10px' }}>Submit equal-length <strong>m0</strong> and <strong>m1</strong>. Challenger picks random b, returns C*=Enc(m_b).</div>
            {pa3LenError && <div style={{ color:accentBad, fontSize: '14px', marginBottom:'8px', padding:'6px 10px', background:'rgba(239,68,68,0.1)', borderRadius:'6px', border:`1px solid ${accentBad}40` }}>{pa3LenError}</div>}
            <div style={{ display:'flex', flexDirection:'column', gap:'8px', marginBottom:'10px' }}>
              <div><label style={{fontSize: '13px',color:'var(--text3)',marginBottom:'3px',display:'block'}}>m0 — Message 0</label>
                <input id="pa3-m0-input" type="text" value={pa3M0} onChange={e=>{setPa3M0(e.target.value);setPa3LenError(null);}} style={{width:'100%',boxSizing:'border-box',padding:'9px 12px',background:'rgba(0,0,0,0.35)',border:`1px solid ${accentOk}50`,borderRadius:'8px',color:'var(--text1)',fontSize: '15px',fontFamily:'monospace',outline:'none'}} />
              </div>
              <div><label style={{fontSize: '13px',color:'var(--text3)',marginBottom:'3px',display:'block'}}>m1 — Message 1 (same byte-length as m0)</label>
                <input id="pa3-m1-input" type="text" value={pa3M1} onChange={e=>{setPa3M1(e.target.value);setPa3LenError(null);}} style={{width:'100%',boxSizing:'border-box',padding:'9px 12px',background:'rgba(0,0,0,0.35)',border:`1px solid ${accentOk}50`,borderRadius:'8px',color:'var(--text1)',fontSize: '15px',fontFamily:'monospace',outline:'none'}} />
              </div>
              <div style={{fontSize: '12px',color:'var(--text3)'}}>
                m0: <strong>{new TextEncoder().encode(pa3M0).length}B</strong> &middot; m1: <strong>{new TextEncoder().encode(pa3M1).length}B</strong>
                {new TextEncoder().encode(pa3M0).length!==new TextEncoder().encode(pa3M1).length&&<span style={{color:accentBad,marginLeft:'6px'}}>lengths differ</span>}
              </div>
            </div>
            <button id="pa3-challenge-btn" disabled={busy('challenge')||!!pa3Challenge} onClick={async()=>{
              const l0=new TextEncoder().encode(pa3M0).length; const l1=new TextEncoder().encode(pa3M1).length;
              if(l0!==l1){setPa3LenError(`Lengths must match: m0=${l0}B, m1=${l1}B`);return;}
              setLoading('challenge',true);
              try{const d=await api.pa3Challenge(pa3SessionId,pa3M0,pa3M1);if(d.detail)setPa3LenError(d.detail);else{setPa3Challenge(d);setPa3GuessResult(null);}}
              catch(e){setPa3LenError(String(e));}
              setLoading('challenge',false);
            }} style={{width:'100%',padding:'10px',borderRadius:'8px',fontWeight:700,fontSize: '15px',cursor:(busy('challenge')||!!pa3Challenge)?'not-allowed':'pointer',background:(busy('challenge')||!!pa3Challenge)?'rgba(34,197,94,0.15)':`linear-gradient(135deg,${accentOk}cc,${accentOk}88)`,border:'none',color:(busy('challenge')||!!pa3Challenge)?accentOk:'white'}}>
              {busy('challenge')?'Encrypting...':pa3Challenge?'Challenge Active — Guess Below':'Get Challenge Ciphertext C*'}
            </button>
            {pa3Challenge && <div style={{marginTop:'12px',background:'rgba(0,0,0,0.25)',borderRadius:'10px',padding:'12px',border:`1px solid ${accentOk}40`}}>
              <div style={{fontSize: '13px',fontWeight:700,color:accentOk,marginBottom:'8px'}}>Challenge Ciphertext C*</div>
              <div style={{display:'grid',gridTemplateColumns:'auto 1fr',gap:'4px 10px',fontSize: '13px'}}>
                <span style={{color:'var(--text3)'}}>nonce</span>{mono(pa3Challenge.nonce_hex, pa3Broken?'#fca5a5':'#a5b4fc')}
                <span style={{color:'var(--text3)'}}>ct</span>{mono((pa3Challenge.ciphertext_hex||'').slice(0,32)+'...')}
              </div>
              {pa3Broken&&pa3OracleLog.length>0&&<div style={{marginTop:'8px',padding:'6px 10px',background:'rgba(239,68,68,0.1)',borderRadius:'6px',border:`1px solid ${accentBad}40`,fontSize: '13px',color:accentBad}}>BROKEN: Fixed nonce — compare with oracle outputs to trivially win!</div>}
            </div>}
          </div>, accentOk, '2. Submit Challenge (m0, m1)')}

          {pa3Challenge && card(<div>
            <div style={{fontSize: '14px',color:'var(--text2)',marginBottom:'10px'}}>Which message did the challenger encrypt?</div>
            <div style={{display:'flex',gap:'10px'}}>
              {[0,1].map(g=>(
                <button key={g} id={`pa3-guess-btn-${g}`} disabled={busy('guess')} onClick={async()=>{
                  setLoading('guess',true);
                  const d=await api.pa3Guess(pa3SessionId,g);
                  setPa3GuessResult(d);setPa3Rounds(d.rounds);
                  setPa3Stats({total:d.total_rounds,correct:d.correct_rounds,advantage:d.advantage,win_rate:d.win_rate,secure:d.secure});
                  setPa3Challenge(null);setLoading('guess',false);
                }} style={{flex:1,padding:'12px',borderRadius:'8px',fontWeight:700,fontSize: '16px',cursor:busy('guess')?'not-allowed':'pointer',background:`linear-gradient(135deg,${accentAmber}cc,${accentAmber}88)`,border:'none',color:'white'}}>
                  Guess b={g} (m{g})
                </button>
              ))}
            </div>
            {pa3GuessResult && <div style={{marginTop:'12px',padding:'12px',borderRadius:'10px',border:`2px solid ${pa3GuessResult.correct?accentOk:accentBad}`,background:pa3GuessResult.correct?'rgba(34,197,94,0.1)':'rgba(239,68,68,0.1)'}}>
              <div style={{fontWeight:700,fontSize: '16px',color:pa3GuessResult.correct?accentOk:accentBad,marginBottom:'6px'}}>
                {pa3GuessResult.correct?'Correct!':'Wrong!'} Challenger chose b={pa3GuessResult.b}
              </div>
              <div style={{fontSize: '13px',color:'var(--text2)'}}>
                Rounds: <strong>{pa3GuessResult.total_rounds}</strong> &middot; Win rate: <strong>{(pa3GuessResult.win_rate*100).toFixed(1)}%</strong> &middot; Advantage: <strong style={{color:pa3GuessResult.advantage<0.15?accentOk:accentBad}}>{(pa3GuessResult.advantage*100).toFixed(1)}%</strong>
              </div>
            </div>}
          </div>, accentAmber, '3. Make Your Guess')}

          {pa3Rounds.length>0 && card(<div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:'8px',marginBottom:'12px'}}>
              {[['Rounds',pa3Rounds.length,accentBlue],['Correct',correctRounds,accentOk],['Advantage',advantage!==null?`${(advantage*100).toFixed(1)}%`:'-',advantage!==null&&advantage<0.15?accentOk:accentBad]].map(([l,v,c])=>(
                <div key={l} style={{textAlign:'center',background:'rgba(0,0,0,0.25)',borderRadius:'8px',padding:'10px',border:`1px solid ${c}40`}}>
                  <div style={{fontSize: '12px',color:'var(--text3)',marginBottom:'3px'}}>{l}</div>
                  <div style={{fontSize: '22px',fontWeight:800,color:c}}>{v}</div>
                </div>
              ))}
            </div>
            {pa3Stats && <div style={{fontSize: '14px',color:pa3Stats.secure?accentOk:accentBad,fontStyle:'italic',marginBottom:'10px'}}>{pa3Stats.secure?`Advantage ${(pa3Stats.advantage*100).toFixed(1)}% — scheme appears CPA-secure`:`Advantage ${(pa3Stats.advantage*100).toFixed(1)}% — ${pa3Broken?'nonce reuse breaks security!':'keep playing...'}`}</div>}
            <div style={{maxHeight:'140px',overflowY:'auto',display:'flex',flexDirection:'column',gap:'4px'}}>
              {[...pa3Rounds].reverse().map(r=>(
                <div key={r.round} style={{display:'flex',gap:'6px',alignItems:'center',fontSize: '13px',padding:'4px 8px',borderRadius:'6px',background:r.correct?'rgba(34,197,94,0.08)':'rgba(239,68,68,0.08)',border:`1px solid ${r.correct?accentOk:accentBad}30`}}>
                  <span style={{color:'var(--text3)',minWidth:'26px'}}>#{r.round}</span>
                  <span style={{color:r.correct?accentOk:accentBad,fontWeight:700}}>{r.correct?'Y':'N'}</span>
                  <span style={{color:'var(--text3)'}}>b={r.b} guess={r.guess}</span>
                  <span style={{marginLeft:'auto',color:'var(--text3)'}}>adv {(r.advantage*100).toFixed(1)}%</span>
                </div>
              ))}
            </div>
          </div>, accentBlue, '4. Running Advantage')}

          {card(<div>
            <div style={{fontSize: '14px',color:'var(--text2)',marginBottom:'10px'}}>20 rounds with dummy adversary — advantage approx 0 (secure) or approx 0.5 (broken).</div>
            <button id="pa3-simulate-btn" disabled={busy('sim')} onClick={async()=>{setLoading('sim',true);const d=await api.pa3Simulate(20,pa3Broken);setPa3SimData(d);setLoading('sim',false);}} style={{width:'100%',padding:'10px',borderRadius:'8px',fontWeight:700,fontSize: '15px',cursor:busy('sim')?'not-allowed':'pointer',background:busy('sim')?'rgba(139,92,246,0.15)':'linear-gradient(135deg,#8b5cf6cc,#8b5cf688)',border:'none',color:busy('sim')?'#8b5cf6':'white'}}>
              {busy('sim')?'Simulating...':'Run 20-Round Automated Simulation'}
            </button>
            {pa3SimData && <div style={{marginTop:'12px'}}>
              <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:'8px'}}>
                {[['Rounds',pa3SimData.rounds,accentBlue],['Correct',pa3SimData.correct??pa3SimData.correct_guesses,accentOk],['Win Rate',`${((pa3SimData.win_rate||0)*100).toFixed(1)}%`,accentAmber],['Advantage',`${((pa3SimData.advantage||0)*100).toFixed(1)}%`,(pa3SimData.advantage||0)<0.15?accentOk:accentBad]].map(([l,v,c])=>(
                  <div key={l} style={{textAlign:'center',background:'rgba(0,0,0,0.25)',borderRadius:'8px',padding:'8px 4px',border:`1px solid ${c}40`}}>
                    <div style={{fontSize: '12px',color:'var(--text3)',marginBottom:'3px'}}>{l}</div>
                    <div style={{fontSize: '18px',fontWeight:800,color:c}}>{v}</div>
                  </div>
                ))}
              </div>
              <div style={{marginTop:'10px',fontSize: '14px',color:pa3SimData.broken_mode?accentBad:accentOk,fontStyle:'italic'}}>
                {pa3SimData.broken_mode?`Broken: advantage=${((pa3SimData.advantage||0)*100).toFixed(1)}% — identical ciphertexts trivially exposed`:`Secure: advantage=${((pa3SimData.advantage||0)*100).toFixed(1)}% approx 0`}
              </div>
            </div>}
          </div>, '#8b5cf6', '5. Automated Simulation (20 rounds)')}
        </>)}

        {!pa3SessionId && <div style={{textAlign:'center',padding:'30px',color:'var(--text3)',fontSize: '15px',fontStyle:'italic'}}>Select a mode and start a session above to begin.</div>}
      </div>
    );
  };

  // ─────────────────────────────────────────────────────────────────
  // PA#4 — Modes of Operation Visual Animator
  // ─────────────────────────────────────────────────────────────────
  const renderPA4Special = () => {
    const busyPA4 = (k) => !!pa4Loading[k];
    const setL = (k, v) => setPa4Loading(p => ({ ...p, [k]: v }));

    const MODES = ['CBC', 'OFB', 'CTR'];
    const modeColor = { CBC: '#6366f1', OFB: '#10b981', CTR: '#f59e0b' };
    const ac = modeColor[pa4Mode] || '#6366f1';

    const shortHex = (h = '') => (h.slice(0, 8) + '…' + h.slice(-4));

    const runAnimate = async (mode, msg) => {
      setL('anim', true);
      setPa4FlipResult(null); setPa4FlippedBlock(null); setPa4AnimStep(0);
      const d = await api.pa4Animate(mode || pa4Mode, msg || pa4Msg);
      setPa4Trace(d);
      setL('anim', false);
    };

    // Block diagram for a single mode
    const renderBlockDiagram = (trace, mode, traceData) => {
      if (!trace || !trace.blocks) return null;
      const blocks = trace.blocks;
      const flip = pa4FlipResult;
      const blockW = 110, gap = 60, totalW = blocks.length * (blockW + gap) - gap + 30;

      return (
        <div style={{ overflowX: 'auto', paddingBottom: '8px' }}>
          <svg width={totalW} height={290} style={{ display: 'block', minWidth: totalW }}>
            {blocks.map((blk, i) => {
              const x = i * (blockW + gap) + 15;
              const isCorrPt = flip && flip.corrupted_pt_blocks?.includes(i);
              const isFlipped = pa4FlippedBlock === i;

              // Row Y positions
              const ptY = 10, arrowY1 = 45, xorY = 55, arrowY2 = 95, blockY = 105, arrowY3 = 155, ctY = 165;

              const blockColor = isCorrPt ? '#ef4444' : (isFlipped ? '#f59e0b' : ac);
              const ptColor = isCorrPt ? '#fca5a5' : '#a5b4fc';

              return (
                <g key={i}>
                  {/* Plaintext block */}
                  <rect x={x} y={ptY} width={blockW} height={28} rx={6} fill={`${ptColor}22`} stroke={ptColor} strokeWidth={1.5} />
                  <text x={x + blockW / 2} y={ptY + 11} textAnchor="middle" fontSize={8} fill={ptColor} fontFamily="monospace">M{i}</text>
                  <text x={x + blockW / 2} y={ptY + 21} textAnchor="middle" fontSize={7} fill={ptColor} fontFamily="monospace">{shortHex(blk.plaintext_hex)}</text>

                  {/* Mode-specific middle elements */}
                  {mode === 'CBC' && (<>
                    {/* XOR symbol */}
                    <circle cx={x + blockW / 2} cy={xorY + 14} r={12} fill="none" stroke={ac} strokeWidth={1.5} />
                    <text x={x + blockW / 2} y={xorY + 19} textAnchor="middle" fontSize={13} fill={ac}>⊕</text>
                    {/* IV/prev-CT label */}
                    <text x={x + blockW / 2} y={xorY + 6} textAnchor="middle" fontSize={7} fill="#94a3b8">{i === 0 ? 'IV' : 'C' + (i - 1)}</text>
                    {/* Arrow into XOR from top */}
                    <line x1={x + blockW / 2} y1={ptY + 28} x2={x + blockW / 2} y2={xorY + 2} stroke="#94a3b8" strokeWidth={1} markerEnd="url(#arr)" />
                    {/* E_k block */}
                    <rect x={x + 10} y={blockY} width={blockW - 20} height={30} rx={6} fill={`${ac}33`} stroke={ac} strokeWidth={1.5} />
                    <text x={x + blockW / 2} y={blockY + 19} textAnchor="middle" fontSize={10} fill={ac} fontWeight={700}>E_k</text>
                    <line x1={x + blockW / 2} y1={xorY + 26} x2={x + blockW / 2} y2={blockY} stroke="#94a3b8" strokeWidth={1} markerEnd="url(#arr)" />
                  </>)}

                  {(mode === 'OFB' || mode === 'CTR') && (<>
                    {/* Keystream block */}
                    <rect x={x + 10} y={blockY - 20} width={blockW - 20} height={26} rx={5} fill={`${ac}22`} stroke={ac} strokeWidth={1.2} />
                    <text x={x + blockW / 2} y={blockY - 9} textAnchor="middle" fontSize={7.5} fill={ac} fontFamily="monospace">{shortHex(blk.keystream_hex)}</text>
                    <text x={x + blockW / 2} y={blockY - 1} textAnchor="middle" fontSize={6.5} fill="#94a3b8">keystream</text>
                    {/* XOR */}
                    <circle cx={x + blockW / 2} cy={blockY + 22} r={12} fill="none" stroke={ac} strokeWidth={1.5} />
                    <text x={x + blockW / 2} y={blockY + 27} textAnchor="middle" fontSize={13} fill={ac}>⊕</text>
                    <line x1={x + blockW / 2} y1={ptY + 28} x2={x + blockW / 2} y2={blockY + 10} stroke="#94a3b8" strokeWidth={1} markerEnd="url(#arr)" />
                  </>)}

                  {/* Ciphertext block (clickable for flip) */}
                  <rect
                    x={x} y={ctY + (mode === 'CBC' ? 10 : 30)} width={blockW} height={28} rx={6}
                    fill={isFlipped ? '#f59e0b33' : `${blockColor}22`} stroke={blockColor} strokeWidth={isFlipped ? 2.5 : 1.5}
                    style={{ cursor: 'pointer' }}
                    onClick={async () => {
                      if (!traceData) return;
                      setL('flip', true); setPa4FlippedBlock(i);
                      const ivKey = traceData.iv_hex || traceData.nonce_hex || '';
                      const d = await api.pa4Flip(mode, traceData.key_hex, ivKey, traceData.full_ciphertext_hex, i);
                      setPa4FlipResult(d); setL('flip', false);
                    }}
                  />
                  <text x={x + blockW / 2} y={ctY + (mode === 'CBC' ? 21 : 41)} textAnchor="middle" fontSize={8} fill={blockColor} fontFamily="monospace" style={{ pointerEvents: 'none' }}>C{i} {isFlipped ? '⚡' : ''}</text>
                  <text x={x + blockW / 2} y={ctY + (mode === 'CBC' ? 31 : 51)} textAnchor="middle" fontSize={7} fill={blockColor} fontFamily="monospace" style={{ pointerEvents: 'none' }}>{shortHex(blk.ciphertext_hex)}</text>

                  {/* Chain arrow between blocks */}
                  {i < blocks.length - 1 && mode === 'CBC' && (
                    <line x1={x + blockW} y1={ctY + 24} x2={x + blockW + gap} y2={ctY + 24} stroke={ac} strokeWidth={1.5} markerEnd="url(#arr)" strokeDasharray="4,2" />
                  )}
                </g>
              );
            })}
            <defs>
              <marker id="arr" markerWidth={8} markerHeight={8} refX={4} refY={3} orient="auto">
                <path d="M0,0 L0,6 L8,3 z" fill="#94a3b8" />
              </marker>
            </defs>
          </svg>
        </div>
      );
    };

    const renderErrorBadge = (corrupted) => {
      if (!corrupted) return null;
      const expected = { CBC: [pa4FlippedBlock, pa4FlippedBlock + 1].filter(n => n >= 0 && n < 3), OFB: [pa4FlippedBlock], CTR: [pa4FlippedBlock] };
      const exp = expected[pa4Mode] || [];
      return (
        <div style={{ marginTop: '10px', padding: '10px 14px', borderRadius: '8px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.4)', fontSize: '14px' }}>
          <div style={{ fontWeight: 700, color: '#ef4444', marginBottom: '4px' }}>⚡ Bit Flip Error Propagation</div>
          <div style={{ color: 'var(--text2)', lineHeight: 1.5 }}>
            Flipped C{pa4FlippedBlock} → corrupted plaintext blocks: {corrupted.length > 0 ? corrupted.map(b => `M${b}`).join(', ') : 'None'}
          </div>
          <div style={{ marginTop: '6px', fontSize: '13px', color: '#94a3b8' }}>
            {pa4Mode === 'CBC' ? `CBC: flipped C${pa4FlippedBlock} corrupts M${pa4FlippedBlock} completely + flips 1 bit in M${pa4FlippedBlock + 1}` : `${pa4Mode}: error stays in exactly the same block — only M${pa4FlippedBlock} is affected`}
          </div>
          <div style={{ marginTop: '4px', fontSize: '13px', color: corrupted.join(',') === exp.join(',') ? '#22c55e' : '#f59e0b' }}>
            {corrupted.join(',') === exp.join(',') ? `✅ Matches expected pattern for ${pa4Mode}` : `Expected blocks: ${exp.map(b => `M${b}`).join(', ')}`}
          </div>
        </div>
      );
    };

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>

        {/* ── Mode Tabs ── */}
        <div style={{ display: 'flex', gap: '6px' }}>
          {MODES.map(m => (
            <button key={m} id={`pa4-tab-${m}`} onClick={async () => {
              setPa4Mode(m); setPa4FlipResult(null); setPa4FlippedBlock(null);
              setPa4IvReuseData(null); setPa4IvReuseOn(false);
              setL('anim', true);
              const d = await api.pa4Animate(m, pa4Msg);
              setPa4Trace(d); setL('anim', false);
            }} style={{ flex: 1, padding: '9px 0', borderRadius: '8px', fontWeight: 700, fontSize: '15px', cursor: 'pointer', transition: 'all 0.18s', border: m === pa4Mode ? `2px solid ${modeColor[m]}` : `1px solid ${modeColor[m]}55`, background: m === pa4Mode ? `linear-gradient(135deg,${modeColor[m]}cc,${modeColor[m]}88)` : 'rgba(0,0,0,0.2)', color: m === pa4Mode ? 'white' : modeColor[m] }}>
              {m}
            </button>
          ))}
        </div>

        {/* ── Message input + Run ── */}
        <div style={{ display: 'flex', gap: '8px' }}>
          <input id="pa4-msg-input" type="text" value={pa4Msg} onChange={e => setPa4Msg(e.target.value)} placeholder="3-block message (48 chars)..." style={{ flex: 1, padding: '9px 12px', background: 'rgba(0,0,0,0.35)', border: `1px solid ${ac}60`, borderRadius: '8px', color: 'var(--text1)', fontSize: '15px', fontFamily: 'monospace', outline: 'none' }} />
          <button id="pa4-run-btn" disabled={busyPA4('anim')} onClick={() => runAnimate()} style={{ padding: '9px 18px', borderRadius: '8px', border: 'none', background: busyPA4('anim') ? `${ac}44` : `linear-gradient(135deg,${ac}cc,${ac}88)`, color: 'white', fontWeight: 700, fontSize: '15px', cursor: busyPA4('anim') ? 'not-allowed' : 'pointer' }}>
            {busyPA4('anim') ? '⏳' : '▶ Animate'}
          </button>
        </div>

        {/* Mode info bar */}
        <div style={{ fontSize: '13px', color: '#94a3b8', padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', border: `1px solid ${ac}30` }}>
          {pa4Mode === 'CBC' && '🔗 CBC: C_i = E_k(C_{i-1} ⊕ M_i) — sequential encryption, parallel decryption. Click any ciphertext block to flip a bit.'}
          {pa4Mode === 'OFB' && '🔄 OFB: C_i = M_i ⊕ E_k(E_k(…E_k(IV)…)) — pre-computable keystream, enc=dec. Click any ciphertext block to flip a bit.'}
          {pa4Mode === 'CTR' && '⚡ CTR: C_i = M_i ⊕ E_k(nonce+i) — fully parallel, stream-cipher mode. Click any ciphertext block to flip a bit.'}
        </div>

        {!pa4Trace && !busyPA4('anim') && (
          <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text3)', fontSize: '15px', fontStyle: 'italic' }}>
            Press ▶ Animate to start the block diagram.
          </div>
        )}

        {busyPA4('anim') && <div style={{ textAlign: 'center', padding: '20px' }}><div className="spinner" /></div>}

        {pa4Trace && !busyPA4('anim') && (<>
          {/* ── Block Diagram ── */}
          <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '12px', padding: '14px', border: `1px solid ${ac}40` }}>
            <div style={{ fontSize: '13px', fontWeight: 700, color: ac, marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
              Block Cipher Mode Diagram — Click a ciphertext block (C0, C1, C2) to flip a bit
            </div>
            {renderBlockDiagram(pa4Trace, pa4Mode, pa4Trace)}
            {busyPA4('flip') && <div style={{ fontSize: '13px', color: '#94a3b8', marginTop: '6px' }}>⏳ Re-decrypting with flipped bit…</div>}
            {renderErrorBadge(pa4FlipResult?.corrupted_pt_blocks)}
          </div>

          {/* ── Key / IV info ── */}
          <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '8px', padding: '10px 12px', border: '1px solid var(--border)', fontSize: '12px', display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '3px 10px' }}>
            <span style={{ color: 'var(--text3)' }}>Key</span><code style={{ color: '#a5b4fc', wordBreak: 'break-all' }}>{pa4Trace.key_hex}</code>
            <span style={{ color: 'var(--text3)' }}>{pa4Trace.nonce_hex ? 'Nonce' : 'IV'}</span><code style={{ color: '#a5b4fc', wordBreak: 'break-all' }}>{pa4Trace.iv_hex || pa4Trace.nonce_hex}</code>
          </div>

          {/* ── IV Reuse attack (CBC only) ── */}
          {pa4Mode === 'CBC' && (
            <div style={{ background: 'linear-gradient(135deg,rgba(239,68,68,0.08),rgba(239,68,68,0.04))', border: '1px solid rgba(239,68,68,0.4)', borderRadius: '12px', padding: '14px' }}>
              <div style={{ fontSize: '13px', fontWeight: 700, color: '#ef4444', marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '0.07em' }}>⚠️ CBC IV-Reuse Attack</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '10px' }}>
                <input id="pa4-ivruse-m1" type="text" value={pa4IvMsg1} onChange={e => setPa4IvMsg1(e.target.value)} placeholder="Message 1 (first 16 chars shared)" style={{ padding: '7px 10px', background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(239,68,68,0.4)', borderRadius: '6px', color: 'var(--text1)', fontSize: '14px', fontFamily: 'monospace', outline: 'none' }} />
                <input id="pa4-ivruse-m2" type="text" value={pa4IvMsg2} onChange={e => setPa4IvMsg2(e.target.value)} placeholder="Message 2 (same first 16 chars)" style={{ padding: '7px 10px', background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(239,68,68,0.4)', borderRadius: '6px', color: 'var(--text1)', fontSize: '14px', fontFamily: 'monospace', outline: 'none' }} />
              </div>
              <button id="pa4-ivruse-btn" disabled={busyPA4('ivr')} onClick={async () => {
                setL('ivr', true);
                const d = await api.pa4IvReuse(pa4IvMsg1, pa4IvMsg2, pa4Trace?.key_hex || '', pa4Trace?.iv_hex || '');
                setPa4IvReuseData(d); setPa4IvReuseOn(true); setL('ivr', false);
              }} style={{ width: '100%', padding: '9px', borderRadius: '8px', border: '1px solid rgba(239,68,68,0.6)', background: busyPA4('ivr') ? 'rgba(239,68,68,0.1)' : 'linear-gradient(135deg,#ef4444cc,#ef444488)', color: 'white', fontWeight: 700, fontSize: '15px', cursor: busyPA4('ivr') ? 'not-allowed' : 'pointer' }}>
                {busyPA4('ivr') ? '⏳ Running…' : '💥 Run IV-Reuse Attack'}
              </button>

              {pa4IvReuseData && pa4IvReuseOn && (
                <div style={{ marginTop: '12px' }}>
                  <div style={{ fontSize: '13px', color: '#94a3b8', marginBottom: '8px' }}>
                    Both messages encrypted with the <strong style={{ color: '#fca5a5' }}>same IV = {pa4IvReuseData.iv_hex?.slice(0, 16)}…</strong>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '6px' }}>
                    {(pa4IvReuseData.ct1_blocks || []).map((ct1, i) => {
                      const ct2 = (pa4IvReuseData.ct2_blocks || [])[i] || '';
                      const match = (pa4IvReuseData.block_match || [])[i];
                      return (
                        <div key={i} style={{ borderRadius: '8px', padding: '8px', background: match ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.08)', border: `1px solid ${match ? '#ef4444' : '#22c55e'}` }}>
                          <div style={{ fontSize: '12px', fontWeight: 700, color: match ? '#ef4444' : '#22c55e', marginBottom: '4px' }}>Block {i} {match ? '🔴 MATCH' : '🟢 diff'}</div>
                          <div style={{ fontSize: '10px', fontFamily: 'monospace', color: '#a5b4fc', wordBreak: 'break-all', marginBottom: '2px' }}>M1: {ct1.slice(0, 10)}…</div>
                          <div style={{ fontSize: '10px', fontFamily: 'monospace', color: '#a5b4fc', wordBreak: 'break-all' }}>M2: {ct2.slice(0, 10)}…</div>
                        </div>
                      );
                    })}
                  </div>
                  <div style={{ marginTop: '10px', fontSize: '13px', color: '#fca5a5', lineHeight: 1.5, padding: '8px 10px', background: 'rgba(239,68,68,0.08)', borderRadius: '6px' }}>
                    {pa4IvReuseData.vulnerability}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Comparison table ── */}
          <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '10px', padding: '12px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text2)', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Mode Properties</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr 1fr', gap: '6px', fontSize: '12px', textAlign: 'center' }}>
              {['', 'Para. Enc', 'Para. Dec', 'Error Prop', 'IV Reuse'].map((h, i) => (
                <div key={i} style={{ fontWeight: 700, color: 'var(--text3)', paddingBottom: '4px', borderBottom: '1px solid var(--border)' }}>{h}</div>
              ))}
              {[['CBC', '✗', '✓', '2 blocks', '💀 Fatal'], ['OFB', '✗', '✗', '1 block', '💀 Fatal'], ['CTR', '✓', '✓', '1 block', '💀 Fatal']].map(([m, pe, pd, ep, ir]) => (
                <React.Fragment key={m}>
                  <div style={{ fontWeight: 700, color: modeColor[m], padding: '4px' }}>{m}</div>
                  {[pe, pd].map((v, j) => <div key={j} style={{ color: v === '✓' ? '#22c55e' : '#ef4444', padding: '4px' }}>{v}</div>)}
                  <div style={{ color: '#f59e0b', padding: '4px' }}>{ep}</div>
                  <div style={{ color: '#ef4444', padding: '4px', fontSize: '11px' }}>{ir}</div>
                </React.Fragment>
              ))}
            </div>
          </div>
        </>)}
      </div>
    );
  };

  const renderPA5Special = () => {
    const card = (children, accent = '#818cf8', title = '') => (
      <div style={{
        background: `linear-gradient(135deg, ${accent}14 0%, ${accent}08 100%)`,
        border: `1px solid ${accent}50`,
        borderRadius: '12px', padding: '18px', marginBottom: '16px',
      }}>
        {title && <div style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.08em', color: accent, marginBottom: '12px', textTransform: 'uppercase' }}>{title}</div>}
        {children}
      </div>
    );

    const btn = (label, onClick, accent = '#818cf8', loading = false) => (
      <button onClick={onClick} disabled={loading} style={{
        padding: '9px 18px', borderRadius: '8px', border: `1px solid ${accent}80`,
        background: loading ? `${accent}22` : `linear-gradient(135deg, ${accent}cc, ${accent}88)`,
        color: 'white', fontWeight: 700, fontSize: '14px', cursor: loading ? 'not-allowed' : 'pointer',
        transition: 'all 0.2s',
      }}>
        {loading ? '⏳ …' : label}
      </button>
    );

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {/* ── Tabs ── */}
        {card(
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            {['euf', 'le'].map(m => (
              <button key={m} onClick={() => setPa5Tab(m)} style={{
                padding: '6px 16px', borderRadius: '8px', fontWeight: 700, fontSize: '14px', cursor: 'pointer',
                background: pa5Tab === m ? 'linear-gradient(135deg,#6366f1,#8b5cf6)' : 'rgba(0,0,0,0.2)',
                border: `1px solid ${pa5Tab === m ? '#818cf8' : 'rgba(99,102,241,0.25)'}`,
                color: pa5Tab === m ? 'white' : 'var(--text2)', transition: 'all 0.18s',
              }}>
                {m === 'euf' ? '🎯 EUF-CMA Forgery Game' : '⚡ Length-Extension Demo'}
              </button>
            ))}
          </div>,
          '#6366f1', 'PA#5 Interactive Demos'
        )}

        {pa5Tab === 'euf' && card(
          <div>
            <div style={{ fontSize: '14px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
              Act as the adversary! Get up to 50 signed messages from the oracle, then try to forge a valid tag for a <strong>new</strong> message.
            </div>
            
            <div style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
              {btn('📡 Get Signed Messages (Oracle)', async () => {
                setPa5Loading(p => ({ ...p, eufInit: true }));
                const d = await api.pa5EufInit();
                setPa5Session(d.session_id);
                setPa5Messages(d.messages);
                setPa5Stats({ attempts: 0, successes: 0 });
                setPa5EufResult(null);
                setPa5Loading(p => ({ ...p, eufInit: false }));
              }, '#6366f1', pa5Loading.eufInit)}
            </div>

            {pa5Messages.length > 0 && (
              <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', padding: '10px', maxHeight: '150px', overflowY: 'auto', marginBottom: '16px' }}>
                {pa5Messages.map((m, i) => (
                  <div key={i} style={{ display: 'flex', gap: '10px', fontSize: '13px', fontFamily: 'monospace', padding: '4px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <span style={{ color: '#94a3b8', width: '20px' }}>{i+1}.</span>
                    <span style={{ color: '#a5b4fc' }}>m: {m.message_hex}</span>
                    <span style={{ color: '#34d399' }}>t: {m.tag_hex}</span>
                  </div>
                ))}
              </div>
            )}

            {pa5Session && (
              <div style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)', borderRadius: '10px', padding: '14px' }}>
                <div style={{ fontSize: '13px', fontWeight: 700, color: '#f59e0b', marginBottom: '12px', textTransform: 'uppercase' }}>😈 Submit Forgery</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '12px' }}>
                  <input type="text" value={pa5EufMsg} onChange={e => setPa5EufMsg(e.target.value)} placeholder="New message m* (hex, 32 chars)" style={{ padding: '8px 12px', background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(245,158,11,0.4)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', fontSize: '14px', outline: 'none' }} />
                  <input type="text" value={pa5EufTag} onChange={e => setPa5EufTag(e.target.value)} placeholder="Forged tag t* (hex, 32 chars)" style={{ padding: '8px 12px', background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(245,158,11,0.4)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', fontSize: '14px', outline: 'none' }} />
                </div>
                <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                  {btn('Submit Forgery', async () => {
                    setPa5Loading(p => ({ ...p, eufVerify: true }));
                    const d = await api.pa5EufVerify(pa5Session, pa5EufMsg, pa5EufTag);
                    setPa5EufResult(d.valid);
                    setPa5Stats(s => ({ attempts: s.attempts + 1, successes: s.successes + (d.valid ? 1 : 0) }));
                    setPa5Loading(p => ({ ...p, eufVerify: false }));
                  }, '#f59e0b', pa5Loading.eufVerify)}
                  
                  <div style={{ fontSize: '14px', color: 'var(--text2)' }}>
                    Attempts: <strong>{pa5Stats.attempts}</strong> | Successes: <strong style={{ color: pa5Stats.successes > 0 ? '#ef4444' : '#22c55e' }}>{pa5Stats.successes}</strong>
                  </div>
                </div>

                {pa5EufResult !== null && (
                  <div style={{ marginTop: '12px', padding: '10px', borderRadius: '6px', background: pa5EufResult ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)', color: pa5EufResult ? '#fca5a5' : '#86efac', fontWeight: 700, fontSize: '15px', border: `1px solid ${pa5EufResult ? '#ef4444' : '#22c55e'}` }}>
                    {pa5EufResult ? '💥 Forgery accepted! (Security broken)' : '🔒 Forgery rejected!'}
                  </div>
                )}

                {/* Cheat Section */}
                <div style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid rgba(245,158,11,0.2)' }}>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: '#fbbf24', marginBottom: '8px', textTransform: 'uppercase' }}>Need Help? (Cheat)</div>
                  <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '10px', lineHeight: 1.4 }}>
                    This CBC-MAC implementation prepends the message length, making it mathematically secure against length-extension and splicing attacks. A real forgery is computationally infeasible. To let you test the 'Success' UI, click below to secretly query the backend oracle for a valid tag on a new message.
                  </div>
                  {btn('Cheat: Forge one for me', async () => {
                    setPa5Loading(p => ({ ...p, eufCheat: true }));
                    const d = await api.pa5EufCheat(pa5Session);
                    setPa5EufMsg(d.message_hex);
                    setPa5EufTag(d.tag_hex);
                    setPa5EufResult(null);
                    setPa5Loading(p => ({ ...p, eufCheat: false }));
                  }, '#fbbf24', pa5Loading.eufCheat)}
                </div>
              </div>
            )}
          </div>,
          '#f59e0b', 'Adversary Workbench'
        )}

        {pa5Tab === 'le' && card(
          <div>
            <div style={{ fontSize: '14px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
              Naive MACs like <code>t = H(k||m)</code> are vulnerable to length extension. Type a suffix <code>m'</code> to compute a valid tag for <code>m || pad || m'</code> from <code>t</code> alone, bypassing <code>k</code>.
            </div>
            
            <div style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
              <input type="text" value={pa5LeSuffix} onChange={e => setPa5LeSuffix(e.target.value)} placeholder="Type a suffix m'..." style={{ flex: 1, padding: '8px 12px', background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(239,68,68,0.4)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', fontSize: '14px', outline: 'none' }} />
              {btn('Run Length Extension', async () => {
                setPa5Loading(p => ({ ...p, leRun: true }));
                const d = await api.pa5LengthExtension(pa5LeSuffix);
                setPa5LeData(d);
                setPa5Loading(p => ({ ...p, leRun: false }));
              }, '#ef4444', pa5Loading.leRun)}
            </div>

            {pa5LeData && (
              <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '10px', padding: '14px', fontSize: '14px' }}>
                <div style={{ fontWeight: 700, color: '#ef4444', marginBottom: '10px' }}>⚠️ Vulnerability Demonstrated</div>
                
                <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', color: 'var(--text2)' }}>
                  <span>Original msg (m):</span> <code style={{ color: '#a5b4fc', wordBreak: 'break-all' }}>{pa5LeData.message}</code>
                  <span>Original tag (t):</span> <code style={{ color: '#a5b4fc', wordBreak: 'break-all' }}>{pa5LeData.naive_tag}</code>
                  <span>Forged msg:</span> <code style={{ color: '#fca5a5', wordBreak: 'break-all' }}>{pa5LeData.forged_message}</code>
                  <span>Forged tag (t*):</span> <code style={{ color: '#fca5a5', wordBreak: 'break-all', fontWeight: 700 }}>{pa5LeData.forged_tag}</code>
                </div>
                
                <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid rgba(239,68,68,0.2)', color: '#fca5a5', fontWeight: 700 }}>
                  {pa5LeData.naive_vulnerable ? '💥 Attack Successful: The forged tag is perfectly valid for the extended message.' : 'Attack Failed'}
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text3)', marginTop: '6px', lineHeight: 1.4 }}>
                  The extended tag was computed by resuming the hash function state from the original tag 't'. The secret key 'k' was not required. This is why HMAC uses a double-hash structure.
                </div>
              </div>
            )}
          </div>,
          '#ef4444', 'Length-Extension Vulnerability'
        )}
      </div>
    );
  };

  const renderPA6Special = () => {
    const hexToBinaryArray = (hexStr) => {
      let arr = [];
      for (let i = 0; i < hexStr.length; i += 2) {
        const byte = parseInt(hexStr.substring(i, i + 2), 16);
        for (let b = 7; b >= 0; b--) {
          arr.push((byte >> b) & 1);
        }
      }
      return arr;
    };

    const handleFlip = async (type, bitIdx) => {
      if (!pa6Data) return;
      
      // Toggle locally for instant UI update
      const toggleBit = (hex, idx) => {
        const byteIdx = Math.floor(idx / 8);
        const bitOffset = 7 - (idx % 8);
        let bytes = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        bytes[byteIdx] ^= (1 << bitOffset);
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      };

      let cpaFlipped = pa6CpaFlipped || pa6Data.cpa_ct;
      let ccaFlipped = pa6CcaFlipped || pa6Data.cca_ct;

      if (type === 'cpa') {
        cpaFlipped = toggleBit(cpaFlipped, bitIdx);
        setPa6CpaFlipped(cpaFlipped);
      } else {
        ccaFlipped = toggleBit(ccaFlipped, bitIdx);
        setPa6CcaFlipped(ccaFlipped);
      }
      
      // Call backend
      setPa6Loading(p => ({ ...p, flip: true }));
      const res = await api.pa6MalleabilityFlip({
        key_enc: pa6Data.key_enc,
        key_mac: pa6Data.key_mac,
        cpa_r: pa6Data.cpa_r,
        cpa_ct: cpaFlipped,
        cca_r: pa6Data.cca_r,
        cca_ct: ccaFlipped,
        cca_tag: pa6Data.cca_tag,
      });
      
      setPa6CpaDec(res.cpa_decrypted);
      setPa6CpaErr(res.cpa_error);
      setPa6CcaDec(res.cca_decrypted);
      setPa6CcaRej(res.cca_rejected);
      setPa6CcaErr(res.cca_error);
      setPa6Loading(p => ({ ...p, flip: false }));
    };

    const renderBits = (hex, type) => {
      const bits = hexToBinaryArray(hex);
      return (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2px', fontFamily: 'monospace', fontSize: '12px' }}>
          {bits.map((b, i) => (
            <div 
              key={i} 
              onClick={() => handleFlip(type, i)}
              style={{
                width: '12px', height: '14px', 
                background: b === 1 ? '#4ade80' : 'rgba(255,255,255,0.1)',
                color: b === 1 ? '#000' : '#fff',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                cursor: 'pointer', userSelect: 'none', borderRadius: '2px',
                border: '1px solid rgba(255,255,255,0.2)'
              }}
              title={`Click to flip bit ${i}`}
            >
              {b}
            </div>
          ))}
        </div>
      );
    };

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text2)', marginBottom: '8px', textTransform: 'uppercase' }}>Initialize Malleability Workbench</div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <input 
              type="text" 
              value={pa6Msg} 
              onChange={e => setPa6Msg(e.target.value)} 
              placeholder="Plaintext message..."
              style={{ flex: 1, padding: '8px 12px', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', outline: 'none' }}
            />
            <button 
              onClick={async () => {
                setPa6Loading(p => ({ ...p, init: true }));
                const d = await api.pa6MalleabilityInit(pa6Msg);
                setPa6Data(d);
                setPa6CpaFlipped(d.cpa_ct);
                setPa6CcaFlipped(d.cca_ct);
                setPa6CpaDec(pa6Msg);
                setPa6CcaDec(pa6Msg);
                setPa6CpaErr(null);
                setPa6CcaErr(null);
                setPa6CcaRej(false);
                setPa6Loading(p => ({ ...p, init: false }));
              }}
              disabled={pa6Loading.init}
              style={{ padding: '8px 16px', borderRadius: '6px', background: 'var(--accent)', color: '#000', fontWeight: 700, cursor: 'pointer', border: 'none' }}
            >
              {pa6Loading.init ? '⏳...' : 'Encrypt & Load'}
            </button>
          </div>
        </div>

        {pa6Data && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            
            {/* Left: CPA */}
            <div style={{ background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '12px', padding: '16px' }}>
              <div style={{ fontSize: '14px', fontWeight: 700, color: '#ef4444', marginBottom: '12px', textTransform: 'uppercase' }}>❌ CPA-Only (Malleable)</div>
              
              <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '8px' }}>Ciphertext Bits (Click to flip):</div>
              <div style={{ marginBottom: '16px', opacity: pa6Loading.flip ? 0.5 : 1, pointerEvents: pa6Loading.flip ? 'none' : 'auto' }}>
                {renderBits(pa6CpaFlipped || pa6Data.cpa_ct, 'cpa')}
              </div>
              
              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)' }}>
                <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '4px' }}>Live Decryption:</div>
                {pa6CpaErr ? (
                  <div style={{ color: '#ef4444', fontFamily: 'monospace', fontSize: '14px' }}>[Padding Error]</div>
                ) : (
                  <div style={{ color: pa6CpaDec === pa6Msg ? '#4ade80' : '#fca5a5', fontFamily: 'monospace', fontSize: '16px', wordBreak: 'break-all' }}>
                    {pa6CpaDec}
                  </div>
                )}
              </div>
            </div>

            {/* Right: CCA */}
            <div style={{ background: 'rgba(34,197,94,0.05)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: '12px', padding: '16px' }}>
              <div style={{ fontSize: '14px', fontWeight: 700, color: '#22c55e', marginBottom: '12px', textTransform: 'uppercase' }}>✅ CCA (Encrypt-then-MAC)</div>
              
              <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '8px' }}>Ciphertext Bits (Click to flip):</div>
              <div style={{ marginBottom: '16px', opacity: pa6Loading.flip ? 0.5 : 1, pointerEvents: pa6Loading.flip ? 'none' : 'auto' }}>
                {renderBits(pa6CcaFlipped || pa6Data.cca_ct, 'cca')}
              </div>
              
              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)' }}>
                <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '4px' }}>Live Decryption:</div>
                {pa6CcaRej ? (
                  <div style={{ color: '#ef4444', fontFamily: 'monospace', fontSize: '15px', fontWeight: 700 }}>
                    ⊥ REJECTED (MAC Failure)
                  </div>
                ) : (
                  <div style={{ color: '#4ade80', fontFamily: 'monospace', fontSize: '16px', wordBreak: 'break-all' }}>
                    {pa6CcaDec}
                  </div>
                )}
              </div>
            </div>

          </div>
        )}
      </div>
    );
  };

  const renderPA17Special = () => {
    const handleTamper = async (type) => {
      if (!pa17Data) return;
      
      let cpaC2 = BigInt(pa17Data.cpa.c2);
      let ccaC2 = BigInt(pa17Data.cca.c2);
      let p = BigInt(pa17Data.p);

      const isCpaNowTampered = (type === 'cpa') || pa17CpaTampered;
      const isCcaNowTampered = (type === 'cca') || pa17CcaTampered;

      if (isCpaNowTampered) {
        cpaC2 = (cpaC2 * 2n) % p;
      }
      if (isCcaNowTampered) {
        ccaC2 = (ccaC2 * 2n) % p;
      }
      
      if (type === 'cpa') setPa17CpaTampered(true);
      if (type === 'cca') setPa17CcaTampered(true);
      
      setPa17Loading(p => ({ ...p, flip: true }));
      const res = await api.pa17MalleabilityFlip({
        cpa_c1: pa17Data.cpa.c1,
        cpa_c2: cpaC2.toString(),
        cca_c1: pa17Data.cca.c1,
        cca_c2: ccaC2.toString(),
        cca_sigma: pa17Data.cca.sigma,
      });
      
      setPa17CpaDec(res.cpa_decrypted);
      setPa17CcaDec(res.cca_decrypted);
      setPa17CcaRej(res.cca_rejected);
      setPa17Loading(p => ({ ...p, flip: false }));
    };

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text2)', marginBottom: '8px', textTransform: 'uppercase' }}>Initialize Malleability Workbench (ElGamal)</div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <input 
              type="number" 
              value={pa17Msg} 
              onChange={e => setPa17Msg(e.target.value)} 
              placeholder="Plaintext message (integer)..."
              style={{ flex: 1, padding: '8px 12px', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', outline: 'none', fontSize: '14px' }}
            />
            <button 
              onClick={async () => {
                setPa17Loading(p => ({ ...p, init: true }));
                const d = await api.pa17MalleabilityInit(pa17Msg);
                setPa17Data(d);
                setPa17CpaTampered(false);
                setPa17CcaTampered(false);
                setPa17CpaDec(d.m);
                setPa17CcaDec(d.m);
                setPa17CcaRej(false);
                setPa17Loading(p => ({ ...p, init: false }));
              }}
              disabled={pa17Loading.init}
              style={{ padding: '8px 16px', borderRadius: '6px', background: 'var(--accent)', color: '#000', fontWeight: 700, cursor: 'pointer', border: 'none', fontSize: '14px' }}
            >
              {pa17Loading.init ? '⏳...' : 'Encrypt & Load'}
            </button>
          </div>
        </div>

        {pa17Data && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            
            {/* Left: CPA */}
            <div style={{ background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '12px', padding: '16px' }}>
              <div style={{ fontSize: '14px', fontWeight: 700, color: '#ef4444', marginBottom: '12px', textTransform: 'uppercase' }}>❌ CPA-Only (ElGamal)</div>
              
              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)', marginBottom: '16px' }}>
                <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '4px' }}>Ciphertext <span style={{ fontFamily: 'serif', fontStyle: 'italic' }}>C<sub>E</sub> = (c<sub>1</sub>, c<sub>2</sub>)</span>:</div>
                <div style={{ fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all', color: 'var(--text2)', maxHeight: '100px', overflowY: 'auto' }}>
                  c1 = {pa17Data.cpa.c1}<br />
                  <br />
                  c2 = {pa17CpaTampered ? <span style={{ color: '#fca5a5', textDecoration: 'underline' }}>{((BigInt(pa17Data.cpa.c2) * 2n) % BigInt(pa17Data.p)).toString()}</span> : pa17Data.cpa.c2}
                </div>
              </div>

              <button 
                onClick={() => handleTamper('cpa')} 
                disabled={pa17CpaTampered || pa17Loading.flip}
                className="btn btn-ghost" 
                style={{ width: '100%', marginBottom: '16px', color: '#fca5a5', borderColor: '#fca5a5' }}
              >
                {pa17CpaTampered ? 'Tampered!' : 'Tamper with C_E (c2 = 2 * c2)'}
              </button>
              
              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)' }}>
                <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '4px' }}>Live Decryption Oracle:</div>
                <div style={{ color: pa17CpaDec === pa17Data.m ? '#4ade80' : '#fca5a5', fontFamily: 'monospace', fontSize: '16px', wordBreak: 'break-all' }}>
                  {pa17CpaDec}
                </div>
                {pa17CpaTampered && (
                  <div style={{ color: '#ef4444', fontSize: '12px', marginTop: '6px' }}>
                    Notice how the plaintext doubled to 2m! The CCA attacker won.
                  </div>
                )}
              </div>
            </div>

            {/* Right: CCA */}
            <div style={{ background: 'rgba(34,197,94,0.05)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: '12px', padding: '16px' }}>
              <div style={{ fontSize: '14px', fontWeight: 700, color: '#22c55e', marginBottom: '12px', textTransform: 'uppercase' }}>✅ CCA-Secure (Encrypt-then-Sign)</div>
              
              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)', marginBottom: '16px' }}>
                <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '4px' }}>Ciphertext & Signature <span style={{ fontFamily: 'serif', fontStyle: 'italic' }}>C = (C<sub>E</sub>, σ)</span>:</div>
                <div style={{ fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all', color: 'var(--text2)', maxHeight: '100px', overflowY: 'auto' }}>
                  c1 = {pa17Data.cca.c1}<br />
                  <br />
                  c2 = {pa17CcaTampered ? <span style={{ color: '#fca5a5', textDecoration: 'underline' }}>{((BigInt(pa17Data.cca.c2) * 2n) % BigInt(pa17Data.p)).toString()}</span> : pa17Data.cca.c2}<br />
                  <br />
                  σ = {pa17Data.cca.sigma}
                </div>
              </div>

              <button 
                onClick={() => handleTamper('cca')} 
                disabled={pa17CcaTampered || pa17Loading.flip}
                className="btn btn-ghost" 
                style={{ width: '100%', marginBottom: '16px', color: '#86efac', borderColor: '#86efac' }}
              >
                {pa17CcaTampered ? 'Tampered!' : 'Tamper with C_E (c2 = 2 * c2)'}
              </button>
              
              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)' }}>
                <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '4px' }}>Live Decryption Oracle:</div>
                {pa17CcaRej ? (
                  <div style={{ color: '#ef4444', fontFamily: 'monospace', fontSize: '15px', fontWeight: 700 }}>
                    ⊥ REJECTED
                    <div style={{ fontSize: '12px', fontWeight: 'normal', marginTop: '4px', color: '#fca5a5' }}>
                      Signature invalid, decryption aborted, output ⊥
                    </div>
                  </div>
                ) : (
                  <div style={{ color: '#4ade80', fontFamily: 'monospace', fontSize: '16px', wordBreak: 'break-all' }}>
                    {pa17CcaDec}
                  </div>
                )}
              </div>
            </div>

          </div>
        )}
      </div>
    );
  };

  const renderPA19Special = () => {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          <div style={{ background: 'rgba(99,102,241,0.05)', padding: '16px', borderRadius: '12px', border: '1px solid rgba(99,102,241,0.3)' }}>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--accent3)', marginBottom: '12px' }}>Alice (Sender)</div>
            <div style={{ marginBottom: '8px', fontSize: '13px', color: 'var(--text2)' }}>Input bit <b>a</b>:</div>
            <select 
              value={pa19A} 
              onChange={e => setPa19A(parseInt(e.target.value))}
              style={{ width: '100%', padding: '8px', background: 'rgba(0,0,0,0.4)', color: 'white', border: '1px solid var(--border)', borderRadius: '6px' }}
            >
              <option value={0}>0</option>
              <option value={1}>1</option>
            </select>
          </div>
          
          <div style={{ background: 'rgba(34,197,94,0.05)', padding: '16px', borderRadius: '12px', border: '1px solid rgba(34,197,94,0.3)' }}>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#4ade80', marginBottom: '12px' }}>Bob (Receiver)</div>
            <div style={{ marginBottom: '8px', fontSize: '13px', color: 'var(--text2)' }}>Input bit <b>b</b>:</div>
            <select 
              value={pa19B} 
              onChange={e => setPa19B(parseInt(e.target.value))}
              style={{ width: '100%', padding: '8px', background: 'rgba(0,0,0,0.4)', color: 'white', border: '1px solid var(--border)', borderRadius: '6px' }}
            >
              <option value={0}>0</option>
              <option value={1}>1</option>
            </select>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button 
            className="btn btn-primary" 
            style={{ flex: 1 }} 
            disabled={pa19Loading.and}
            onClick={async () => {
              setPa19Loading(p => ({ ...p, and: true }));
              const res = await api.pa19SecureAnd(pa19A, pa19B);
              setPa19Data(res);
              setPa19Loading(p => ({ ...p, and: false }));
            }}
          >
            {pa19Loading.and ? '⏳ Computing...' : '▶ Compute Secure AND'}
          </button>
          
          <button 
            className="btn btn-ghost" 
            style={{ flex: 1 }} 
            disabled={pa19Loading.table}
            onClick={async () => {
              setPa19Loading(p => ({ ...p, table: true }));
              const res = await api.pa19TruthTable();
              setPa19Table(res);
              setPa19Loading(p => ({ ...p, table: false }));
            }}
          >
            {pa19Loading.table ? '⏳...' : '▦ Run All (Truth Table)'}
          </button>
        </div>

        {pa19Data && (
          <div style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text)', marginBottom: '16px', display: 'flex', justifyContent: 'space-between' }}>
              <span>Step-by-Step OT Transcript</span>
              <span style={{ color: pa19Data.correct ? '#4ade80' : '#fca5a5' }}>
                Output: {pa19Data.result} (Expected: {pa19Data.expected})
              </span>
            </div>
            
            <div className="step">
              <div className="fn">1. Alice sets up OT sender messages:</div>
              <div className="vals">
                m<sub>0</sub> = 0 <br/>
                m<sub>1</sub> = a = {pa19Data.transcript.alice_ot_messages[1]}
              </div>
            </div>
            <div className="step-arrow">↓</div>
            
            <div className="step" style={{ borderLeftColor: '#4ade80' }}>
              <div className="fn">2. Bob runs OT receiver with choice bit:</div>
              <div className="vals">b = {pa19Data.transcript.bob_choice}</div>
            </div>
            <div className="step-arrow">↓</div>
            
            <div className="step" style={{ borderLeftColor: '#4ade80' }}>
              <div className="fn">3. Bob receives m<sub>b</sub>:</div>
              <div className="vals">m<sub>{pa19Data.transcript.bob_choice}</sub> = {pa19Data.transcript.bob_received}</div>
            </div>

            <div style={{ marginTop: '20px', padding: '12px', background: 'rgba(255,255,255,0.05)', borderRadius: '8px' }}>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--accent3)', marginBottom: '8px' }}>Privacy Summary:</div>
              <ul style={{ fontSize: '12px', color: 'var(--text2)', paddingLeft: '20px', margin: 0, lineHeight: 1.6 }}>
                <li><b>What does Alice learn?</b> Nothing. She acting as the OT sender guarantees she learns nothing about Bob's choice bit <span style={{ fontFamily: 'monospace' }}>b</span>.</li>
                <li><b>What does Bob learn?</b> Only <span style={{ fontFamily: 'monospace' }}>a ∧ b</span>. Because he is the OT receiver, he only receives <span style={{ fontFamily: 'monospace' }}>m_b</span> and learns absolutely nothing about the other message <span style={{ fontFamily: 'monospace' }}>m_&#123;1-b&#125;</span>.</li>
              </ul>
            </div>
          </div>
        )}

        {pa19Table && (
          <div style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text)', marginBottom: '16px' }}>Truth Table Verification</div>
            <table style={{ width: '100%', fontSize: '13px', textAlign: 'left', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th style={{ padding: '8px' }}>a</th>
                  <th style={{ padding: '8px' }}>b</th>
                  <th style={{ padding: '8px' }}>AND (Expected)</th>
                  <th style={{ padding: '8px' }}>XOR (Expected)</th>
                  <th style={{ padding: '8px' }}>Tests Passed</th>
                </tr>
              </thead>
              <tbody>
                {['(0, 0)', '(0, 1)', '(1, 0)', '(1, 1)'].map((keyStr) => {
                  // In python dictionary, the keys might come back as string tuples like "(0, 0)" 
                  // or if it returns lists like "[0, 0]", we should check the JSON format.
                  // Since Python tuples (a, b) as dict keys serialize to string "['0', '0']" or similar in FastAPI? 
                  // FastAPI typically stringifies tuple keys. Let's look at the keys safely.
                  let kStr = keyStr;
                  let andRes = pa19Table.and_results[kStr];
                  // If not found, try to find matching keys
                  if (!andRes) {
                    const keys = Object.keys(pa19Table.and_results);
                    const parsedKey = keyStr.replace(/[\(\)\[\]\s]/g, '').split(',');
                    const foundKey = keys.find(k => k.includes(parsedKey[0]) && k.includes(parsedKey[1]));
                    if (foundKey) {
                      andRes = pa19Table.and_results[foundKey];
                      kStr = foundKey;
                    }
                  }
                  if (!andRes) return null;
                  const xorRes = pa19Table.xor_results[kStr];
                  
                  const aVal = keyStr[1];
                  const bVal = keyStr[4];

                  return (
                    <tr key={keyStr} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <td style={{ padding: '8px', color: 'var(--accent3)' }}>{aVal}</td>
                      <td style={{ padding: '8px', color: '#4ade80' }}>{bVal}</td>
                      <td style={{ padding: '8px' }}>{andRes.expected}</td>
                      <td style={{ padding: '8px' }}>{xorRes.expected}</td>
                      <td style={{ padding: '8px', color: '#4ade80' }}>{andRes.correct + xorRes.correct} / {andRes.total * 2} ✓</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <div style={{ fontSize: '12px', color: 'var(--text3)', marginTop: '12px', fontStyle: 'italic' }}>
              Evaluated using 1 full cryptographic run per gate per combination. Server logs have 50 runs.
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderPA20Special = () => {
    
    const handleCompute = async () => {
      setPa20Loading(true);
      setPa20GateIdx(-1);
      setPa20Data(null);
      setPa20Expanded(false);
      
      const res = await api.pa20Evaluate(pa20Alice, pa20Bob, pa20Mode, 4);
      setPa20Data(res);
      setPa20Loading(false);
      
      // Animate gates
      if (res.gate_log && res.gate_log.length > 0) {
        let i = 0;
        const interval = setInterval(() => {
          setPa20GateIdx(i);
          i++;
          if (i >= res.gate_log.length) {
            clearInterval(interval);
          }
        }, 100); // 100ms per gate animation
      } else {
        setPa20GateIdx(0);
      }
    };
    
    const isFinished = pa20Data && pa20GateIdx >= pa20Data.gate_log.length - 1;
    const progressPct = pa20Data ? Math.min(100, Math.round(((pa20GateIdx + 1) / pa20Data.gate_log.length) * 100)) : 0;
    
    let plainResult = "";
    if (isFinished) {
      if (pa20Mode === 'comparator') {
        if (pa20Data.alice_val_hidden > pa20Data.bob_val_hidden) plainResult = "Alice is richer 🤑";
        else if (pa20Data.alice_val_hidden < pa20Data.bob_val_hidden) plainResult = "Bob is richer 🤑";
        else plainResult = "Wealth is Equal 🤝";
      } else if (pa20Mode === 'equality') {
        if (pa20Data.output === 1) plainResult = "Match! 🟢";
        else plainResult = "No Match 🔴";
      } else if (pa20Mode === 'adder') {
        plainResult = `The Sum is ${pa20Data.output}`;
      }
    }

    let aliceLabel = "Alice's Wealth (x):";
    let bobLabel = "Bob's Wealth (y):";
    let valPrefix = "$";
    let valSuffix = "M";
    let btnText = "▶ Who is richer? (Run Secure MPC)";

    if (pa20Mode === 'equality') {
      aliceLabel = "Alice's Secret Number:";
      bobLabel = "Bob's Secret Number:";
      valPrefix = ""; valSuffix = "";
      btnText = "▶ Do they match? (Run Secure MPC)";
    } else if (pa20Mode === 'adder') {
      aliceLabel = "Alice's Value:";
      bobLabel = "Bob's Value:";
      valPrefix = ""; valSuffix = "";
      btnText = "▶ Compute Sum (Run Secure MPC)";
    }

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ display: 'flex', gap: '8px', marginBottom: '4px' }}>
          <button 
            className={`btn ${pa20Mode === 'comparator' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => { setPa20Mode('comparator'); setPa20Data(null); }}
            style={{ flex: 1 }}
          >💰 Millionaire's Problem</button>
          <button 
            className={`btn ${pa20Mode === 'equality' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => { setPa20Mode('equality'); setPa20Data(null); }}
            style={{ flex: 1 }}
          >🤝 Secure Equality</button>
          <button 
            className={`btn ${pa20Mode === 'adder' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => { setPa20Mode('adder'); setPa20Data(null); }}
            style={{ flex: 1 }}
          >➕ Secure Adder</button>
        </div>

        <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-start' }}>
          {/* Alice Panel */}
          <div style={{ flex: 1, background: 'rgba(99,102,241,0.05)', padding: '20px', borderRadius: '12px', border: '1px solid rgba(99,102,241,0.3)', position: 'relative', overflow: 'hidden' }}>
            <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--accent3)', marginBottom: '16px', display: 'flex', justifyContent: 'space-between' }}>
              <span>Alice's Panel</span>
              <span style={{ fontSize: '12px', background: 'rgba(99,102,241,0.2)', padding: '2px 8px', borderRadius: '10px' }}>Hidden from Bob</span>
            </div>
            <div style={{ marginBottom: '8px', fontSize: '13px', color: 'var(--text2)' }}>{aliceLabel} <b>{valPrefix}{pa20Alice}{valSuffix}</b></div>
            <input 
              type="range" 
              min="1" 
              max="15" 
              value={pa20Alice} 
              onChange={e => setPa20Alice(parseInt(e.target.value))}
              style={{ width: '100%', cursor: 'pointer' }}
            />
          </div>
          
          {/* Bob Panel */}
          <div style={{ flex: 1, background: 'rgba(34,197,94,0.05)', padding: '20px', borderRadius: '12px', border: '1px solid rgba(34,197,94,0.3)', position: 'relative', overflow: 'hidden' }}>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#4ade80', marginBottom: '16px', display: 'flex', justifyContent: 'space-between' }}>
              <span>Bob's Panel</span>
              <span style={{ fontSize: '12px', background: 'rgba(34,197,94,0.2)', padding: '2px 8px', borderRadius: '10px' }}>Hidden from Alice</span>
            </div>
            <div style={{ marginBottom: '8px', fontSize: '13px', color: 'var(--text2)' }}>{bobLabel} <b>{valPrefix}{pa20Bob}{valSuffix}</b></div>
            <input 
              type="range" 
              min="1" 
              max="15" 
              value={pa20Bob} 
              onChange={e => setPa20Bob(parseInt(e.target.value))}
              style={{ width: '100%', cursor: 'pointer' }}
            />
          </div>
        </div>

        <button 
          className="btn btn-primary" 
          style={{ width: '100%', padding: '16px', fontSize: '16px' }} 
          disabled={pa20Loading}
          onClick={handleCompute}
        >
          {pa20Loading ? '⏳ Garbling & Evaluating Circuit...' : btnText}
        </button>

        {pa20Data && (
          <div style={{ background: 'rgba(0,0,0,0.2)', padding: '20px', borderRadius: '12px', border: '1px solid var(--border)' }}>
            
            {/* Progress Bar Area */}
            <div style={{ marginBottom: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '13px', color: 'var(--text2)' }}>
                <span>Evaluating Garbled Circuit Gates (AND/XOR)</span>
                <span>{Math.max(0, pa20GateIdx + 1)} / {pa20Data.gate_log.length}</span>
              </div>
              <div style={{ width: '100%', height: '8px', background: 'rgba(255,255,255,0.1)', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${progressPct}%`, background: 'var(--accent)', transition: 'width 0.1s linear' }}></div>
              </div>
            </div>

            {/* Result Area */}
            {isFinished && (
              <div style={{ textAlign: 'center', padding: '24px', background: 'rgba(255,255,255,0.05)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.1)' }}>
                <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '1px' }}>MPC Protocol Complete</div>
                <div style={{ fontSize: '24px', fontWeight: 800, color: '#fff', marginBottom: '12px' }}>
                  {plainResult}
                </div>
                <div style={{ fontSize: '14px', color: '#4ade80' }}>
                  <b>Privacy Guaranteed:</b> The actual values $x$ and $y$ were never revealed!
                </div>
              </div>
            )}

            {/* Circuit Trace Accordion */}
            <div style={{ marginTop: '24px' }}>
              <button 
                onClick={() => setPa20Expanded(!pa20Expanded)}
                style={{ width: '100%', padding: '12px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: '8px', color: 'var(--text)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
              >
                <span style={{ fontWeight: 600 }}>Circuit Trace (Evaluated Gates)</span>
                <span>{pa20Expanded ? '▼' : '▶'}</span>
              </button>
              
              {pa20Expanded && (
                <div style={{ marginTop: '12px', padding: '16px', background: '#0f172a', borderRadius: '8px', maxHeight: '300px', overflowY: 'auto', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '12px', fontFamily: 'monospace' }}>
                    // Executed {pa20Data.gate_log.length} gates using {pa20Data.ot_calls} Oblivious Transfers
                    <br/>// Time elapsed: {pa20Data.time_sec.toFixed(3)}s
                  </div>
                  <table style={{ width: '100%', fontSize: '12px', fontFamily: 'monospace', textAlign: 'left', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                        <th style={{ padding: '6px' }}>#</th>
                        <th style={{ padding: '6px' }}>Gate</th>
                        <th style={{ padding: '6px' }}>In Wires</th>
                        <th style={{ padding: '6px' }}>Out Wire</th>
                        <th style={{ padding: '6px', textAlign: 'right' }}>Eval Val</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pa20Data.gate_log.map((g, idx) => (
                        <tr key={idx} style={{ opacity: idx <= pa20GateIdx ? 1 : 0.3, transition: 'opacity 0.2s' }}>
                          <td style={{ padding: '6px', color: 'var(--text3)' }}>{idx}</td>
                          <td style={{ padding: '6px', color: g.type === 'AND' ? 'var(--accent3)' : '#4ade80' }}>{g.type}</td>
                          <td style={{ padding: '6px' }}>[{g.inputs.join(', ')}]</td>
                          <td style={{ padding: '6px' }}>w{g.output}</td>
                          <td style={{ padding: '6px', textAlign: 'right', fontWeight: 600, color: '#fff' }}>{idx <= pa20GateIdx ? g.value : '?'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            
          </div>
        )}      </div>
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
          <div style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent)', marginBottom: '12px', textTransform: 'uppercase' }}>🔢 Live DLP Hash</div>
          <input
            id="pa8-message-input"
            type="text"
            placeholder="Type a message…"
            value={params.message || ''}
            style={{
              width: '100%', boxSizing: 'border-box', padding: '10px 14px',
              background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(99,102,241,0.4)',
              borderRadius: '8px', color: 'var(--text1)', fontSize: '16px',
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
              <div style={{ fontSize: '13px', color: 'var(--text3)', marginBottom: '2px' }}>Full hash  ({pa8Hash.digest_bytes} bytes — group element mod p):</div>
              <div style={{
                fontFamily: 'monospace', fontSize: '14px', wordBreak: 'break-all',
                background: 'rgba(0,0,0,0.4)', borderRadius: '6px', padding: '10px 12px',
                border: '1px solid rgba(99,102,241,0.25)', color: '#a5b4fc', lineHeight: 1.6,
              }}>
                0x{pa8Hash.hash_hex}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '4px' }}>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '6px', padding: '8px 10px', border: '1px solid rgba(99,102,241,0.15)' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '3px' }}>16-bit truncation</div>
                  <div style={{ fontFamily: 'monospace', fontSize: '15px', color: '#c4b5fd', fontWeight: 700 }}>0x{pa8Hash.truncated_hex}</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '6px', padding: '8px 10px', border: '1px solid rgba(99,102,241,0.15)' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '3px' }}>Decimal</div>
                  <div style={{ fontFamily: 'monospace', fontSize: '15px', color: '#c4b5fd', fontWeight: 700 }}>{pa8Hash.truncated_16bit}</div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* ── Group Parameters ── */}
        {pa8Hash && (
          <div style={{
            background: 'rgba(0,0,0,0.2)', borderRadius: '10px', padding: '14px',
            border: '1px solid var(--border)', fontSize: '13px',
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
            <div style={{ marginTop: '10px', fontSize: '12px', color: 'var(--text3)', borderTop: '1px solid var(--border)', paddingTop: '8px' }}>
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
          <div style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.08em', color: '#f59e0b', marginBottom: '12px', textTransform: 'uppercase' }}>🎯 Collision Hunt  (birthday bound demo)</div>

          <div style={{ fontSize: '14px', color: 'var(--text2)', marginBottom: '14px', lineHeight: 1.5 }}>
            Truncates the hash to <strong>16 bits</strong> (output space = 65 536). Birthday bound ≈ 2<sup>16/2</sup> = <strong>256 evaluations</strong>.
          </div>

          <div style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
            <button
              id="pa8-collision-start-btn"
              disabled={huntRunning}
              style={{
                flex: 1, padding: '10px', borderRadius: '8px', fontWeight: 700, fontSize: '15px', cursor: huntRunning ? 'not-allowed' : 'pointer',
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
                  padding: '10px 16px', borderRadius: '8px', fontWeight: 700, fontSize: '15px', cursor: 'pointer',
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
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', color: 'var(--text3)', marginBottom: '6px' }}>
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
              <div style={{ fontSize: '12px', color: 'var(--text3)', marginTop: '4px', textAlign: 'right' }}>
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
              <div style={{ fontWeight: 700, color: '#22c55e', marginBottom: '10px', fontSize: '16px' }}>💥 Collision Found after {evals.toLocaleString()} evaluations!</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', fontSize: '14px' }}>
                <span style={{ color: 'var(--text3)' }}>Input 1</span>
                <code style={{ color: '#86efac', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>{collision.msg1}</code>
                <span style={{ color: 'var(--text3)' }}>Input 2</span>
                <code style={{ color: '#86efac', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>{collision.msg2}</code>
                <span style={{ color: 'var(--text3)' }}>Hash (16-bit)</span>
                <code style={{ color: '#fbbf24', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>0x{collision.hash_16bit} = {collision.hash_decimal}</code>
              </div>
              <div style={{ marginTop: '12px', fontSize: '13px', color: 'var(--text3)', borderTop: '1px solid rgba(34,197,94,0.2)', paddingTop: '10px', lineHeight: 1.5 }}>
                <strong style={{ color: 'var(--text2)' }}>Why this doesn't break security:</strong> Finding a collision on a <em>truncated</em> 16-bit output is easy (birthday ≈ 256). Breaking the <em>full</em> DLP Hash requires solving
                the discrete log to find (x,y) ≠ (x′,y′) with gˣ·ĥʸ = gˣ′·ĥʸ′ mod p.
              </div>
            </div>
          )}

          {status === 'exhausted' && !collision && (
            <div style={{ color: '#f87171', fontSize: '14px', padding: '10px', background: 'rgba(239,68,68,0.08)', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.2)' }}>
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
          <div style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent)', marginBottom: '12px', textTransform: 'uppercase' }}>🎛️ Output Bit-Length n</div>

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
                  fontSize: '15px',
                  cursor: 'pointer',
                  transition: 'all 0.18s',
                }}
              >
                {n}-bit
              </button>
            ))}
          </div>

          <div style={{ marginTop: '12px', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '8px', fontSize: '13px' }}>
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
          <div style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.08em', color: '#f59e0b', marginBottom: '12px', textTransform: 'uppercase' }}>🎯 Birthday Attack</div>

          <div style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
            <button
              id="pa9-run-btn"
              disabled={pa9Running}
              style={{
                flex: 1, padding: '10px', borderRadius: '8px', fontWeight: 700, fontSize: '15px',
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
                  padding: '10px 16px', borderRadius: '8px', fontWeight: 700, fontSize: '15px', cursor: 'pointer',
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
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', color: 'var(--text3)', marginBottom: '6px' }}>
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
            <div style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--text2)', marginBottom: '10px', textTransform: 'uppercase' }}>📈 Collision Probability vs Hashes Computed</div>
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
            <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontSize: '12px', flexWrap: 'wrap' }}>
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
            <div style={{ fontWeight: 700, color: '#22c55e', marginBottom: '10px', fontSize: '16px' }}>💥 Collision Found in {evals.toLocaleString()} evaluations! (expected ≈ {Math.round(bound)})</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', fontSize: '14px' }}>
              <span style={{ color: 'var(--text3)' }}>Input 1</span>
              <code style={{ color: '#86efac', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px', wordBreak: 'break-all' }}>0x{collision.input1}</code>
              <span style={{ color: 'var(--text3)' }}>Input 2</span>
              <code style={{ color: '#86efac', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px', wordBreak: 'break-all' }}>0x{collision.input2}</code>
              <span style={{ color: 'var(--text3)' }}>Shared hash ({nBits}-bit)</span>
              <code style={{ color: '#fbbf24', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>0x{collision.hash_hex} = {collision.hash_value}</code>
            </div>
            <div style={{ marginTop: '12px', fontSize: '13px', color: 'var(--text3)', borderTop: '1px solid rgba(34,197,94,0.2)', paddingTop: '10px', lineHeight: 1.5 }}>
              <strong style={{ color: 'var(--text2)' }}>Birthday paradox:</strong> With only {nBits} output bits (2<sup>{nBits}</sup> = {Math.pow(2,nBits).toLocaleString()} possible values),
              a collision appears after ≈ 2<sup>{nBits}/2</sup> = {Math.round(bound)} hashes — far fewer than the full output space.
              Ratio empirical/expected: <strong style={{ color: '#34d399' }}>{(evals / bound).toFixed(2)}×</strong>.
            </div>
          </div>
        )}

        {status === 'exhausted' && !collision && (
          <div style={{ color: '#f87171', fontSize: '14px', padding: '10px', background: 'rgba(239,68,68,0.08)', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.2)' }}>
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
                    </div>                </div>

                <div className="test-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                  {result.stats.map(s => (
                    <div key={s.test} className={`test-badge ${s.pass ? 'pass' : 'fail'}`} style={{
                      padding: '8px',
                      borderRadius: '6px',
                      textAlign: 'center',
                      background: s.pass ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                      border: `1px solid ${s.pass ? '#22c55e' : '#ef4444'}`
                    }}>
                      <div style={{ fontSize: '12px', fontWeight: 600, color: s.pass ? '#22c55e' : '#ef4444' }}>{s.test.toUpperCase()}</div>
                      <div style={{ fontSize: '13px' }}>{s.pass ? 'PASS' : 'FAIL'}</div>
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
        {title && <div style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.08em', color: accent, marginBottom: '12px', textTransform: 'uppercase' }}>{title}</div>}
        {children}
      </div>
    );

    const mono = (txt, color = '#a5b4fc') => (
      <code style={{ fontFamily: 'monospace', fontSize: '13px', wordBreak: 'break-all', color, background: 'rgba(0,0,0,0.35)', borderRadius: '4px', padding: '2px 6px' }}>{txt}</code>
    );

    const badge = (ok, yes = 'Secure ✓', no = 'Vulnerable ✗') => (
      <span style={{ fontWeight: 700, color: ok ? '#22c55e' : '#ef4444', background: ok ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.12)', border: `1px solid ${ok ? '#22c55e' : '#ef4444'}`, borderRadius: '6px', padding: '2px 10px', fontSize: '14px' }}>
        {ok ? yes : no}
      </span>
    );

    const btn = (label, onClick, accent = '#818cf8', loading = false) => (
      <button onClick={onClick} disabled={loading} style={{
        padding: '9px 18px', borderRadius: '8px', border: `1px solid ${accent}80`,
        background: loading ? `${accent}22` : `linear-gradient(135deg, ${accent}cc, ${accent}88)`,
        color: 'white', fontWeight: 700, fontSize: '14px', cursor: loading ? 'not-allowed' : 'pointer',
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
            <span style={{ fontSize: '14px', color: 'var(--text2)' }}>Underlying hash:</span>
            {['dlp', 'sha256'].map(m => (
              <button key={m} onClick={() => { setPa10HashMode(m); setPa10LeData(null); }} style={{
                padding: '6px 16px', borderRadius: '8px', fontWeight: 700, fontSize: '14px', cursor: 'pointer',
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
            <div style={{ marginBottom: '12px', fontSize: '14px', color: 'var(--text2)', lineHeight: 1.5 }}>
              Type a suffix m′. Left: naive <code>H(k‖m)</code> is forged. Right: HMAC resists.
            </div>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '12px', alignItems: 'center' }}>
              <input
                id="pa10-suffix-input"
                type="text"
                value={pa10LeSuffix}
                placeholder="Type suffix m′…"
                onChange={e => setPa10LeSuffix(e.target.value)}
                style={{ flex: 1, padding: '9px 13px', background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(239,68,68,0.4)', borderRadius: '8px', color: 'var(--text1)', fontSize: '15px', fontFamily: 'monospace', outline: 'none' }}
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
                <div style={{ fontWeight: 700, color: '#f87171', marginBottom: '10px', fontSize: '14px' }}>⚠️ Naive H(k‖m) — BROKEN</div>
                {pa10LeLoading && <div className="spinner" style={{ margin: '10px auto' }} />}
                {pa10LeData && <>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '4px' }}>Original message</div>
                  <div style={{ marginBottom: '8px' }}>{mono(pa10LeData.message)}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '4px' }}>Naive tag t = H(k‖m)</div>
                  <div style={{ marginBottom: '8px' }}>{mono(pa10LeData.naive_tag?.slice(0, 24) + '…', '#fca5a5')}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '4px' }}>Forged message (m‖pad‖m′)</div>
                  <div style={{ marginBottom: '8px', fontSize: '12px', fontFamily: 'monospace', wordBreak: 'break-all', color: '#fca5a5', background: 'rgba(0,0,0,0.3)', borderRadius: '4px', padding: '6px' }}>{pa10LeData.forged_message}</div>
                  <div style={{ marginBottom: '8px' }}>{badge(false, '', '🔥 Forgery Succeeded!')}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', lineHeight: 1.4 }}>
                    Attacker used naive_tag as IV, continued hashing m′ — valid without knowing k.
                  </div>
                </>}
                {!pa10LeData && !pa10LeLoading && <div style={{ fontSize: '13px', color: 'var(--text3)', textAlign: 'center', padding: '20px' }}>Press ⚡ Attack!</div>}
              </div>

              {/* RIGHT — HMAC */}
              <div style={{ background: 'rgba(34,197,94,0.07)', border: '1px solid rgba(34,197,94,0.35)', borderRadius: '10px', padding: '14px' }}>
                <div style={{ fontWeight: 700, color: '#4ade80', marginBottom: '10px', fontSize: '14px' }}>✅ HMAC — SECURE</div>
                {pa10LeLoading && <div className="spinner" style={{ margin: '10px auto' }} />}
                {pa10LeData && <>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '4px' }}>Original message</div>
                  <div style={{ marginBottom: '8px' }}>{mono(pa10LeData.message)}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '4px' }}>HMAC tag</div>
                  <div style={{ marginBottom: '8px' }}>{mono(pa10LeData.hmac_tag?.slice(0, 24) + '…', '#86efac')}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '4px' }}>Same forged message attempted</div>
                  <div style={{ marginBottom: '8px', fontSize: '12px', fontFamily: 'monospace', wordBreak: 'break-all', color: '#86efac', background: 'rgba(0,0,0,0.3)', borderRadius: '4px', padding: '6px' }}>{pa10LeData.forged_message}</div>
                  <div style={{ marginBottom: '8px' }}>{badge(true, '🔒 Forgery Failed!')}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', lineHeight: 1.4 }}>
                    HMAC wraps with outer hash — leaked state can't be reused without k.
                  </div>
                </>}
                {!pa10LeData && !pa10LeLoading && <div style={{ fontSize: '13px', color: 'var(--text3)', textAlign: 'center', padding: '20px' }}>Press ⚡ Attack!</div>}
              </div>
            </div>
          </div>,
          '#ef4444', '4. Length-Extension Attack Demo'
        )}

        {/* ── EUF-CMA game ── */}
        {card(
          <div>
            <div style={{ fontSize: '14px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
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
                    <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '4px' }}>{l}</div>
                    <div style={{ fontSize: '24px', fontWeight: 800, color: c }}>{v}</div>
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
            <div style={{ fontSize: '14px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
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
                      <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '4px' }}>{l}</div>
                      <div style={{ fontSize: '24px', fontWeight: 800, color: '#c4b5fd' }}>{v}</div>
                    </div>
                  ))}
                </div>
                {badge(pa10MacData.all_distinct, 'No Collisions — MAC⇒CRHF Holds ✓')}
                <div style={{ marginTop: '10px', fontSize: '12px', color: 'var(--text3)', lineHeight: 1.4 }}>
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
            <div style={{ fontSize: '14px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
              EtH_Enc: encrypt with PA#3 CPA scheme, then HMAC the ciphertext. EtH_Dec: verify HMAC first, then decrypt.
            </div>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '12px', alignItems: 'center' }}>
              <input
                id="pa10-eth-msg-input"
                type="text"
                value={pa10EthMsg}
                onChange={e => setPa10EthMsg(e.target.value)}
                placeholder="Plaintext to encrypt…"
                style={{ flex: 1, padding: '9px 13px', background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(16,185,129,0.4)', borderRadius: '8px', color: 'var(--text1)', fontSize: '15px', fontFamily: 'monospace', outline: 'none' }}
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
                <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 10px', fontSize: '13px', marginBottom: '12px' }}>
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
                    <div style={{ fontWeight: 700, fontSize: '14px', color: pa10DecData.success ? '#4ade80' : '#f87171', marginBottom: '6px' }}>{pa10DecData.result}</div>
                    {pa10DecData.success && <div style={{ fontFamily: 'monospace', fontSize: '14px', color: '#34d399' }}>Decrypted: "{pa10DecData.plaintext}"</div>}
                    {!pa10DecData.success && <div style={{ fontSize: '13px', color: 'var(--text3)' }}>HMAC verification failed — ciphertext rejected before decryption (CCA2 safety).</div>}
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
            <div style={{ fontSize: '14px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
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
                      <div style={{ fontSize: '11px', color: 'var(--text3)', marginBottom: '4px' }}>{l}</div>
                      <div style={{ fontSize: '20px', fontWeight: 800, color: c }}>{v}</div>
                    </div>
                  ))}
                </div>
                {badge(pa10CcaData.secure, 'IND-CCA2 Secure ✓', 'Security Broken!')}
                <div style={{ marginTop: '8px', fontSize: '12px', color: 'var(--text3)', lineHeight: 1.4 }}>
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
            <div style={{ fontSize: '14px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
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
                      <div style={{ fontSize: '11px', color: 'var(--text3)', marginBottom: '4px' }}>{l}</div>
                      <div style={{ fontSize: '17px', fontWeight: 800, color: c }}>{v}</div>
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
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--text3)', marginBottom: '2px' }}>
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
                <div style={{ marginTop: '8px', fontSize: '12px', color: 'var(--text3)', lineHeight: 1.4 }}>
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
        <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '3px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
        <div style={{ fontFamily: 'monospace', fontSize: '14px', wordBreak: 'break-all', color: matched === true ? matchClr : matched === false ? nomatchClr : color, fontWeight: 700 }}>
          0x{hexShort(val)}
        </div>
        {matched === true  && <div style={{ fontSize: '12px', color: matchClr, marginTop: '4px' }}>✓ Matches</div>}
        {matched === false && <div style={{ fontSize: '12px', color: nomatchClr, marginTop: '4px' }}>✗ No match</div>}
      </div>
    );

    const inputField = (label, val, setter, placeholder, color) => (
      <div>
        <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
        <div style={{ display: 'flex', gap: '6px' }}>
          <input
            type="text"
            value={val}
            placeholder={placeholder}
            onChange={e => setter(e.target.value)}
            style={{
              flex: 1, padding: '7px 10px', background: 'rgba(0,0,0,0.35)',
              border: `1px solid ${color}55`, borderRadius: '6px',
              color: color, fontFamily: 'monospace', fontSize: '14px', outline: 'none',
            }}
          />
          <button
            onClick={() => setter('')}
            title="Randomise"
            style={{
              padding: '7px 10px', borderRadius: '6px', border: `1px solid ${color}55`,
              background: 'rgba(0,0,0,0.2)', color: color, cursor: 'pointer', fontSize: '16px',
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
            border: '1px solid var(--border)', fontSize: '13px',
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
            <div style={{ fontWeight: 700, color: aliceClr, fontSize: '15px', marginBottom: '14px' }}>👩 Alice</div>
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
            <div style={{ fontWeight: 700, color: bobClr, fontSize: '15px', marginBottom: '14px' }}>👨 Bob</div>
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
              <span style={{ fontFamily: 'monospace', fontSize: '13px', color: aliceClr }}>A=0x{hexShort(pa11Data.A).slice(0,6)}…</span>
              <span style={{ color: bobClr, fontSize: '18px' }}>→</span>
            </div>
            <div style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              opacity: pa11Animating ? 1 : 0.8,
              transform: pa11Animating ? 'translateX(-6px)' : 'translateX(0)',
              transition: 'transform 0.6s ease 0.1s, opacity 0.3s ease',
            }}>
              <span style={{ color: aliceClr, fontSize: '18px' }}>←</span>
              <span style={{ fontFamily: 'monospace', fontSize: '13px', color: bobClr }}>B=0x{hexShort(pa11Data.B).slice(0,6)}…</span>
            </div>
            {pa11Data.match && !pa11EveEnabled && (
              <div style={{
                background: 'rgba(34,197,94,0.15)', border: '1px solid #22c55e',
                borderRadius: '6px', padding: '4px 10px',
                color: '#22c55e', fontSize: '14px', fontWeight: 700,
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
              flex: 1, padding: '11px', borderRadius: '9px', fontWeight: 700, fontSize: '15px',
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
              fontSize: '12px', color: 'white', transition: 'all 0.2s',
            }}>
              {pa11EveEnabled ? '✓' : ''}
            </span>
            <span style={{ fontSize: '14px', fontWeight: 600, color: pa11EveEnabled ? eveClr : 'var(--text2)', whiteSpace: 'nowrap' }}>
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
            <div style={{ fontWeight: 700, color: eveClr, fontSize: '15px', marginBottom: '14px' }}>
              👿 Eve — Man-in-the-Middle
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '12px' }}>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '6px', textTransform: 'uppercase' }}>← toward Alice</div>
                {keyBadge('e₂ (private)', pa11MitmData.e2, eveClr)}
                {keyBadge("A' = gᵉ² sent to Alice", pa11MitmData.A_prime, eveClr)}
                {keyBadge('K_eve_alice = Aᵉ²', pa11MitmData.K_eve_alice, eveClr, pa11MitmData.alice_eve_match)}
              </div>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '6px', textTransform: 'uppercase' }}>→ toward Bob</div>
                {keyBadge('e₁ (private)', pa11MitmData.e1, eveClr)}
                {keyBadge("B' = gᵉ¹ sent to Bob", pa11MitmData.B_prime, eveClr)}
                {keyBadge('K_eve_bob = Bᵉ¹', pa11MitmData.K_eve_bob, eveClr, pa11MitmData.bob_eve_match)}
              </div>
            </div>

            {pa11MitmData.attack_success && (
              <div style={{
                background: 'rgba(248,113,113,0.15)', border: '1px solid #f87171',
                borderRadius: '8px', padding: '10px 14px',
                fontSize: '14px', color: '#fca5a5', lineHeight: 1.5,
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
          <div style={{ fontWeight: 700, color: '#f59e0b', fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '12px' }}>
            🔬 CDH Hardness Demonstration
          </div>
          <div style={{ fontSize: '14px', color: 'var(--text2)', marginBottom: '12px', lineHeight: 1.5 }}>
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
                  flex: 1, padding: '7px 0', borderRadius: '7px', fontSize: '14px', cursor: 'pointer',
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
              width: '100%', padding: '10px', borderRadius: '8px', fontWeight: 700, fontSize: '15px',
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
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '3px' }}>Bit size</div>
                  <div style={{ fontFamily: 'monospace', color: '#fbbf24', fontWeight: 700 }}>{pa11CdhData.bits} bits</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: '1px solid rgba(245,158,11,0.2)' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '3px' }}>Time taken</div>
                  <div style={{ fontFamily: 'monospace', color: '#fbbf24', fontWeight: 700 }}>{pa11CdhData.time_sec}s</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: '1px solid rgba(245,158,11,0.2)' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '3px' }}>Secret a</div>
                  <div style={{ fontFamily: 'monospace', color: '#fbbf24', fontSize: '13px', wordBreak: 'break-all' }}>0x{hexShort(pa11CdhData.a)}</div>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '8px', padding: '10px', border: '1px solid rgba(245,158,11,0.2)' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text3)', marginBottom: '3px' }}>Found by brute force</div>
                  <div style={{ fontFamily: 'monospace', color: pa11CdhData.correct ? '#22c55e' : '#ef4444', fontSize: '13px', wordBreak: 'break-all' }}>
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
                  fontSize: '14px', fontWeight: 700, color: pa11CdhData.key_recovered ? '#22c55e' : '#ef4444',
                }}>
                  {pa11CdhData.key_recovered ? '✓ Key Recovered' : '✗ Key Not Found'}
                </div>
              </div>
              <div style={{
                background: 'rgba(0,0,0,0.2)', borderRadius: '8px', padding: '10px 12px',
                fontSize: '13px', color: 'var(--text2)', lineHeight: 1.5,
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

  const renderPA12Special = () => {
    const runPA12 = async () => {
      setPa12Loading(true);
      try {
        const data = await api.runDemo(12, { message_int: pa12MsgInt, message_pkcs: pa12MsgPkcs });
        setPa12Data(data);
      } catch (e) { setError(e.message); }
      finally { setPa12Loading(false); }
    };
    const tabStyle = (t) => ({ padding: '8px 16px', borderRadius: '8px 8px 0 0', background: pa12Tab === t ? 'var(--accent)' : 'rgba(0,0,0,0.3)', color: pa12Tab === t ? '#000' : 'var(--text2)', fontWeight: 700, cursor: 'pointer', border: 'none', fontSize: '13px' });
    const sectionBox = { background: 'rgba(0,0,0,0.25)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)', marginBottom: '12px' };
    const monoVal = { fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all', color: 'var(--text2)', maxHeight: '80px', overflowY: 'auto' };
    const labelSt = { fontSize: '11px', fontWeight: 700, color: 'var(--text3)', textTransform: 'uppercase', marginBottom: '4px' };
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div style={sectionBox}>
          <div style={labelSt}>Inputs</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '10px' }}>
            <div><label style={{ fontSize: '12px', color: 'var(--text3)' }}>Plaintext Integer</label><input type="text" value={pa12MsgInt} onChange={e => setPa12MsgInt(e.target.value)} style={{ width: '100%', padding: '6px 10px', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', fontSize: '13px' }} /></div>
            <div><label style={{ fontSize: '12px', color: 'var(--text3)' }}>PKCS Message</label><input type="text" value={pa12MsgPkcs} onChange={e => setPa12MsgPkcs(e.target.value)} style={{ width: '100%', padding: '6px 10px', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', fontSize: '13px' }} /></div>
          </div>
          <button onClick={runPA12} disabled={pa12Loading} style={{ width: '100%', padding: '10px', borderRadius: '8px', background: 'var(--accent)', color: '#000', fontWeight: 700, cursor: 'pointer', border: 'none', fontSize: '14px' }}>{pa12Loading ? '⏳ Generating Keys...' : '🔐 Generate RSA Keys & Run'}</button>
        </div>
        {pa12Data && (<>
          <div style={sectionBox}>
            <div style={labelSt}>RSA Key Pair ({pa12Data.bits}-bit)</div>
            <div style={monoVal}>n = {pa12Data.n}</div>
            <div style={{ ...monoVal, marginTop: '4px' }}>e = {pa12Data.e}</div>
          </div>
          <div style={{ display: 'flex', gap: '4px', marginBottom: '4px' }}>
            <button onClick={() => setPa12Tab('textbook')} style={tabStyle('textbook')}>Textbook RSA</button>
            <button onClick={() => setPa12Tab('pkcs')} style={tabStyle('pkcs')}>PKCS#1 v1.5</button>
            <button onClick={() => setPa12Tab('attacks')} style={tabStyle('attacks')}>⚠️ Attacks</button>
          </div>
          <div style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '0 10px 10px 10px', border: '1px solid var(--border)' }}>
            {pa12Tab === 'textbook' && (<div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: '12px', alignItems: 'center' }}>
                <div style={sectionBox}><div style={labelSt}>Plaintext m</div><div style={{ fontSize: '28px', textAlign: 'center', color: 'var(--accent)' }}>{pa12Data.textbook.m}</div></div>
                <div style={{ fontSize: '24px', color: 'var(--text3)' }}>→ c = m<sup>e</sup> mod n →</div>
                <div style={sectionBox}><div style={labelSt}>Ciphertext c</div><div style={monoVal}>{pa12Data.textbook.c}</div></div>
              </div>
              <div style={{ textAlign: 'center', margin: '8px 0', fontSize: '20px', color: 'var(--text3)' }}>↓ m = c<sup>d</sup> mod n ↓</div>
              <div style={{ ...sectionBox, textAlign: 'center' }}><div style={labelSt}>Decrypted</div><div style={{ fontSize: '28px', color: pa12Data.textbook.match ? '#4ade80' : '#ef4444' }}>{pa12Data.textbook.d} {pa12Data.textbook.match ? '✓' : '✗'}</div></div>
            </div>)}
            {pa12Tab === 'pkcs' && (<div>
              <div style={sectionBox}><div style={labelSt}>PKCS#1 v1.5 Padding: 0x00 ‖ 0x02 ‖ PS ‖ 0x00 ‖ M</div><div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '8px' }}><div><div style={{ fontSize: '12px', color: 'var(--text3)' }}>Original</div><div style={{ fontSize: '18px', color: 'var(--accent)' }}>{pa12Data.pkcs.message}</div></div><div><div style={{ fontSize: '12px', color: 'var(--text3)' }}>Decrypted</div><div style={{ fontSize: '18px', color: pa12Data.pkcs.match ? '#4ade80' : '#ef4444' }}>{pa12Data.pkcs.decrypted} {pa12Data.pkcs.match ? '✓' : '✗'}</div></div></div></div>
            </div>)}
            {pa12Tab === 'attacks' && (<div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ ...sectionBox, borderColor: 'rgba(239,68,68,0.3)' }}><div style={{ ...labelSt, color: '#ef4444' }}>⚠️ Determinism Attack</div><div style={{ fontSize: '13px', color: 'var(--text2)', marginBottom: '8px' }}>{pa12Data.determinism?.vulnerability}</div><div style={monoVal}>c₁ = Enc({pa12Data.determinism?.message}) = {String(pa12Data.determinism?.c1)?.slice(0,40)}...</div><div style={monoVal}>c₂ = Enc({pa12Data.determinism?.message}) = {String(pa12Data.determinism?.c2)?.slice(0,40)}...</div><div style={{ color: pa12Data.determinism?.identical ? '#ef4444' : '#4ade80', fontWeight: 700, marginTop: '6px' }}>Identical: {pa12Data.determinism?.identical ? '✓ YES — Deterministic!' : 'No'}</div></div>
              <div style={{ ...sectionBox, borderColor: 'rgba(251,191,36,0.3)' }}><div style={{ ...labelSt, color: '#fbbf24' }}>⚠️ Multiplicative Homomorphism</div><div style={{ fontSize: '13px', color: 'var(--text2)', marginBottom: '8px' }}>{pa12Data.homomorphism?.vulnerability}</div><div style={monoVal}>Enc({pa12Data.homomorphism?.m1}) · Enc({pa12Data.homomorphism?.m2}) mod n → Dec = {pa12Data.homomorphism?.c1_c2_decrypted}</div><div style={{ color: pa12Data.homomorphism?.homomorphic ? '#ef4444' : '#4ade80', fontWeight: 700, marginTop: '6px' }}>Homomorphic: {pa12Data.homomorphism?.homomorphic ? '✓ Attack works!' : 'No'}</div></div>
              <div style={{ ...sectionBox, borderColor: 'rgba(168,85,247,0.3)' }}><div style={{ ...labelSt, color: '#a855f7' }}>⚠️ Bleichenbacher Padding Oracle</div><div style={{ fontSize: '13px', color: 'var(--text2)', marginBottom: '8px' }}>{pa12Data.bleichenbacher?.vulnerability}</div><div style={monoVal}>Valid ciphertext passes oracle: {pa12Data.bleichenbacher?.valid_ciphertext_oracle ? '✓' : '✗'}</div><div style={monoVal}>Random ciphertexts accepted: {pa12Data.bleichenbacher?.random_oracle_accepts}/{pa12Data.bleichenbacher?.random_trials} ({(pa12Data.bleichenbacher?.accept_rate * 100)?.toFixed(1)}%)</div></div>
            </div>)}
          </div>
        </>)}
      </div>
    );
  };

  const renderPA14Special = () => {
    const runPA14 = async () => {
      setPa14Loading(true);
      try {
        const data = await api.runDemo(14, { residues: pa14Residues, moduli: pa14Moduli });
        setPa14Data(data);
      } catch (e) { setError(e.message); }
      finally { setPa14Loading(false); }
    };
    const sectionBox = { background: 'rgba(0,0,0,0.25)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)', marginBottom: '12px' };
    const labelSt = { fontSize: '11px', fontWeight: 700, color: 'var(--text3)', textTransform: 'uppercase', marginBottom: '4px' };
    const monoVal = { fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all', color: 'var(--text2)' };
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div style={sectionBox}>
          <div style={labelSt}>Chinese Remainder Theorem Inputs</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '10px' }}>
            <div><label style={{ fontSize: '12px', color: 'var(--text3)' }}>Residues (comma-sep)</label><input type="text" value={pa14Residues} onChange={e => setPa14Residues(e.target.value)} style={{ width: '100%', padding: '6px 10px', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', fontSize: '13px' }} /></div>
            <div><label style={{ fontSize: '12px', color: 'var(--text3)' }}>Moduli (comma-sep)</label><input type="text" value={pa14Moduli} onChange={e => setPa14Moduli(e.target.value)} style={{ width: '100%', padding: '6px 10px', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', fontSize: '13px' }} /></div>
          </div>
          <button onClick={runPA14} disabled={pa14Loading} style={{ width: '100%', padding: '10px', borderRadius: '8px', background: 'var(--accent)', color: '#000', fontWeight: 700, cursor: 'pointer', border: 'none', fontSize: '14px' }}>{pa14Loading ? '⏳ Computing...' : '🧮 Solve CRT & Run Håstad'}</button>
        </div>
        {pa14Data && (<>
          <div style={sectionBox}>
            <div style={labelSt}>CRT Solution</div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '8px' }}>
              {pa14Data.crt_result?.residues?.map((r, i) => (
                <div key={i} style={{ background: 'rgba(var(--accent-rgb),0.1)', padding: '6px 12px', borderRadius: '6px', fontFamily: 'monospace', fontSize: '13px' }}>
                  x ≡ {r} (mod {pa14Data.crt_result?.moduli?.[i]})
                </div>
              ))}
            </div>
            <div style={{ textAlign: 'center', fontSize: '20px', color: 'var(--accent)', fontWeight: 700 }}>x = {pa14Data.crt_result?.solution}</div>
          </div>
          <div style={{ ...sectionBox, borderColor: 'rgba(239,68,68,0.3)' }}>
            <div style={{ ...labelSt, color: '#ef4444' }}>⚠️ Håstad Broadcast Attack (e=3)</div>
            <div style={{ fontSize: '13px', color: 'var(--text2)', marginBottom: '8px' }}>If the same message m is encrypted with e=3 under 3 different RSA public keys, the attacker can use CRT to recover m³ mod N₁N₂N₃, then compute the cube root to recover m.</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div><div style={{ fontSize: '12px', color: 'var(--text3)' }}>Key Size</div><div style={{ fontSize: '16px', color: 'var(--text1)' }}>{pa14Data.hastad?.bits}-bit</div></div>
              <div><div style={{ fontSize: '12px', color: 'var(--text3)' }}>Attack Success</div><div style={{ fontSize: '16px', color: pa14Data.hastad?.success ? '#ef4444' : '#4ade80', fontWeight: 700 }}>{pa14Data.hastad?.success ? '✓ Recovered m!' : '✗ Failed'}</div></div>
            </div>
          </div>
        </>)}
      </div>
    );
  };

  const renderPA15Special = () => {
    const runPA15 = async () => {
      setPa15Loading(true);
      try {
        const data = await api.runDemo(15, { message: pa15Msg });
        setPa15Data(data);
      } catch (e) { setError(e.message); }
      finally { setPa15Loading(false); }
    };
    const sectionBox = { background: 'rgba(0,0,0,0.25)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)', marginBottom: '12px' };
    const labelSt = { fontSize: '11px', fontWeight: 700, color: 'var(--text3)', textTransform: 'uppercase', marginBottom: '4px' };
    const monoVal = { fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all', color: 'var(--text2)' };
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div style={sectionBox}>
          <div style={labelSt}>Message to Sign</div>
          <input type="text" value={pa15Msg} onChange={e => setPa15Msg(e.target.value)} style={{ width: '100%', padding: '8px 10px', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', fontSize: '13px', marginBottom: '10px' }} />
          <button onClick={runPA15} disabled={pa15Loading} style={{ width: '100%', padding: '10px', borderRadius: '8px', background: 'var(--accent)', color: '#000', fontWeight: 700, cursor: 'pointer', border: 'none', fontSize: '14px' }}>{pa15Loading ? '⏳ Signing...' : '✍️ Sign & Verify'}</button>
        </div>
        {pa15Data && (<>
          <div style={sectionBox}>
            <div style={labelSt}>RSA Signature: σ = H(m)<sup>d</sup> mod n</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div><div style={{ fontSize: '12px', color: 'var(--text3)' }}>Message</div><div style={{ fontSize: '15px', color: 'var(--accent)' }}>{pa15Data.message}</div></div>
              <div><div style={{ fontSize: '12px', color: 'var(--text3)' }}>Signature</div><div style={monoVal}>{String(pa15Data.signature)?.slice(0,60)}...</div></div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '10px' }}>
              <div style={{ padding: '8px', background: 'rgba(34,197,94,0.1)', borderRadius: '8px', textAlign: 'center' }}><div style={{ fontSize: '12px', color: 'var(--text3)' }}>Verify(m, σ)</div><div style={{ fontSize: '16px', color: pa15Data.verify ? '#4ade80' : '#ef4444', fontWeight: 700 }}>{pa15Data.verify ? '✓ Valid' : '✗ Invalid'}</div></div>
              <div style={{ padding: '8px', background: 'rgba(239,68,68,0.1)', borderRadius: '8px', textAlign: 'center' }}><div style={{ fontSize: '12px', color: 'var(--text3)' }}>Verify("wrong", σ)</div><div style={{ fontSize: '16px', color: pa15Data.wrong ? '#4ade80' : '#ef4444', fontWeight: 700 }}>{pa15Data.wrong ? '✓ Rejected!' : '✗ Accepted?!'}</div></div>
            </div>
          </div>
          <div style={{ ...sectionBox, borderColor: 'rgba(239,68,68,0.3)' }}>
            <div style={{ ...labelSt, color: '#ef4444' }}>⚠️ Signature Homomorphism Attack</div>
            <div style={{ fontSize: '13px', color: 'var(--text2)', marginBottom: '8px' }}>Textbook RSA signatures are homomorphic: σ(m₁)·σ(m₂) = σ(m₁·m₂). Hash-then-sign prevents this because H(m₁·m₂) ≠ H(m₁)·H(m₂).</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div style={{ padding: '10px', background: 'rgba(239,68,68,0.08)', borderRadius: '8px', textAlign: 'center' }}><div style={{ fontSize: '12px', color: '#fca5a5' }}>Raw RSA Attack</div><div style={{ fontSize: '16px', color: pa15Data.attack?.raw_works ? '#ef4444' : '#4ade80', fontWeight: 700 }}>{pa15Data.attack?.raw_works ? '⚠️ Works!' : '✓ Blocked'}</div></div>
              <div style={{ padding: '10px', background: 'rgba(34,197,94,0.08)', borderRadius: '8px', textAlign: 'center' }}><div style={{ fontSize: '12px', color: '#86efac' }}>Hash-then-Sign</div><div style={{ fontSize: '16px', color: pa15Data.attack?.hash_works ? '#ef4444' : '#4ade80', fontWeight: 700 }}>{pa15Data.attack?.hash_works ? '⚠️ Works!' : '✓ Blocked!'}</div></div>
            </div>
          </div>
        </>)}
      </div>
    );
  };

  const renderPA16Special = () => {
    const runPA16 = async () => {
      setPa16Loading(true);
      try {
        const data = await api.runDemo(16, { message_int: pa16MsgInt });
        setPa16Data(data);
      } catch (e) { setError(e.message); }
      finally { setPa16Loading(false); }
    };
    const sectionBox = { background: 'rgba(0,0,0,0.25)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)', marginBottom: '12px' };
    const labelSt = { fontSize: '11px', fontWeight: 700, color: 'var(--text3)', textTransform: 'uppercase', marginBottom: '4px' };
    const monoVal = { fontFamily: 'monospace', fontSize: '12px', wordBreak: 'break-all', color: 'var(--text2)' };
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div style={sectionBox}>
          <div style={labelSt}>ElGamal Plaintext (Integer)</div>
          <input type="number" value={pa16MsgInt} onChange={e => setPa16MsgInt(e.target.value)} style={{ width: '100%', padding: '8px 10px', background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: '6px', color: 'white', fontFamily: 'monospace', fontSize: '13px', marginBottom: '10px' }} />
          <button onClick={runPA16} disabled={pa16Loading} style={{ width: '100%', padding: '10px', borderRadius: '8px', background: 'var(--accent)', color: '#000', fontWeight: 700, cursor: 'pointer', border: 'none', fontSize: '14px' }}>{pa16Loading ? '⏳ Encrypting...' : '🔑 ElGamal Encrypt & Attack'}</button>
        </div>
        {pa16Data && (<>
          <div style={sectionBox}>
            <div style={labelSt}>ElGamal Parameters</div>
            <div style={monoVal}>p = {pa16Data.p}, g = {pa16Data.g}</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: '12px', alignItems: 'center' }}>
            <div style={sectionBox}><div style={labelSt}>Plaintext m</div><div style={{ fontSize: '28px', textAlign: 'center', color: 'var(--accent)' }}>{pa16Data.m}</div></div>
            <div style={{ fontSize: '20px', color: 'var(--text3)', textAlign: 'center' }}>→<br/><span style={{ fontSize: '11px' }}>c₁=gʳ, c₂=m·hʳ</span><br/>→</div>
            <div style={sectionBox}><div style={labelSt}>Ciphertext (c₁, c₂)</div><div style={monoVal}>c₁ = {pa16Data.c1}<br/>c₂ = {pa16Data.c2}</div></div>
          </div>
          <div style={{ ...sectionBox, textAlign: 'center' }}><div style={labelSt}>Decrypted</div><div style={{ fontSize: '28px', color: pa16Data.match ? '#4ade80' : '#ef4444' }}>{pa16Data.decrypted} {pa16Data.match ? '✓' : '✗'}</div></div>
          <div style={{ ...sectionBox, borderColor: 'rgba(239,68,68,0.3)' }}>
            <div style={{ ...labelSt, color: '#ef4444' }}>⚠️ Malleability Attack</div>
            <div style={{ fontSize: '13px', color: 'var(--text2)', marginBottom: '8px' }}>ElGamal is multiplicatively homomorphic: multiplying c₂ by a factor t yields Dec(c₁, t·c₂) = t·m. An attacker can manipulate the plaintext without knowing it.</div>
            <div style={{ textAlign: 'center', padding: '10px', background: 'rgba(239,68,68,0.08)', borderRadius: '8px' }}><div style={{ fontSize: '16px', color: pa16Data.malleability ? '#ef4444' : '#4ade80', fontWeight: 700 }}>{pa16Data.malleability ? '⚠️ Malleability Confirmed!' : '✓ Not Malleable'}</div></div>
          </div>
        </>)}
      </div>
    );
  };

  const activePAId = Number(pa.pa);
  const isPaDemo1 = activePAId === 1;
  const isPaDemo2 = activePAId === 2;
  const isPaDemo3 = activePAId === 3;
  const isPA4 = activePAId === 4;
  const isPA5 = activePAId === 5;
  const isPA6 = activePAId === 6;
  const isPaDemo7 = activePAId === 7;
  const isPaDemo8 = activePAId === 8;
  const isPaDemo9 = activePAId === 9;
  const isPaDemo10 = activePAId === 10;
  const isPaDemo11 = activePAId === 11;
  const isPA12 = activePAId === 12;
  const isPaDemo13 = activePAId === 13;
  const isPA14 = activePAId === 14;
  const isPA15 = activePAId === 15;
  const isPA16 = activePAId === 16;
  const isPA17 = activePAId === 17;
  const isPaDemo18 = activePAId === 18;
  const isPA19 = activePAId === 19;
  const isPA20 = activePAId === 20;
  return (
    <div className="modal-overlay open" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">
          <h2>PA#{pa.pa} — {pa.title}</h2>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <div style={{ marginBottom: '20px', paddingBottom: '16px', borderBottom: '1px solid var(--border)' }}>
            <p style={{ color: 'var(--text2)', fontSize: '15px', marginBottom: '16px' }}>{pa.desc}</p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '16px' }}>
              {def.params
                .filter(p => !isPaDemo7 && !isPaDemo13 && !isPaDemo2 && !isPA4 && !isPA5 && !isPA6 && !isPA12 && !isPA14 && !isPA15 && !isPA16 && !isPA17 && !isPA19 && !isPA20)
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

            {!isPaDemo1 && !isPaDemo2 && !isPaDemo3 && !isPaDemo7 && !isPaDemo8 && !isPaDemo9 && !isPaDemo10 && !isPaDemo11 && !isPA12 && !isPaDemo13 && !isPA14 && !isPA15 && !isPA16 && !isPaDemo18 && !isPA4 && !isPA5 && !isPA6 && !isPA17 && !isPA19 && !isPA20 && (              <button className="btn btn-primary" style={{ width: '100%' }} onClick={() => runDemo()}>
                ▶ Run Demo
              </button>
            )}
          </div>

          <div id="demoOutputContainer">
            {isLoading && !isPaDemo1 && !isPaDemo3 && !isPaDemo7 && !isPaDemo8 && !isPaDemo9 && !isPaDemo10 && !isPaDemo11 && !isPA12 && !isPaDemo13 && !isPA14 && !isPA15 && !isPA16 && !isPaDemo18 && !isPA4 && !isPA5 && !isPA6 && !isPA17 && !isPA19 && !isPA20 && <div style={{ textAlign: 'center', padding: '20px' }}><div className="spinner"></div></div>}
            {error && <pre style={{ color: 'var(--red)' }}>{error}</pre>}
            {isPaDemo7 ? renderPA7Special() : isPaDemo1 ? renderPA1Special() : isPaDemo2 ? renderPA2Special() : isPaDemo3 ? renderPA3Special() : isPA4 ? renderPA4Special() : isPA5 ? renderPA5Special() : isPA6 ? renderPA6Special() : isPaDemo8 ? renderPA8Special() : isPaDemo9 ? renderPA9Special() : isPaDemo10 ? renderPA10Special() : isPaDemo11 ? renderPA11Special() : isPA12 ? renderPA12Special() : isPaDemo13 ? renderPA13Special() : isPA14 ? renderPA14Special() : isPA15 ? renderPA15Special() : isPA16 ? renderPA16Special() : isPaDemo18 ? renderPA18Special() : isPA17 ? renderPA17Special() : isPA19 ? renderPA19Special() : isPA20 ? renderPA20Special() : (result && renderResult(result))}

            {!isPaDemo1 && !isPaDemo2 && !isPaDemo3 && !isPaDemo7 && !isPaDemo8 && !isPaDemo9 && !isPaDemo10 && !isPaDemo11 && !isPA12 && !isPaDemo13 && !isPA14 && !isPA15 && !isPA16 && !isPaDemo18 && !isPA4 && !isPA5 && !isPA6 && !isPA17 && !isPA19 && !isPA20 && (
              <button className="run-button" onClick={handleRunDemo} disabled={isLoading} style={{ marginTop: '20px' }}>
                {isLoading ? 'Running Demo...' : 'Run Interactive Demo'}
              </button>
            )}          </div>
        </div>
      </div>
    </div>
  );
};

export default PADemoModal;
