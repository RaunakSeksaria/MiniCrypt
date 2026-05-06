import React, { useState } from 'react';

const Explorer = ({ foundation, api }) => {
  const [source, setSource] = useState('PRF');
  const [target, setTarget] = useState('PRP');
  const [seed, setSeed] = useState('2b7e151628aed2a6abf7158809cf4f3c');
  const [query, setQuery] = useState('00000000000000000000000000000001');
  
  const [buildSteps, setBuildSteps] = useState([]);
  const [buildResult, setBuildResult] = useState(null);
  const [isBuilding, setIsBuilding] = useState(false);
  
  const [reduceSteps, setReduceSteps] = useState([]);
  const [reduceResult, setReduceResult] = useState(null);
  const [isReducing, setIsReducing] = useState(false);
  const [reduceError, setReduceError] = useState(null);

  const runBuild = async () => {
    setIsBuilding(true);
    setBuildResult(null);
    try {
      const data = await api.build({ foundation, source, seed });
      setBuildSteps(data.steps || []);
      setBuildResult({ source: data.source, foundation: data.foundation, value: data.result });
    } catch (e) {
      console.error(e);
    } finally {
      setIsBuilding(false);
    }
  };

  const runReduce = async () => {
    setIsReducing(true);
    setReduceResult(null);
    setReduceError(null);
    try {
      const data = await api.reduce({ foundation, source, target, seed, query });
      if (data.error) {
        setReduceError(data.error);
      } else {
        setReduceSteps(data.steps || []);
        setReduceResult(data.output);
        // We might want to pass the proof data up to the parent App
        if (api.onProofUpdate) api.onProofUpdate(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsReducing(false);
    }
  };

  const swapDirection = () => {
    setSource(target);
    setTarget(source);
  };

  const renderStepList = (steps) => (
    steps.map((s, i) => (
      <React.Fragment key={i}>
        <div className="step" style={{ animationDelay: `${i * 0.1}s` }}>
          <div>
            <div className="fn">{s.fn}</div>
            <div className="vals">
              In: {s.input}<br />
              Out: <span>{s.output}</span>
            </div>
          </div>
        </div>
        {i < steps.length - 1 && <div className="step-arrow">↓</div>}
      </React.Fragment>
    ))
  );

  return (
    <div className="main">
      {/* Column 1: Build */}
      <div className="panel">
        <div className="panel-header">
          <h2>⚡ Build Source Primitive <span className="badge">Leg 1</span></h2>
        </div>
        <div className="panel-body">
          <div className="field">
            <label>Source Primitive A</label>
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="OWF">OWF — One-Way Function</option>
              <option value="PRG">PRG — Pseudorandom Generator</option>
              <option value="PRF">PRF — Pseudorandom Function</option>
              <option value="PRP">PRP — Pseudorandom Permutation</option>
              <option value="MAC">MAC — Message Auth Code</option>
              <option value="CRHF">CRHF — Collision-Resistant Hash</option>
              <option value="HMAC">HMAC</option>
            </select>
          </div>
          <div className="field">
            <label>Input Seed (hex)</label>
            <input 
              type="text" 
              value={seed} 
              onChange={(e) => setSeed(e.target.value)} 
              placeholder="e.g. 2b7e..." 
            />
          </div>
          <button className="btn btn-primary" onClick={runBuild} style={{ width: '100%', marginBottom: '16px' }}>
            {isBuilding ? <div className="spinner"></div> : 'Build →'}
          </button>
          <div className="steps-container">
            {renderStepList(buildSteps)}
          </div>
          {buildResult && (
            <div className="result">
              <div className="label">{buildResult.source} Output ({buildResult.foundation})</div>
              <div className="value">{buildResult.value}</div>
            </div>
          )}
        </div>
      </div>

      {/* Column 2: Reduce */}
      <div className="panel">
        <div className="panel-header">
          <h2>🔄 Reduce to Target <span className="badge">Leg 2</span></h2>
        </div>
        <div className="panel-body">
          <div className="field">
            <label>Target Primitive B</label>
            <select value={target} onChange={(e) => setTarget(e.target.value)}>
              <option value="OWF">OWF</option>
              <option value="PRG">PRG</option>
              <option value="PRF">PRF</option>
              <option value="PRP">PRP</option>
              <option value="MAC">MAC</option>
              <option value="CRHF">CRHF</option>
              <option value="HMAC">HMAC</option>
            </select>
          </div>
          <div className="field">
            <label>Query x (hex)</label>
            <input 
              type="text" 
              value={query} 
              onChange={(e) => setQuery(e.target.value)} 
              placeholder="e.g. 0000..." 
            />
          </div>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
            <button className="btn btn-primary" onClick={runReduce} style={{ flex: 1 }}>
              {isReducing ? <div className="spinner"></div> : 'Reduce →'}
            </button>
            <button className="btn btn-ghost" onClick={swapDirection}>⇄ Swap</button>
          </div>
          
          {reduceError && (
            <div style={{ color: 'var(--amber)', padding: '12px', background: 'var(--bg)', borderRadius: '8px' }}>
              ⚠️ {reduceError}
            </div>
          )}
          
          <div className="steps-container">
            {renderStepList(reduceSteps)}
          </div>
          
          {reduceResult && (
            <div className="result">
              <div className="label">Final Output</div>
              <div className="value">{reduceResult}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Explorer;
