import React, { useEffect, useRef } from 'react';

const nodes = [
  {id:'AES',x:100,y:50,c:'#6366f1'},{id:'OWF/PRG',x:100,y:150,c:'#6366f1'},
  {id:'PRF/GGM',x:100,y:250,c:'#6366f1'},{id:'Miller-Rabin',x:450,y:50,c:'#22c55e'},
  {id:'CPA-Enc',x:250,y:350,c:'#06b6d4'},{id:'Modes',x:50,y:350,c:'#06b6d4'},
  {id:'MAC',x:250,y:250,c:'#06b6d4'},{id:'CCA-Enc',x:250,y:450,c:'#06b6d4'},
  {id:'Merkle-Damgård',x:450,y:250,c:'#f59e0b'},{id:'DLP-CRHF',x:450,y:350,c:'#f59e0b'},
  {id:'Birthday',x:600,y:350,c:'#f59e0b'},{id:'HMAC',x:450,y:450,c:'#f59e0b'},
  {id:'DH',x:600,y:150,c:'#22c55e'},{id:'RSA',x:750,y:150,c:'#22c55e'},
  {id:'CRT',x:750,y:250,c:'#22c55e'},{id:'Signatures',x:750,y:350,c:'#22c55e'},
  {id:'ElGamal',x:600,y:250,c:'#22c55e'},{id:'CCA-PKC',x:700,y:450,c:'#ef4444'},
  {id:'OT',x:600,y:450,c:'#ef4444'},{id:'Secure AND',x:600,y:530,c:'#ef4444'},
  {id:'MPC',x:750,y:530,c:'#ef4444'},
];

const edges = [
  ['AES','OWF/PRG'],['OWF/PRG','PRF/GGM'],['AES','PRF/GGM'],
  ['PRF/GGM','CPA-Enc'],['AES','Modes'],['PRF/GGM','MAC'],
  ['CPA-Enc','CCA-Enc'],['MAC','CCA-Enc'],
  ['Merkle-Damgård','DLP-CRHF'],['Miller-Rabin','DLP-CRHF'],
  ['DLP-CRHF','HMAC'],['CPA-Enc','HMAC'],
  ['Miller-Rabin','DH'],['Miller-Rabin','RSA'],
  ['RSA','CRT'],['RSA','Signatures'],['DLP-CRHF','Signatures'],
  ['DH','ElGamal'],['ElGamal','CCA-PKC'],['Signatures','CCA-PKC'],
  ['ElGamal','OT'],['OT','Secure AND'],['Secure AND','MPC'],
];

const DependencyGraph = () => {
  const nodeMap = {};
  nodes.forEach(n => nodeMap[n.id] = n);

  return (
    <div className="main single">
      <div className="panel">
        <div className="panel-header"><h2>Dependency Graph</h2></div>
        <div className="panel-body" style={{ textAlign: 'center' }}>
          <svg viewBox="0 0 900 620" style={{ width: '100%', maxWidth: '900px', height: 'auto' }}>
            <defs>
              <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                <polygon points="0 0, 8 3, 0 6" fill="#475569" />
              </marker>
            </defs>
            {edges.map(([from, to], i) => {
              const a = nodeMap[from];
              const b = nodeMap[to];
              if (!a || !b) return null;
              return (
                <line 
                  key={i}
                  x1={a.x + 50} y1={a.y + 20} 
                  x2={b.x + 50} y2={b.y} 
                  stroke="#334155" strokeWidth="1.5" 
                  markerEnd="url(#arrowhead)" 
                />
              );
            })}
            {nodes.map((n, i) => {
              const lines = n.id.split('\n');
              return (
                <React.Fragment key={i}>
                  <rect 
                    x={n.x} y={n.y} 
                    width="100" height={lines.length > 1 ? 40 : 30} 
                    rx="8" fill={`${n.c}22`} stroke={n.c} strokeWidth="1.5" 
                  />
                  {lines.map((line, j) => (
                    <text 
                      key={j}
                      x={n.x + 50} y={n.y + 14 + j * 16} 
                      textAnchor="middle" fill={n.c} 
                      fontSize="11" fontWeight="600" 
                      fontFamily="Inter,sans-serif"
                    >
                      {line}
                    </text>
                  ))}
                </React.Fragment>
              );
            })}
          </svg>
        </div>
      </div>
    </div>
  );
};

export default DependencyGraph;
