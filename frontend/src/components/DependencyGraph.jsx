import React, { useEffect, useRef } from 'react';

const nodes = [
  {id:'AES',x:100,y:50,c:'#6366f1'},{id:'PA#1\nOWF/PRG',x:100,y:150,c:'#6366f1'},
  {id:'PA#2\nPRF/GGM',x:100,y:250,c:'#6366f1'},{id:'PA#13\nMiller-Rabin',x:450,y:50,c:'#22c55e'},
  {id:'PA#3\nCPA-Enc',x:250,y:350,c:'#06b6d4'},{id:'PA#4\nModes',x:50,y:350,c:'#06b6d4'},
  {id:'PA#5\nMAC',x:250,y:250,c:'#06b6d4'},{id:'PA#6\nCCA-Enc',x:250,y:450,c:'#06b6d4'},
  {id:'PA#7\nMerkle-Damgård',x:450,y:250,c:'#f59e0b'},{id:'PA#8\nDLP-CRHF',x:450,y:350,c:'#f59e0b'},
  {id:'PA#9\nBirthday',x:600,y:350,c:'#f59e0b'},{id:'PA#10\nHMAC',x:450,y:450,c:'#f59e0b'},
  {id:'PA#11\nDH',x:600,y:150,c:'#22c55e'},{id:'PA#12\nRSA',x:750,y:150,c:'#22c55e'},
  {id:'PA#14\nCRT',x:750,y:250,c:'#22c55e'},{id:'PA#15\nSignatures',x:750,y:350,c:'#22c55e'},
  {id:'PA#16\nElGamal',x:600,y:250,c:'#22c55e'},{id:'PA#17\nCCA-PKC',x:700,y:450,c:'#ef4444'},
  {id:'PA#18\nOT',x:600,y:450,c:'#ef4444'},{id:'PA#19\nSecure AND',x:600,y:530,c:'#ef4444'},
  {id:'PA#20\nMPC',x:750,y:530,c:'#ef4444'},
];

const edges = [
  ['AES','PA#1\nOWF/PRG'],['PA#1\nOWF/PRG','PA#2\nPRF/GGM'],['AES','PA#2\nPRF/GGM'],
  ['PA#2\nPRF/GGM','PA#3\nCPA-Enc'],['AES','PA#4\nModes'],['PA#2\nPRF/GGM','PA#5\nMAC'],
  ['PA#3\nCPA-Enc','PA#6\nCCA-Enc'],['PA#5\nMAC','PA#6\nCCA-Enc'],
  ['PA#7\nMerkle-Damgård','PA#8\nDLP-CRHF'],['PA#13\nMiller-Rabin','PA#8\nDLP-CRHF'],
  ['PA#8\nDLP-CRHF','PA#10\nHMAC'],['PA#3\nCPA-Enc','PA#10\nHMAC'],
  ['PA#13\nMiller-Rabin','PA#11\nDH'],['PA#13\nMiller-Rabin','PA#12\nRSA'],
  ['PA#12\nRSA','PA#14\nCRT'],['PA#12\nRSA','PA#15\nSignatures'],['PA#8\nDLP-CRHF','PA#15\nSignatures'],
  ['PA#11\nDH','PA#16\nElGamal'],['PA#16\nElGamal','PA#17\nCCA-PKC'],['PA#15\nSignatures','PA#17\nCCA-PKC'],
  ['PA#16\nElGamal','PA#18\nOT'],['PA#18\nOT','PA#19\nSecure AND'],['PA#19\nSecure AND','PA#20\nMPC'],
];

const DependencyGraph = () => {
  const nodeMap = {};
  nodes.forEach(n => nodeMap[n.id] = n);

  return (
    <div className="main single">
      <div className="panel">
        <div className="panel-header"><h2>📊 Full Dependency Graph</h2></div>
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
