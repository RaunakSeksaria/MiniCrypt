import React from 'react';

const PAS = [
  {pa:1,title:"OWF & PRG",desc:"DLP/AES OWFs, HILL PRG construction",phase:1},
  {pa:2,title:"PRF (GGM Tree)",desc:"GGM tree PRF, distinguishing game",phase:1},
  {pa:3,title:"CPA-Secure Encryption",desc:"Randomized encryption, IND-CPA game",phase:2},
  {pa:4,title:"Modes of Operation",desc:"CBC, OFB, CTR modes with attack demos",phase:2},
  {pa:5,title:"MACs",desc:"PRF-MAC, CBC-MAC, EUF-CMA game",phase:2},
  {pa:6,title:"CCA-Secure Encryption",desc:"Encrypt-then-MAC, malleability demo",phase:2},
  {pa:7,title:"Merkle-Damgård",desc:"Generic hash framework with trace",phase:3},
  {pa:8,title:"DLP-CRHF",desc:"g^x·h^y mod p hash function",phase:3},
  {pa:9,title:"Birthday Attack",desc:"Collision finding on toy hashes",phase:3},
  {pa:10,title:"HMAC",desc:"HMAC, Encrypt-then-HMAC, timing demo",phase:3},
  {pa:11,title:"Diffie-Hellman",desc:"Key exchange, MITM attack",phase:4},
  {pa:12,title:"RSA",desc:"Textbook RSA, PKCS#1 v1.5, Bleichenbacher",phase:4},
  {pa:13,title:"Miller-Rabin",desc:"Primality testing, prime generation",phase:4},
  {pa:14,title:"CRT & Håstad",desc:"CRT, RSA CRT speedup, broadcast attack",phase:4},
  {pa:15,title:"Digital Signatures",desc:"RSA signatures, homomorphism attack",phase:4},
  {pa:16,title:"ElGamal",desc:"PKC, malleability attack",phase:4},
  {pa:17,title:"CCA-Secure PKC",desc:"Encrypt-then-Sign, IND-CCA2",phase:5},
  {pa:18,title:"Oblivious Transfer",desc:"1-out-of-2 OT (Bellare-Micali)",phase:5},
  {pa:19,title:"Secure AND",desc:"AND/XOR/NOT gates via OT",phase:5},
  {pa:20,title:"2-Party MPC",desc:"Circuits: comparator, equality, adder",phase:5},
];

const phaseClass = {1:'pa-phase1',2:'pa-phase2',3:'pa-phase3',4:'pa-phase4',5:'pa-phase5'};
const phaseNames = {1:'Foundation',2:'Symmetric',3:'Hashing',4:'Public-Key',5:'MPC'};

const Demos = ({ onSelectPA }) => {
  return (
    <div className="main single">
      <div className="demo-grid">
        {PAS.map(p => (
          <div 
            key={p.pa} 
            className={`demo-card ${phaseClass[p.phase]}`} 
            onClick={() => onSelectPA(p)}
          >
            <div className="card-header">
              <h3>{p.title}</h3>
              <span className="pa-num">Module {p.pa}</span>
            </div>
            <div className="card-body">
              {p.desc}<br />
              <small style={{ color: 'var(--text3)' }}>
                {phaseNames[p.phase]}
              </small>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Demos;
export { PAS };
