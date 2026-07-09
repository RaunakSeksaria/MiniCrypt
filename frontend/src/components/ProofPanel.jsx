import { useState } from 'react';

const ProofPanel = ({ proofData, foundation, source, target }) => {
  const [isOpen, setIsOpen] = useState(false);

  if (!proofData || !proofData.proofs) return null;

  return (
    <div className="proof-panel">
      <div className="proof-header" onClick={() => setIsOpen(!isOpen)}>
        <span>Reduction Chain & Security Proofs</span>
        <span>{isOpen ? '▲' : '▼'}</span>
      </div>
      <div className={`proof-body ${isOpen ? 'open' : ''}`}>
        <div className="proof-chain">
          <div className="proof-node">{foundation}</div>
          <div className="proof-edge">→</div>
          <div className="proof-node">{source}</div>
          <div className="proof-edge">→</div>
          <div className="proof-node">{target}</div>
        </div>
        <div id="proofItems">
          {proofData.proofs.map((p, i) => (
            <div className="proof-item" key={i}>
              <div className="theorem">{p.theorem || p.step}</div>
              <div className="security">{p.security || p.description}</div>
              {p.pa && <div className="pa-badge">{p.pa}</div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ProofPanel;
