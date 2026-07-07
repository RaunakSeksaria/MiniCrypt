import React from 'react';

const Header = ({ foundation, setFoundation }) => {
  return (
    <header className="header">
      <div className="logo">
        <div className="logo-icon">M</div>
        <div>
          <h1>MiniCrypt Explorer</h1>
          <span>Cryptographic primitives &amp; reductions, from scratch</span>
        </div>
      </div>
      <div className="foundation-toggle">
        <button 
          className={foundation === 'AES' ? 'active' : ''} 
          onClick={() => setFoundation('AES')}
        >
          AES-128 (PRP)
        </button>
        <button 
          className={foundation === 'DLP' ? 'active' : ''} 
          onClick={() => setFoundation('DLP')}
        >
          DLP (g<sup>x</sup> mod p)
        </button>
      </div>
    </header>
  );
};

export default Header;
