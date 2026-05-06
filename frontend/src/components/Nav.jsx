import React from 'react';

const Nav = ({ activeTab, setActiveTab }) => {
  return (
    <nav className="nav">
      <button 
        className={activeTab === 'explorer' ? 'active' : ''} 
        onClick={() => setActiveTab('explorer')}
      >
        🔗 Clique Explorer
      </button>
      <button 
        className={activeTab === 'demos' ? 'active' : ''} 
        onClick={() => setActiveTab('demos')}
      >
        🧪 PA Demos
      </button>
      <button 
        className={activeTab === 'graph' ? 'active' : ''} 
        onClick={() => setActiveTab('graph')}
      >
        📊 Dependency Graph
      </button>
    </nav>
  );
};

export default Nav;
