import React, { useState } from 'react';
import Header from './components/Header';
import Nav from './components/Nav';
import Explorer from './components/Explorer';
import Demos from './components/Demos';
import DependencyGraph from './components/DependencyGraph';
import ProofPanel from './components/ProofPanel';
import PADemoModal from './components/PADemoModal';
import api from './api';
import './App.css';

function App() {
  const [foundation, setFoundation] = useState('AES');
  const [activeTab, setActiveTab] = useState('explorer');
  const [selectedPA, setSelectedPA] = useState(null);
  const [proofData, setProofData] = useState(null);
  const [reductionState, setReductionState] = useState({ source: 'PRF', target: 'PRP' });

  // Connect API to local state for proof updates
  api.onProofUpdate = (data) => {
    setProofData(data);
    setReductionState({ source: data.source || 'PRF', target: data.target || 'PRP' });
  };

  return (
    <div className="app-container">
      <Header foundation={foundation} setFoundation={setFoundation} />
      <Nav activeTab={activeTab} setActiveTab={setActiveTab} />

      <main className="content">
        {activeTab === 'explorer' && (
          <>
            <Explorer foundation={foundation} api={api} />
            <ProofPanel 
              proofData={proofData} 
              foundation={foundation} 
              source={reductionState.source} 
              target={reductionState.target} 
            />
          </>
        )}

        {activeTab === 'demos' && (
          <Demos onSelectPA={setSelectedPA} />
        )}

        {activeTab === 'graph' && (
          <DependencyGraph />
        )}
      </main>

      {selectedPA && (
        <PADemoModal 
          pa={selectedPA} 
          onClose={() => setSelectedPA(null)} 
          api={api} 
        />
      )}
    </div>
  );
}

export default App;
