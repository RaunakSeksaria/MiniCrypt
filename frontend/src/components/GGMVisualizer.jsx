
const GGMVisualizer = ({ tree, queryBits, output }) => {
  if (!tree) return null;

  const depths = Object.keys(tree).sort((a, b) => a - b);
  const maxDepth = depths.length - 1;
  
  // Dynamic width: Bottom level nodes * 40px spacing
  const nBottom = Math.pow(2, maxDepth);
  const width = Math.max(800, nBottom * 40); 
  const height = 500;
  const nodeRadius = maxDepth > 6 ? 6 : 10;
  const levelHeight = height / (maxDepth + 1.5);

  // Helper to check if a node is on the active path
  const isActive = (depth, index) => {
    if (depth === 0) return true;
    // Walk down the query bits to see if this node's index matches
    let currentIndex = 0;
    for (let d = 1; d <= depth; d++) {
      const bit = queryBits[d - 1];
      currentIndex = currentIndex * 2 + bit;
      if (d === depth && currentIndex === index) return true;
    }
    return false;
  };

  const nodes = [];
  const lines = [];

  depths.forEach(depthStr => {
    const depth = parseInt(depthStr);
    const levelNodes = tree[depth];
    const nNodes = levelNodes.length;
    const spacing = width / nNodes;

    levelNodes.forEach((node, i) => {
      const x = spacing * i + spacing / 2;
      const y = depth * levelHeight + 30;
      const active = isActive(depth, node.index);

      nodes.push(
        <g key={`node-${depth}-${node.index}`} className="tree-node">
          <circle
            cx={x}
            cy={y}
            r={nodeRadius}
            fill={active ? 'var(--accent)' : 'var(--bg3)'}
            stroke={active ? 'var(--accent)' : 'var(--border)'}
            strokeWidth="2"
            style={{ transition: 'all 0.3s ease' }}
          />
          <title>{`Depth ${depth}, Index ${node.index}\nValue: ${node.value}`}</title>
          {depth === maxDepth && active && (
            <text
              x={x}
              y={y + 25}
              textAnchor="middle"
              fontSize="10"
              fill="var(--accent)"
              fontWeight="bold"
            >
              Fk(x)
            </text>
          )}
        </g>
      );

      if (depth < maxDepth) {
        // Draw lines to children (calculated in next iteration usually, but we can look ahead)
        const nextLevelSpacing = width / (nNodes * 2);
        const child0X = (i * 2) * nextLevelSpacing + nextLevelSpacing / 2;
        const child1X = (i * 2 + 1) * nextLevelSpacing + nextLevelSpacing / 2;
        const childY = (depth + 1) * levelHeight + 30;

        const leftActive = active && queryBits[depth] === 0;
        const rightActive = active && queryBits[depth] === 1;

        lines.push(
          <line
            key={`line-${depth}-${node.index}-L`}
            x1={x} y1={y} x2={child0X} y2={childY}
            stroke={leftActive ? 'var(--accent)' : 'var(--border)'}
            strokeWidth={leftActive ? 3 : 1}
            opacity={leftActive ? 1 : 0.3}
            style={{ transition: 'all 0.3s ease' }}
          />
        );
        lines.push(
          <line
            key={`line-${depth}-${node.index}-R`}
            x1={x} y1={y} x2={child1X} y2={childY}
            stroke={rightActive ? 'var(--accent)' : 'var(--border)'}
            strokeWidth={rightActive ? 3 : 1}
            opacity={rightActive ? 1 : 0.3}
            style={{ transition: 'all 0.3s ease' }}
          />
        );
      }
    });
  });

  return (
    <div className="ggm-visualizer animate-fade-in" style={{ 
      background: 'rgba(var(--accent-rgb), 0.02)', 
      borderRadius: '12px', 
      padding: '20px',
      border: '1px solid var(--border)',
      marginTop: '20px'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
        <h3 style={{ margin: 0 }}>GGM Tree Visualizer</h3>
        <div style={{ fontSize: '12px', color: 'var(--text3)' }}>
          Depth: <span style={{ color: 'var(--accent)', fontWeight: 600 }}>{maxDepth}</span>
        </div>
      </div>

      <div style={{ 
        overflowX: 'auto', 
        textAlign: 'center', 
        padding: '10px', 
        background: 'rgba(0,0,0,0.2)', 
        borderRadius: '8px',
        border: '1px solid var(--border)',
        maxHeight: '600px'
      }}>
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ display: 'block', margin: '0 auto' }}>
          {lines}
          {nodes}
        </svg>
      </div>

      <div style={{ 
        marginTop: '20px', 
        padding: '15px', 
        background: 'var(--bg2)', 
        borderRadius: '8px', 
        borderLeft: '4px solid var(--accent)' 
      }}>
        <div style={{ fontSize: '11px', color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px' }}>
          Final PRF Output
        </div>
        <div style={{ fontSize: '16px', fontFamily: 'monospace', fontWeight: 600, color: 'var(--accent)', wordBreak: 'break-all' }}>
          Fk(x) = {output}
        </div>
      </div>
      
      <div style={{ marginTop: '12px', fontSize: '11px', color: 'var(--text3)', fontStyle: 'italic' }}>
        The highlighted path shows the route determined by the bits of x. Hover over nodes to see hex values.
      </div>
    </div>
  );
};

export default GGMVisualizer;
