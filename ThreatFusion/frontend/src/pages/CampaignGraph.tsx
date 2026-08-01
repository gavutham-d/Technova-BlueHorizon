import React, { useEffect, useState, useCallback } from 'react';
import { apiClient } from '../context/AuthContext';
import { Network, Layers, RefreshCw } from 'lucide-react';

interface Node {
  id: string;
  label: string;
  type: 'campaign' | 'indicator' | 'malware';
  ioc_type?: string;
  risk_score?: number;
  severity?: string;
  size: number;
  color: string;
  // Calculated positions
  x?: number;
  y?: number;
}

interface Edge {
  id: string;
  source: string;
  target: string;
  label: string;
}

interface GraphData {
  nodes: Node[];
  edges: Edge[];
}

export const CampaignGraph: React.FC = () => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [campaigns, setCampaigns] = useState<any[]>([]);

  const layoutNodes = useCallback((nodes: Node[], edges: Edge[]): Node[] => {
    const width = 800;
    const height = 500;
    
    // Group indicators by campaign
    const campaigns = nodes.filter(n => n.type === 'campaign');
    const nonCampaigns = nodes.filter(n => n.type !== 'campaign');
    
    // Slice indicators rendering to top-200 nodes initially for performance
    const limitedNonCampaigns = nonCampaigns.slice(0, 200);
    const finalNodes = [...campaigns, ...limitedNonCampaigns];
    
    // Position campaign nodes spaced out
    campaigns.forEach((camp, idx) => {
      const angle = (idx / (campaigns.length || 1)) * 2 * Math.PI;
      const radius = 180;
      camp.x = width / 2 + radius * Math.cos(angle);
      camp.y = height / 2 + radius * Math.sin(angle);
    });
    
    // Position indicators & malware around their campaign
    limitedNonCampaigns.forEach((node, idx) => {
      // Find connected campaign edge
      const edge = edges.find(e => e.target === node.id || e.source === node.id);
      let parent = campaigns[0];
      if (edge) {
        const parentId = edge.source === node.id ? edge.target : edge.source;
        parent = campaigns.find(c => c.id === parentId) || campaigns[0];
      }
      
      if (parent && parent.x !== undefined && parent.y !== undefined) {
        const offsetAngle = (idx / (limitedNonCampaigns.length || 1)) * 2 * Math.PI + (idx * 0.5);
        const radius = 70 + (idx % 2) * 20;
        node.x = parent.x + radius * Math.cos(offsetAngle);
        node.y = parent.y + radius * Math.sin(offsetAngle);
      } else {
        node.x = width / 2 + 100 * Math.cos(idx);
        node.y = height / 2 + 100 * Math.sin(idx);
      }
    });
    
    return finalNodes;
  }, []);

  const fetchGraphData = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      const gRes = await apiClient.get('/campaigns/graph', { signal });
      const cRes = await apiClient.get('/campaigns', { signal });
      
      const rawNodes = gRes.data.nodes as Node[];
      const edges = gRes.data.edges as Edge[];
      
      // Calculate coordinates dynamically using a layout algorithm (e.g., clustered concentric layout)
      const nodes = layoutNodes(rawNodes, edges);
      
      setGraphData({ nodes, edges });
      setCampaigns(cRes.data);
    } catch (err: any) {
      if (err.name !== 'CanceledError' && err.name !== 'AbortError') {
        console.error("Error fetching campaign graphs:", err);
      }
    } finally {
      setLoading(false);
    }
  }, [layoutNodes]);

  useEffect(() => {
    const controller = new AbortController();
    fetchGraphData(controller.signal);
    return () => controller.abort();
  }, [fetchGraphData]);

  if (loading || !graphData) {
    return (
      <div className="flex-1 bg-cyber-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-2">
          <div className="w-10 h-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin mx-auto"></div>
          <div className="text-sm font-mono text-cyber-primary tracking-widest uppercase">GENERATING campaign GRAPH LAYOUTS...</div>
        </div>
      </div>
    );
  }

  // Helper to find coordinates of node by ID
  const getNodePosition = (id: string) => {
    const node = graphData.nodes.find(n => n.id === id);
    return node ? { x: node.x || 0, y: node.y || 0 } : { x: 0, y: 0 };
  };

  return (
    <div className="flex-1 p-8 overflow-y-auto max-h-screen">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-wide text-cyber-text">Threat Campaigns Relationship</h1>
          <p className="text-sm text-cyber-muted">Network graph correlating threats clustered via DBSCAN machine learning models.</p>
        </div>
        <button
          onClick={() => fetchGraphData()}
          className="p-2 border border-cyber-border bg-cyber-card rounded-xl text-cyber-muted hover:text-cyber-primary"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      <div className="grid grid-cols-4 gap-8">
        {/* Campaign Info Cards */}
        <div className="col-span-1 space-y-6">
          <div className="glass-panel p-6">
            <h3 className="text-sm font-bold font-mono text-cyber-text mb-4 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyber-secondary" /> Clustered Campaigns
            </h3>
            
            <div className="space-y-4">
              {campaigns.map((camp, idx) => (
                <div key={idx} className="p-4 bg-cyber-bg border border-cyber-border rounded-xl">
                  <div className="text-xs font-bold text-cyber-secondary font-mono">{camp.name}</div>
                  <div className="text-[10px] text-cyber-muted mt-1 uppercase font-mono">Actor: {camp.threat_actor}</div>
                  <div className="flex justify-between text-xs mt-3 text-cyber-text font-mono">
                    <span>Indicators: {camp.indicators_count}</span>
                    <span className="text-cyber-danger">Max Risk: {camp.max_risk_score}</span>
                  </div>
                  {camp.malware_tags.length > 0 && (
                    <div className="mt-2.5 flex flex-wrap gap-1">
                      {camp.malware_tags.map((tag: string, tIdx: number) => (
                        <span key={tIdx} className="text-[9px] bg-red-950 text-red-400 border border-red-900 px-1.5 py-0.5 rounded">
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Dynamic Interactive SVG Network Graph */}
        <div className="col-span-3 space-y-6">
          <div className="glass-panel p-6 relative">
            <h3 className="text-sm font-bold font-mono text-cyber-text mb-4 flex items-center gap-2">
              <Network className="w-4 h-4 text-cyber-primary" /> Core Correlated Relationships
            </h3>

            {/* SVG drawing canvas */}
            <div className="w-full bg-cyber-bg border border-cyber-border rounded-xl overflow-hidden relative">
              <svg viewBox="0 0 800 500" className="w-full h-[500px]">
                {/* 1. Draw Links/Edges */}
                {(() => {
                  const nodeIds = new Set(graphData.nodes.map(n => n.id));
                  const validEdges = graphData.edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
                  return validEdges.map((edge) => {
                    const sourcePos = getNodePosition(edge.source);
                    const targetPos = getNodePosition(edge.target);
                    return (
                      <line
                        key={edge.id}
                        x1={sourcePos.x}
                        y1={sourcePos.y}
                        x2={targetPos.x}
                        y2={targetPos.y}
                        stroke="#1f2937"
                        strokeWidth={1.5}
                        strokeDasharray={edge.label === 'uses' ? '4' : '0'}
                      />
                    );
                  });
                })()}

                {/* 2. Draw Nodes */}
                {graphData.nodes.map((node) => (
                  <g 
                    key={node.id}
                    transform={`translate(${node.x || 0}, ${node.y || 0})`}
                    onClick={() => setSelectedNode(node)}
                    className="cursor-pointer group"
                  >
                    <circle
                      r={node.size}
                      fill={node.color}
                      className="transition-all duration-300 group-hover:stroke-cyber-text group-hover:stroke-2"
                      opacity={0.85}
                    />
                    {node.type === 'campaign' && (
                      <circle
                        r={node.size + 4}
                        fill="none"
                        stroke={node.color}
                        strokeWidth={1}
                        strokeDasharray="4"
                        className="animate-spin"
                        style={{ transformOrigin: 'center', animationDuration: '10s' }}
                      />
                    )}
                    {/* Node Tooltip label when hovered */}
                    <text
                      dy=".35em"
                      y={node.size + 12}
                      textAnchor="middle"
                      fill="#f3f4f6"
                      fontSize={9}
                      fontFamily="monospace"
                      className="opacity-60 group-hover:opacity-100 transition-opacity pointer-events-none"
                    >
                      {node.label.length > 20 ? node.label.slice(0, 17) + '...' : node.label}
                    </text>
                  </g>
                ))}
              </svg>

              {/* Node Inspector Overlay */}
              {selectedNode && (
                <div className="absolute bottom-4 right-4 max-w-sm glass-panel p-4 font-mono text-xs shadow-2xl">
                  <div className="flex justify-between items-center border-b border-cyber-border pb-2 mb-2">
                    <span className="font-bold text-cyber-primary uppercase">Node Detail Inspector</span>
                    <button 
                      onClick={() => setSelectedNode(null)} 
                      className="text-cyber-muted hover:text-cyber-text text-sm font-bold"
                    >
                      ×
                    </button>
                  </div>
                  <div className="space-y-1">
                    <div>
                      <span className="text-cyber-muted">LABEL:</span>{' '}
                      <span className="text-cyber-text break-all">{selectedNode.label}</span>
                    </div>
                    <div>
                      <span className="text-cyber-muted">NODE TYPE:</span>{' '}
                      <span className="text-cyber-text uppercase">{selectedNode.type}</span>
                    </div>
                    {selectedNode.ioc_type && (
                      <div>
                        <span className="text-cyber-muted">IOC TYPE:</span>{' '}
                        <span className="text-cyber-text uppercase">{selectedNode.ioc_type}</span>
                      </div>
                    )}
                    {selectedNode.risk_score !== undefined && (
                      <div>
                        <span className="text-cyber-muted">RISK SCORE:</span>{' '}
                        <span className="text-cyber-warning font-bold">{selectedNode.risk_score.toFixed(1)} / 100</span>
                      </div>
                    )}
                    {selectedNode.severity && (
                      <div>
                        <span className="text-cyber-muted">SEVERITY:</span>{' '}
                        <span className="text-cyber-danger font-bold">{selectedNode.severity}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
            
            {/* Graph Legend */}
            <div className="flex gap-6 justify-center mt-2 text-xs font-mono text-cyber-muted">
              <div className="flex items-center gap-2">
                <span className="w-3.5 h-3.5 rounded-full bg-[#a855f7]"></span>
                <span>DBSCAN Campaign Cluster</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-3.5 h-3.5 rounded-full bg-[#06b6d4]"></span>
                <span>Threat Indicator (IP/Domain)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-3.5 h-3.5 rounded-full bg-[#ef4444]"></span>
                <span>Associated Malware Payload</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
