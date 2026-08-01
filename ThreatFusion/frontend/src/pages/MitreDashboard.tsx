import React, { useEffect, useState } from 'react';
import { apiClient } from '../context/AuthContext';
import { Grid, Eye, ShieldAlert } from 'lucide-react';

interface MitreMapping {
  tactic: string;
  techniques: Array<{
    id: string;
    name: string;
    description: string;
    indicators: string[];
  }>;
}

export const MitreDashboard: React.FC = () => {
  const [matrix, setMatrix] = useState<MitreMapping[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState<any | null>(null);

  const fetchMitreData = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get('/indicators', { params: { limit: 100 } });
      const indicators = response.data.indicators;
      
      // Group indicators into MITRE tactics
      const tacticsMap: Record<string, any> = {
        "Initial Access": {
          "T1566": { name: "Phishing", desc: "Spearphishing attempts targeting users", indicators: [] }
        },
        "Execution": {
          "T1204": { name: "User Execution", desc: "User execution of malicious attachments or links", indicators: [] },
          "T1059": { name: "Command and Script Interpreter", desc: "Powershell/bash code executions", indicators: [] }
        },
        "Persistence": {
          "T1547": { name: "Boot or Logon Autostart Execution", desc: "Registry run keys, startup folder additions", indicators: [] }
        },
        "Defense Evasion": {
          "T1027": { name: "Obfuscated Files or Information", desc: "Encrypted payloads or file obfuscation", indicators: [] }
        },
        "Command and Control": {
          "T1071": { name: "Application Layer Protocol", desc: "Web C2 protocols (HTTP/HTTPS/DNS)", indicators: [] },
          "T1090": { name: "Proxy", desc: "Multi-hop proxy systems to hide origins", indicators: [] },
          "T1568": { name: "Dynamic Resolution", desc: "Domain Generation Algorithms (DGA)", indicators: [] }
        }
      };

      // Map indicators to tactics Map
      indicators.forEach((ind: any) => {
        ind.mitre_techniques.forEach((techStr: string) => {
          // parse ID e.g. "T1071.001 - Command and Control..."
          const match = techStr.match(/^(T\d{4})/);
          if (match) {
            const techId = match[1];
            // Find which tactic has this technique
            for (const tactic in tacticsMap) {
              if (tacticsMap[tactic][techId]) {
                if (!tacticsMap[tactic][techId].indicators.includes(ind.value)) {
                  tacticsMap[tactic][techId].indicators.push(ind.value);
                }
              }
            }
          }
        });
      });

      // Format as List
      const formattedMatrix: MitreMapping[] = Object.keys(tacticsMap).map(tacticName => {
        const techs = tacticsMap[tacticName];
        return {
          tactic: tacticName,
          techniques: Object.keys(techs).map(techId => ({
            id: techId,
            name: techs[techId].name,
            description: techs[techId].desc,
            indicators: techs[techId].indicators
          }))
        };
      });

      setMatrix(formattedMatrix);
    } catch (err) {
      console.error("Error loading MITRE dashboard:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMitreData();
  }, []);

  if (loading) {
    return (
      <div className="flex-1 bg-cyber-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-2">
          <div className="w-10 h-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin mx-auto"></div>
          <div className="text-sm font-mono text-cyber-primary tracking-widest uppercase">MAPPING MITRE MATRIX TARGETS...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 p-8 overflow-y-auto max-h-screen">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-wide text-cyber-text">MITRE ATT&CK Matrix</h1>
        <p className="text-sm text-cyber-muted">Active threat indicators mapped to corresponding adversarial tactics and techniques.</p>
      </div>

      {/* MITRE Matrix Table Layout */}
      <div className="glass-panel p-6 overflow-x-auto mb-8">
        <div className="flex items-center gap-2 mb-6">
          <Grid className="text-cyber-primary w-5 h-5" />
          <h3 className="text-md font-bold font-mono text-cyber-text">SOC Enterprise Attack Mapping</h3>
        </div>

        <div className="flex gap-4 min-w-[900px] select-none">
          {matrix.map((tacticCol) => (
            <div key={tacticCol.tactic} className="flex-1 bg-cyber-bg border border-cyber-border rounded-xl p-4 flex flex-col gap-4">
              <div className="text-xs font-bold text-cyber-secondary font-mono uppercase tracking-wider text-center border-b border-cyber-border pb-2.5">
                {tacticCol.tactic}
              </div>
              <div className="flex flex-col gap-3">
                {tacticCol.techniques.map((tech) => (
                  <div
                    key={tech.id}
                    onClick={() => setSelectedTechnique(tech)}
                    className={`p-3.5 border rounded-lg text-left transition-all duration-200 cursor-pointer ${
                      tech.indicators.length > 0
                        ? 'border-red-900 border-opacity-65 bg-red-950 bg-opacity-15 hover:border-cyber-danger'
                        : 'border-cyber-border bg-cyber-card bg-opacity-20 hover:border-cyber-muted'
                    }`}
                  >
                    <div className="flex justify-between items-start gap-1">
                      <span className="text-[10px] font-bold text-cyber-muted font-mono">{tech.id}</span>
                      {tech.indicators.length > 0 && (
                        <span className="text-[9px] font-bold font-mono px-1.5 py-0.5 rounded bg-cyber-danger text-cyber-bg animate-pulse">
                          {tech.indicators.length} Active
                        </span>
                      )}
                    </div>
                    <div className="text-xs font-bold text-cyber-text mt-1 truncate max-w-[130px]">{tech.name}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technique detail overlay drawer */}
      {selectedTechnique && (
        <div className="glass-panel p-6 font-mono text-xs max-w-3xl">
          <div className="flex justify-between items-center border-b border-cyber-border pb-3 mb-4">
            <div>
              <span className="text-cyber-muted text-[10px]">TECHNIQUE SPECIFICATION</span>
              <h4 className="text-sm font-bold text-cyber-primary">{selectedTechnique.id} - {selectedTechnique.name}</h4>
            </div>
            <button 
              onClick={() => setSelectedTechnique(null)} 
              className="text-cyber-muted hover:text-cyber-text font-bold text-lg"
            >
              ×
            </button>
          </div>
          
          <div className="mb-4">
            <span className="text-cyber-muted uppercase">Description:</span>
            <p className="text-cyber-text mt-1 leading-relaxed">{selectedTechnique.description}</p>
          </div>

          <div>
            <span className="text-cyber-muted uppercase">Active Indicators ({selectedTechnique.indicators.length}):</span>
            {selectedTechnique.indicators.length > 0 ? (
              <div className="grid grid-cols-2 gap-2 mt-2 max-h-48 overflow-y-auto pr-2">
                {selectedTechnique.indicators.map((val: string, idx: number) => (
                  <div key={idx} className="p-2 bg-cyber-bg border border-cyber-border rounded-lg text-cyber-text break-all">
                    {val}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-cyber-muted mt-1.5">No active threats targeting this technique signature.</p>
            )}
          </div>
        </div>
      )}

    </div>
  );
};
