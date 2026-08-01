import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { apiClient } from '../context/AuthContext';
import { 
  ArrowLeft, Shield, Clock, Eye, AlertTriangle, 
  Layers, Link as LinkIcon, Info, Database
} from 'lucide-react';

interface STIXRep {
  id: string;
  type: string;
  pattern: string;
  valid_from: string;
  labels: string[];
}

interface IndicatorDetail {
  _id: string;
  value: string;
  ioc_type: string;
  severity: string;
  risk_score: number;
  feed_confidence: number;
  source_count: number;
  days_active: number;
  ip_in_malicious_subnet: boolean;
  source: string;
  description: string;
  mitre_techniques: string[];
  associated_malware: string[];
  associated_cves: string[];
  cvss_score: number | null;
  campaign_id: string | null;
  created_at: string;
  stix_representation: STIXRep;
}

export const ThreatDetails: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [indicator, setIndicator] = useState<IndicatorDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDetail = async () => {
      try {
        const response = await apiClient.get(`/indicators/${id}`);
        setIndicator(response.data);
      } catch (err: any) {
        setError(err.response?.data?.detail || "Failed to load indicator details.");
      } finally {
        setLoading(false);
      }
    };
    fetchDetail();
  }, [id]);

  if (loading) {
    return (
      <div className="flex-1 bg-cyber-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-2">
          <div className="w-10 h-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <div className="text-sm font-mono text-cyber-primary tracking-widest uppercase">HARVESTING IOC DATA...</div>
        </div>
      </div>
    );
  }

  if (error || !indicator) {
    return (
      <div className="flex-1 p-8 bg-cyber-bg">
        <Link to="/feed" className="flex items-center gap-2 text-cyber-primary hover:underline font-mono text-sm mb-6">
          <ArrowLeft className="w-4 h-4" /> BACK TO FEED
        </Link>
        <div className="glass-panel p-8 text-center text-cyber-danger border-cyber-danger border-opacity-35 bg-cyber-danger bg-opacity-5">
          <AlertTriangle className="w-12 h-12 mx-auto mb-3" />
          <h2 className="text-lg font-bold font-mono">ERROR RETRIEVING DATA</h2>
          <p className="text-xs font-mono mt-1">{error || 'Unknown database retrieval error.'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 p-8 overflow-y-auto max-h-screen">
      <Link to="/feed" className="flex items-center gap-2 text-cyber-primary hover:underline font-mono text-sm mb-6">
        <ArrowLeft className="w-4 h-4" /> BACK TO REGISTRY FEED
      </Link>

      <div className="flex items-center justify-between mb-8">
        <div>
          <span className="text-xs font-mono text-cyber-muted uppercase tracking-widest">INDICATOR PROFILE DEEP DIVE</span>
          <h1 className="text-3xl font-bold tracking-wide text-cyber-text mt-1 truncate max-w-xl">{indicator.value}</h1>
        </div>
        <div className="flex gap-3">
          <span className={`px-4 py-2 border rounded-xl font-mono text-xs font-semibold ${
            indicator.severity === 'Critical' ? 'bg-red-500 bg-opacity-10 text-cyber-danger border-cyber-danger' :
            indicator.severity === 'High' ? 'bg-red-500 bg-opacity-5 text-red-400 border-red-900' :
            indicator.severity === 'Medium' ? 'bg-amber-500 bg-opacity-10 text-cyber-warning border-cyber-warning' :
            'bg-emerald-500 bg-opacity-10 text-cyber-success border-cyber-success'
          }`}>
            SEVERITY: {indicator.severity}
          </span>
          <span className="px-4 py-2 bg-cyber-card border border-cyber-border rounded-xl font-mono text-xs font-bold text-cyber-primary">
            XGBOOST RISK: {indicator.risk_score.toFixed(1)} / 100
          </span>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-8">
        
        {/* Profile Details column */}
        <div className="col-span-2 space-y-6">
          <div className="glass-panel p-6">
            <h3 className="text-sm font-bold font-mono text-cyber-text mb-4 flex items-center gap-2">
              <Info className="w-4 h-4 text-cyber-primary" /> General threat context
            </h3>
            <p className="text-sm text-cyber-muted mb-6 leading-relaxed">{indicator.description}</p>
            
            <div className="grid grid-cols-2 gap-6 font-mono text-xs">
              <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl flex items-center justify-between">
                <span className="text-cyber-muted">IOC TYPE:</span>
                <span className="text-cyber-text font-bold uppercase">{indicator.ioc_type}</span>
              </div>
              <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl flex items-center justify-between">
                <span className="text-cyber-muted">CTI SOURCE:</span>
                <span className="text-cyber-text font-bold">{indicator.source}</span>
              </div>
              <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl flex items-center justify-between">
                <span className="text-cyber-muted">DAYS DETECTED:</span>
                <span className="text-cyber-text font-bold">{indicator.days_active} Days</span>
              </div>
              <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl flex items-center justify-between">
                <span className="text-cyber-muted">SUBNET MALICIOUS:</span>
                <span className={`font-bold ${indicator.ip_in_malicious_subnet ? 'text-cyber-danger' : 'text-cyber-success'}`}>
                  {indicator.ip_in_malicious_subnet ? 'YES' : 'NO'}
                </span>
              </div>
            </div>
          </div>

          {/* MITRE ATT&CK Matrix & Vulnerability Connections */}
          <div className="grid grid-cols-2 gap-6">
            
            {/* MITRE Panel */}
            <div className="glass-panel p-6">
              <h3 className="text-sm font-bold font-mono text-cyber-text mb-4 flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyber-secondary" /> MITRE ATT&CK Techniques
              </h3>
              {indicator.mitre_techniques.length > 0 ? (
                <ul className="space-y-3 text-xs font-mono">
                  {indicator.mitre_techniques.map((t, idx) => (
                    <li key={idx} className="p-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-cyber-text">
                      {t}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs font-mono text-cyber-muted">No specific technique signatures mapped.</p>
              )}
            </div>

            {/* Context associations */}
            <div className="glass-panel p-6">
              <h3 className="text-sm font-bold font-mono text-cyber-text mb-4 flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyber-warning" /> Associations & Vulnerabilities
              </h3>
              <div className="space-y-4 text-xs font-mono">
                <div>
                  <div className="text-cyber-muted mb-2">MALWARE FAMILIES:</div>
                  <div className="flex flex-wrap gap-2">
                    {indicator.associated_malware.map((m, idx) => (
                      <span key={idx} className="px-2.5 py-1 bg-red-950 text-red-400 border border-red-900 rounded-lg">
                        {m}
                      </span>
                    ))}
                  </div>
                </div>

                {indicator.associated_cves.length > 0 && (
                  <div>
                    <div className="text-cyber-muted mb-2">TARGET CVE VULNERABILITIES:</div>
                    <div className="flex flex-wrap gap-2">
                      {indicator.associated_cves.map((cve, idx) => (
                        <span key={idx} className="px-2.5 py-1 bg-cyber-bg border border-cyber-border rounded-lg text-cyber-text">
                          {cve}
                        </span>
                      ))}
                    </div>
                    {indicator.cvss_score !== null && (
                      <div className="mt-2 text-cyber-muted">
                        CVSS Score: <span className="text-cyber-danger font-bold">{indicator.cvss_score.toFixed(1)}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

          </div>

          {/* STIX 2.1 Schema Codeblock */}
          <div className="glass-panel p-6">
            <h3 className="text-sm font-bold font-mono text-cyber-text mb-4 flex items-center gap-2">
              <Database className="w-4 h-4 text-cyber-primary" /> STIX 2.1 Representational Object Schema
            </h3>
            <div className="relative">
              <pre className="p-4 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-cyber-primary overflow-x-auto max-h-64 scrollbar-thin glow-cyan">
                {JSON.stringify(indicator.stix_representation, null, 2)}
              </pre>
            </div>
          </div>
        </div>

        {/* Right side: ML predictions summary */}
        <div className="space-y-6">
          <div className="glass-panel p-6">
            <h3 className="text-sm font-bold font-mono text-cyber-text mb-4">ML Intelligence insights</h3>
            
            <div className="space-y-6">
              {/* XGBoost scoring info */}
              <div>
                <div className="text-xs text-cyber-muted font-mono uppercase mb-2">XGBoost Risk Score</div>
                <div className="w-full bg-cyber-bg h-3 rounded-full border border-cyber-border overflow-hidden">
                  <div 
                    className={`h-full ${
                      indicator.risk_score > 80 ? 'bg-cyber-danger' : 
                      indicator.risk_score > 50 ? 'bg-cyber-warning' : 'bg-cyber-success'
                    }`} 
                    style={{ width: `${indicator.risk_score}%` }}
                  ></div>
                </div>
                <div className="flex justify-between text-[10px] text-cyber-muted font-mono mt-1">
                  <span>0.0</span>
                  <span className="font-bold text-cyber-text">{indicator.risk_score.toFixed(1)}% (Regressed Risk)</span>
                  <span>100.0</span>
                </div>
              </div>

              {/* Random Forest info */}
              <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl">
                <div className="text-xs text-cyber-muted font-mono uppercase">Severity Classifier (Random Forest)</div>
                <div className="text-md font-bold mt-2 text-cyber-text flex items-center gap-2">
                  <span className={`w-3 h-3 rounded-full ${
                    indicator.severity === 'Critical' ? 'bg-cyber-danger' : 
                    indicator.severity === 'High' ? 'bg-red-500' :
                    indicator.severity === 'Medium' ? 'bg-cyber-warning' : 'bg-cyber-success'
                  }`}></span>
                  <span>{indicator.severity}</span>
                </div>
              </div>

              {/* DBSCAN Campaign Cluster info */}
              <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl">
                <div className="text-xs text-cyber-muted font-mono uppercase">DBSCAN Clustering Campaign</div>
                <div className="text-xs font-semibold mt-2 text-cyber-text leading-relaxed">
                  {indicator.campaign_id ? (
                    <>
                      Associated with cluster:<br/>
                      <span className="text-cyber-secondary font-bold font-mono text-sm">
                        {indicator.campaign_id}
                      </span>
                    </>
                  ) : (
                    <span className="text-cyber-muted font-mono">Unassociated Scans / General Activity</span>
                  )}
                </div>
              </div>

              {/* Feed confidence */}
              <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl">
                <div className="text-xs text-cyber-muted font-mono uppercase">CTI Confidence score</div>
                <div className="text-md font-bold mt-1 text-cyber-primary font-mono">
                  {indicator.feed_confidence.toFixed(1)}%
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
