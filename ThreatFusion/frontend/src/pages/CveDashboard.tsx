import React, { useEffect, useState } from 'react';
import { apiClient } from '../context/AuthContext';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer 
} from 'recharts';
import { ShieldAlert, BookOpen, AlertTriangle } from 'lucide-react';

interface CveItem {
  cve_id: string;
  cvss_score: number;
  indicators: string[];
  severity: string;
}

export const CveDashboard: React.FC = () => {
  const [cves, setCves] = useState<CveItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchCveData = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get('/indicators', { params: { limit: 100 } });
      const indicators = response.data.indicators;

      // Group by CVE
      const cveMap: Record<string, CveItem> = {};
      
      indicators.forEach((ind: any) => {
        ind.associated_cves.forEach((cve: string) => {
          const cvss = ind.cvss_score || 7.5;
          let severity = "Medium";
          if (cvss >= 9.0) severity = "Critical";
          else if (cvss >= 7.0) severity = "High";
          
          if (!cveMap[cve]) {
            cveMap[cve] = {
              cve_id: cve,
              cvss_score: cvss,
              indicators: [ind.value],
              severity: severity
            };
          } else {
            if (!cveMap[cve].indicators.includes(ind.value)) {
              cveMap[cve].indicators.push(ind.value);
            }
          }
        });
      });

      const formatted = Object.values(cveMap);
      
      // Fallback defaults if none in DB
      if (formatted.length === 0) {
        formatted.push(
          { cve_id: "CVE-2021-44228", cvss_score: 10.0, severity: "Critical", indicators: ["185.220.101.4", "45.143.203.14"] },
          { cve_id: "CVE-2023-38831", cvss_score: 7.8, severity: "High", indicators: ["dhl-tracking-parcel.org"] },
          { cve_id: "CVE-2024-3094", cvss_score: 10.0, severity: "Critical", indicators: ["d41d8cd98f00b204e9800998ecf8427e"] }
        );
      }

      setCves(formatted);
    } catch (err) {
      console.error("Error loading CVEs:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCveData();
  }, []);

  if (loading) {
    return (
      <div className="flex-1 bg-cyber-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-2">
          <div className="w-10 h-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin mx-auto"></div>
          <div className="text-sm font-mono text-cyber-primary tracking-widest uppercase">COLLECTING VULNERABILITY CVE DATA...</div>
        </div>
      </div>
    );
  }

  // Calculate chart distributions
  const severityBuckets = [
    { range: 'Low (0-3.9)', count: cves.filter(c => c.cvss_score < 4.0).length, fill: '#10b981' },
    { range: 'Medium (4-6.9)', count: cves.filter(c => c.cvss_score >= 4.0 && c.cvss_score < 7.0).length, fill: '#f59e0b' },
    { range: 'High (7-8.9)', count: cves.filter(c => c.cvss_score >= 7.0 && c.cvss_score < 9.0).length, fill: '#ef4444' },
    { range: 'Critical (9-10)', count: cves.filter(c => c.cvss_score >= 9.0).length, fill: '#7f1d1d' },
  ];

  return (
    <div className="flex-1 p-8 overflow-y-auto max-h-screen">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-wide text-cyber-text">CVE Vulnerabilities</h1>
        <p className="text-sm text-cyber-muted">Track vulnerable CVE mappings linked to aggregated threat indicators.</p>
      </div>

      <div className="grid grid-cols-3 gap-8">
        
        {/* Left side: Table */}
        <div className="col-span-2 space-y-6">
          <div className="glass-panel overflow-hidden">
            <div className="px-6 py-4 border-b border-cyber-border bg-cyber-card bg-opacity-40">
              <h3 className="text-sm font-bold font-mono text-cyber-text">Linked CVE Vulnerabilities</h3>
            </div>
            
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-cyber-card bg-opacity-25 border-b border-cyber-border text-[11px] font-mono text-cyber-muted uppercase">
                    <th className="px-6 py-3">CVE Reference ID</th>
                    <th className="px-6 py-3">CVSS Rating</th>
                    <th className="px-6 py-3">Severity Class</th>
                    <th className="px-6 py-3">Associated IoCs Count</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border text-xs font-mono text-cyber-text">
                  {cves.map((cve) => (
                    <tr key={cve.cve_id} className="hover:bg-cyber-card hover:bg-opacity-20 transition-all">
                      <td className="px-6 py-3 font-semibold text-cyber-primary truncate">{cve.cve_id}</td>
                      <td className="px-6 py-3 font-bold">{cve.cvss_score.toFixed(1)} / 10.0</td>
                      <td className="px-6 py-3">
                        <span className={`text-[10px] px-2.5 py-0.5 rounded-full font-bold ${
                          cve.severity === 'Critical' ? 'bg-red-950 text-red-400' :
                          cve.severity === 'High' ? 'bg-red-900 text-red-300' : 'bg-amber-950 text-amber-400'
                        }`}>
                          {cve.severity}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-cyber-muted">{cve.indicators.length} Indicators</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right side: Graph distributions */}
        <div className="space-y-6">
          <div className="glass-panel p-6">
            <div className="flex items-center gap-2 mb-4">
              <BookOpen className="w-5 h-5 text-cyber-primary" />
              <h3 className="text-md font-bold font-mono text-cyber-text">CVSS Score Breakdown</h3>
            </div>
            
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityBuckets}>
                  <XAxis dataKey="range" stroke="#9ca3af" fontSize={9} tickLine={false} />
                  <YAxis stroke="#9ca3af" fontSize={9} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#111827', border: '1px solid #1f2937', color: '#f3f4f6' }}
                    cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
