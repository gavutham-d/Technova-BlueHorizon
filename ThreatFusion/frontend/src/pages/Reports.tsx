import React, { useEffect, useState } from 'react';
import { apiClient } from '../context/AuthContext';
import { FileText, Printer, ShieldAlert, FileCode } from 'lucide-react';

interface ReportDetails {
  report_title: string;
  generated_at: string;
  generated_by: string;
  organization: string;
  summary: string;
  metrics: {
    total_threats_analyzed: number;
    zero_trust_compliance_logs: number;
  };
  critical_threats: Array<{
    value: string;
    ioc_type: string;
    severity: string;
    risk_score: number;
    malware: string;
    cves: string;
  }>;
}

export const Reports: React.FC = () => {
  const [report, setReport] = useState<ReportDetails | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchReport = async () => {
    try {
      const response = await apiClient.get('/reports/export');
      setReport(response.data);
    } catch (err) {
      console.error("Error generating executive report:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, []);

  const handlePrint = () => {
    window.print();
  };

  if (loading || !report) {
    return (
      <div className="flex-1 bg-cyber-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-2">
          <div className="w-10 h-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin mx-auto"></div>
          <div className="text-sm font-mono text-cyber-primary tracking-widest uppercase">GENERATING EXECUTIVE REPORT...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 p-8 overflow-y-auto max-h-screen print:p-0 print:max-h-none print:bg-white print:text-black">
      
      {/* Control bar - hidden during print */}
      <div className="flex justify-between items-center mb-8 print:hidden">
        <div>
          <h1 className="text-3xl font-bold tracking-wide text-cyber-text">SOC Executive Reports</h1>
          <p className="text-sm text-cyber-muted">Generate and print cybersecurity compliance reports for audit reviews.</p>
        </div>
        <button
          onClick={handlePrint}
          className="px-4 py-2 bg-cyber-primary text-cyber-bg font-bold rounded-xl text-xs hover:bg-opacity-90 flex items-center gap-2 transition-all"
        >
          <Printer className="w-4 h-4" />
          <span>PRINT / SAVE AS PDF</span>
        </button>
      </div>

      {/* PDF layout sheet */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-10 max-w-4xl mx-auto shadow-2xl print:border-none print:bg-white print:text-black print:p-6 print:shadow-none">
        
        {/* Header letterhead */}
        <div className="border-b border-cyber-border pb-6 mb-8 flex justify-between items-start print:border-black">
          <div>
            <h2 className="text-xl font-bold text-cyber-primary tracking-wide uppercase font-mono print:text-black">{report.report_title}</h2>
            <div className="text-xs text-cyber-muted mt-1 font-mono">
              Organization: <span className="text-cyber-text font-semibold print:text-black">{report.organization}</span>
            </div>
            <div className="text-xs text-cyber-muted font-mono">
              Auditor: <span className="text-cyber-text font-semibold print:text-black">{report.generated_by}</span>
            </div>
          </div>
          <div className="text-right font-mono text-xs text-cyber-muted">
            <div>DATE: {new Date(report.generated_at).toLocaleDateString()}</div>
            <div>TIME: {new Date(report.generated_at).toLocaleTimeString()}</div>
            <div className="text-[10px] text-cyber-primary uppercase tracking-widest mt-1 print:text-black">CONFIDENTIAL SECURITY AUDIT</div>
          </div>
        </div>

        {/* Posture summary */}
        <div className="mb-8 font-mono text-xs leading-relaxed text-cyber-muted print:text-black">
          <h3 className="font-bold text-cyber-text uppercase border-b border-cyber-border pb-1.5 mb-2.5 print:text-black print:border-black">
            Executive Summary Overview
          </h3>
          <p className="text-cyber-text print:text-black">{report.summary}</p>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 gap-6 mb-8 font-mono print:text-black">
          <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl print:bg-white print:border-black">
            <div className="text-[10px] text-cyber-muted uppercase">High/Critical Threats Investigated</div>
            <div className="text-2xl font-bold mt-1 text-cyber-danger print:text-black">{report.metrics.total_threats_analyzed}</div>
          </div>
          <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl print:bg-white print:border-black">
            <div className="text-[10px] text-cyber-muted uppercase">Zero Trust Compliance Audit Trails</div>
            <div className="text-2xl font-bold mt-1 text-cyber-primary print:text-black">{report.metrics.zero_trust_compliance_logs}</div>
          </div>
        </div>

        {/* High Risk Threat Mappings table */}
        <div className="font-mono text-xs print:text-black">
          <h3 className="font-bold text-cyber-text uppercase border-b border-cyber-border pb-1.5 mb-4 print:text-black print:border-black">
            Critical Indicators of Compromise (IoC) Registry
          </h3>

          <div className="border border-cyber-border rounded-lg overflow-hidden print:border-black">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-cyber-bg border-b border-cyber-border text-[10px] text-cyber-muted uppercase print:bg-gray-100 print:text-black print:border-black">
                  <th className="px-4 py-2">Indicator Value</th>
                  <th className="px-4 py-2">Type</th>
                  <th className="px-4 py-2">Risk</th>
                  <th className="px-4 py-2">Malware Payload</th>
                  <th className="px-4 py-2">Vulnerability</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-[11px] text-cyber-text print:text-black print:border-black print:divide-black">
                {report.critical_threats.map((threat, idx) => (
                  <tr key={idx} className="print:bg-white">
                    <td className="px-4 py-3 font-semibold break-all max-w-[180px]">{threat.value}</td>
                    <td className="px-4 py-3 uppercase">{threat.ioc_type}</td>
                    <td className="px-4 py-3 font-bold text-cyber-danger print:text-black">{threat.risk_score.toFixed(1)}</td>
                    <td className="px-4 py-3 text-cyber-muted print:text-black">{threat.malware || 'N/A'}</td>
                    <td className="px-4 py-3 text-cyber-muted print:text-black">{threat.cves || 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer sign-off */}
        <div className="mt-12 pt-8 border-t border-cyber-border flex justify-between text-[10px] font-mono text-cyber-muted print:border-black print:text-black">
          <span>THREAT FUSION COMPLIANCE REPORT GENERATOR</span>
          <span>SIGNATURE: ___________________________</span>
        </div>

      </div>
    </div>
  );
};
