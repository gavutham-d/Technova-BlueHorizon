import React, { useEffect, useState, useRef, useCallback } from 'react';
import { apiClient } from '../context/AuthContext';
import { Link } from 'react-router-dom';
import { 
  Search, Filter, UploadCloud, Terminal, 
  Trash2, ShieldAlert, ChevronLeft, ChevronRight, FileText
} from 'lucide-react';

interface Indicator {
  _id: string;
  value: string;
  ioc_type: string;
  severity: string;
  risk_score: number;
  source: string;
  created_at: string;
}

export const ThreatFeed: React.FC = () => {
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [appliedSearch, setAppliedSearch] = useState('');
  const [iocType, setIocType] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);

  // Log upload states
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [logType, setLogType] = useState('CSV');
  const [uploadProgress, setUploadProgress] = useState(false);
  const [uploadResult, setUploadResult] = useState<any | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchIndicators = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      const response = await apiClient.get('/indicators', {
        params: {
          page,
          limit: 15,
          search: appliedSearch || undefined,
          ioc_type: iocType || undefined,
          severity: severity || undefined
        },
        signal
      });
      setIndicators(response.data.indicators);
      setTotalItems(response.data.total);
      setTotalPages(Math.ceil(response.data.total / 15));
    } catch (err: any) {
      if (err.name !== 'CanceledError' && err.name !== 'AbortError') {
        console.error("Error loading indicators:", err);
      }
    } finally {
      setLoading(false);
    }
  }, [page, appliedSearch, iocType, severity]);

  useEffect(() => {
    const controller = new AbortController();
    fetchIndicators(controller.signal);
    return () => controller.abort();
  }, [fetchIndicators]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    setAppliedSearch(search);
  };

  const handleFileUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadFile) return;

    setUploadProgress(true);
    setUploadResult(null);

    const formData = new FormData();
    formData.append("file", uploadFile);
    formData.append("log_type", logType);

    try {
      const response = await apiClient.post('/indicators/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });
      setUploadResult(response.data);
      setUploadFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
      
      setAppliedSearch('');
      setSearch('');
      if (page === 1) {
        fetchIndicators();
      } else {
        setPage(1);
      }
    } catch (err: any) {
      alert("Failed to process file upload: " + (err.response?.data?.detail || err.message));
    } finally {
      setUploadProgress(false);
    }
  };

  return (
    <div className="flex-1 p-8 overflow-y-auto max-h-screen">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-wide text-cyber-text">Threat Intelligence Feed</h1>
        <p className="text-sm text-cyber-muted">Consolidated Indicators of Compromise (IoC) normalized to STIX 2.1 schemas.</p>
      </div>

      {/* Grid: Indicators Search and Bulk Upload */}
      <div className="grid grid-cols-3 gap-8">
        
        {/* Left side: Search & Table */}
        <div className="col-span-2 space-y-6">
          <div className="glass-panel p-6">
            <form onSubmit={handleSearchSubmit} className="flex flex-wrap gap-4 items-center justify-between">
              <div className="relative flex-1 min-w-[250px]">
                <Search className="absolute left-3 top-3 w-4 h-4 text-cyber-muted" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search value (e.g. IP, hash, domain)..."
                  className="w-full pl-10 pr-4 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-cyber-text focus:outline-none focus:border-cyber-primary"
                />
              </div>

              <div className="flex items-center gap-3">
                <select
                  value={iocType}
                  onChange={(e) => { setIocType(e.target.value); setPage(1); }}
                  className="px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-xs text-cyber-text focus:outline-none focus:border-cyber-primary"
                >
                  <option value="">All Types</option>
                  <option value="ip">IP Addresses</option>
                  <option value="domain">Domains</option>
                  <option value="hash">Hashes</option>
                  <option value="url">URLs</option>
                </select>

                <select
                  value={severity}
                  onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
                  className="px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-xs text-cyber-text focus:outline-none focus:border-cyber-primary"
                >
                  <option value="">All Severities</option>
                  <option value="Low">Low</option>
                  <option value="Medium">Medium</option>
                  <option value="High">High</option>
                  <option value="Critical">Critical</option>
                </select>

                <button
                  type="submit"
                  className="px-4 py-2 bg-cyber-primary text-cyber-bg font-bold rounded-lg text-xs hover:bg-opacity-90 transition-all"
                >
                  QUERY
                </button>
              </div>
            </form>
          </div>

          {/* Indicator Table */}
          <div className="glass-panel overflow-hidden">
            <div className="px-6 py-4 border-b border-cyber-border bg-cyber-card bg-opacity-40">
              <h3 className="text-sm font-bold font-mono text-cyber-text">Indicators Registry ({totalItems} found)</h3>
            </div>
            
            {loading ? (
              <div className="p-12 text-center">
                <div className="w-8 h-8 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
                <span className="text-xs font-mono text-cyber-muted">RESOLVING INDICATORS...</span>
              </div>
            ) : indicators.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-cyber-card bg-opacity-25 border-b border-cyber-border text-[11px] font-mono text-cyber-muted uppercase">
                      <th className="px-6 py-3">IoC Target Value</th>
                      <th className="px-6 py-3">Type</th>
                      <th className="px-6 py-3">Severity</th>
                      <th className="px-6 py-3">Risk Rating</th>
                      <th className="px-6 py-3">Source Feed</th>
                      <th className="px-6 py-3 text-center">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-cyber-border text-xs font-mono text-cyber-text">
                    {indicators.map((ind) => (
                      <tr key={ind._id} className="hover:bg-cyber-card hover:bg-opacity-20 transition-all">
                        <td className="px-6 py-3 font-semibold text-cyber-primary truncate max-w-[200px]">
                          <Link to={`/indicator/${ind._id}`} className="hover:underline">
                            {ind.value}
                          </Link>
                        </td>
                        <td className="px-6 py-3 uppercase text-[10px] text-cyber-muted">{ind.ioc_type}</td>
                        <td className="px-6 py-3">
                          <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${
                            ind.severity === 'Critical' ? 'bg-red-950 text-red-400 border border-red-500' :
                            ind.severity === 'High' ? 'bg-red-900 text-red-300' :
                            ind.severity === 'Medium' ? 'bg-amber-950 text-amber-400' :
                            'bg-emerald-950 text-emerald-400'
                          }`}>
                            {ind.severity}
                          </span>
                        </td>
                        <td className="px-6 py-3 font-bold">{ind.risk_score.toFixed(1)}</td>
                        <td className="px-6 py-3 text-cyber-muted truncate max-w-[120px]">{ind.source}</td>
                        <td className="px-6 py-3 text-center">
                          <Link
                            to={`/indicator/${ind._id}`}
                            className="px-2 py-1 border border-cyber-primary text-cyber-primary text-[10px] rounded hover:bg-cyber-primary hover:bg-opacity-10 transition-all"
                          >
                            INVESTIGATE
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-12 text-center text-sm text-cyber-muted font-mono">
                No threat indicators matched the search filters.
              </div>
            )}

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="px-6 py-4 bg-cyber-card bg-opacity-30 border-t border-cyber-border flex items-center justify-between">
                <span className="text-xs text-cyber-muted font-mono">
                  Page {page} of {totalPages}
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="p-1.5 bg-cyber-bg border border-cyber-border rounded hover:border-cyber-primary disabled:opacity-40 disabled:hover:border-cyber-border text-cyber-text"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="p-1.5 bg-cyber-bg border border-cyber-border rounded hover:border-cyber-primary disabled:opacity-40 disabled:hover:border-cyber-border text-cyber-text"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right side: Log Upload */}
        <div className="space-y-6">
          <div className="glass-panel p-6">
            <h3 className="text-md font-bold mb-4 font-mono text-cyber-text">Ingest Private Threat Dataset</h3>
            <p className="text-xs text-cyber-muted mb-6">
              Upload Firewall logs, SIEM syslog dumps, Antivirus history, or CSV/JSON/Excel spreadsheets to extract, normalize, and score indicators automatically.
            </p>

            <form onSubmit={handleFileUpload} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-cyber-muted uppercase mb-1">Select Log Schema/Format</label>
                <select
                  value={logType}
                  onChange={(e) => setLogType(e.target.value)}
                  className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-xs text-cyber-text focus:outline-none focus:border-cyber-primary"
                >
                  <option value="CSV">CSV Spreadsheet</option>
                  <option value="Excel">Microsoft Excel (.xlsx)</option>
                  <option value="JSON">JSON File Structure</option>
                  <option value="Firewall">Firewall Access logs</option>
                  <option value="IDS">IDS/IPS Alert logs</option>
                  <option value="SIEM">SIEM Export logs</option>
                  <option value="Antivirus">Antivirus report logs</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-cyber-muted uppercase mb-1">Upload Data File</label>
                <div 
                  onClick={() => fileInputRef.current?.click()}
                  className="border border-dashed border-cyber-border hover:border-cyber-primary rounded-xl p-8 flex flex-col items-center justify-center cursor-pointer bg-cyber-bg bg-opacity-30 transition-all"
                >
                  <UploadCloud className="w-10 h-10 text-cyber-primary animate-pulse mb-2" />
                  <span className="text-xs text-cyber-text font-semibold">
                    {uploadFile ? uploadFile.name : 'Select or drop logs file'}
                  </span>
                  <span className="text-[9px] text-cyber-muted mt-1 uppercase font-mono">
                    Any raw text, JSON, CSV or Excel file
                  </span>
                </div>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                  className="hidden"
                />
              </div>

              <button
                type="submit"
                disabled={!uploadFile || uploadProgress}
                className="w-full py-2.5 bg-cyber-primary text-cyber-bg font-bold text-xs rounded-lg flex items-center justify-center gap-2 hover:bg-opacity-90 disabled:opacity-40 disabled:hover:bg-opacity-100"
              >
                {uploadProgress ? (
                  <span className="w-4 h-4 border-2 border-cyber-bg border-t-transparent rounded-full animate-spin"></span>
                ) : (
                  <>
                    <Terminal className="w-3.5 h-3.5" />
                    <span>INGEST LOG ARCHIVE</span>
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Upload Results Summary Card */}
          {uploadResult && (
            <div className="glass-panel p-6 border-cyber-success border-opacity-35 bg-cyber-success bg-opacity-5">
              <div className="flex items-center gap-2 mb-3">
                <FileText className="text-cyber-success w-5 h-5" />
                <h4 className="text-xs font-bold font-mono text-cyber-success uppercase tracking-wider">Ingestion Complete</h4>
              </div>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-cyber-muted">Processed File:</span>
                  <span className="text-cyber-text truncate max-w-[150px]">{uploadResult.filename}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cyber-muted">Extracted IOCs:</span>
                  <span className="text-cyber-text font-bold">{uploadResult.extracted_iocs}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cyber-muted">New STIX Ingested:</span>
                  <span className="text-cyber-success font-bold">+{uploadResult.imported_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cyber-muted">Duplications:</span>
                  <span className="text-cyber-muted">{uploadResult.duplicate_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cyber-muted">Critical Alerts Raised:</span>
                  <span className="text-cyber-danger font-bold">{uploadResult.alerts_triggered}</span>
                </div>
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
