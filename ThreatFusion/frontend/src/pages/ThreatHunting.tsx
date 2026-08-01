import React, { useEffect, useState } from 'react';
import { apiClient } from '../context/AuthContext';
import { 
  Search, ShieldAlert, Sparkles, Terminal, 
  HelpCircle, Eye, AlertTriangle 
} from 'lucide-react';

interface AnomalyLog {
  log_id: string;
  username: string;
  action: string;
  ip_address: string;
  timestamp: string;
  anomaly_score: number;
  reason: string;
}

export const ThreatHunting: React.FC = () => {
  const [anomalies, setAnomalies] = useState<AnomalyLog[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Custom manual test input
  const [reqCount, setReqCount] = useState(10);
  const [hourOfDay, setHourOfDay] = useState(12);
  const [byteSize, setByteSize] = useState(500);
  const [testResult, setTestResult] = useState<any | null>(null);
  const [testing, setTesting] = useState(false);

  const fetchAnomalies = async () => {
    try {
      const response = await apiClient.get('/hunting/anomalies');
      setAnomalies(response.data);
    } catch (err) {
      console.error("Error fetching anomalies:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnomalies();
  }, []);

  const handleTestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTesting(true);
    setTestResult(null);

    try {
      const response = await apiClient.post(`/hunting/test-log`, null, {
        params: {
          request_count: reqCount,
          hour_of_day: hourOfDay,
          log_byte_size: byteSize
        }
      });
      setTestResult(response.data);
    } catch (err: any) {
      alert("Failed to analyze log: " + (err.response?.data?.detail || err.message));
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="flex-1 p-8 overflow-y-auto max-h-screen">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-wide text-cyber-text">AI Threat Hunting</h1>
        <p className="text-sm text-cyber-muted">Inspect log patterns and identify outliers using our Isolation Forest model.</p>
      </div>

      <div className="grid grid-cols-3 gap-8">
        
        {/* Left side: Anomalies Listing */}
        <div className="col-span-2 space-y-6">
          <div className="glass-panel overflow-hidden">
            <div className="px-6 py-4 border-b border-cyber-border bg-cyber-card bg-opacity-40 flex items-center justify-between">
              <h3 className="text-sm font-bold font-mono text-cyber-text">Detected Log Anomalies (Isolation Forest)</h3>
              <span className="text-[10px] bg-cyber-danger bg-opacity-10 text-cyber-danger px-2.5 py-0.5 rounded border border-cyber-danger border-opacity-35 font-mono">
                OUTLIERS IDENTIFIED
              </span>
            </div>

            {loading ? (
              <div className="p-12 text-center">
                <div className="w-8 h-8 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
                <span className="text-xs font-mono text-cyber-muted">SCANNING COMPLIANCE LOGS...</span>
              </div>
            ) : anomalies.length > 0 ? (
              <div className="divide-y divide-cyber-border">
                {anomalies.map((anom) => (
                  <div key={anom.log_id} className="p-6 flex items-start justify-between hover:bg-cyber-card hover:bg-opacity-15 transition-all">
                    <div>
                      <div className="flex items-center gap-3">
                        <span className="text-sm font-bold text-cyber-text font-mono">{anom.action}</span>
                        <span className="text-xs text-cyber-muted font-mono">{anom.ip_address}</span>
                      </div>
                      <div className="text-xs text-cyber-danger mt-1 font-mono">Reason: {anom.reason}</div>
                      <div className="text-[10px] text-cyber-muted mt-2 font-mono">
                        User: {anom.username} | Timestamp: {new Date(anom.timestamp).toLocaleString()}
                      </div>
                    </div>
                    <div className="text-right">
                      <span className="px-2.5 py-1 bg-red-950 text-cyber-danger border border-red-900 rounded-lg text-xs font-mono font-bold">
                        {anom.anomaly_score.toFixed(1)}% Anomaly
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-12 text-center text-sm text-cyber-muted font-mono">
                No anomalous activities flagged in the active log cycle.
              </div>
            )}
          </div>
        </div>

        {/* Right side: ML test console */}
        <div className="space-y-6">
          <div className="glass-panel p-6">
            <div className="flex items-center gap-2 mb-4">
              <Sparkles className="w-5 h-5 text-cyber-primary" />
              <h3 className="text-md font-bold font-mono text-cyber-text">Isolation Forest Playground</h3>
            </div>
            <p className="text-xs text-cyber-muted mb-6">
              Simulate operational variables below to evaluate log threat classifications in real time.
            </p>

            <form onSubmit={handleTestSubmit} className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-cyber-muted mb-1">REQUESTS COUNT (1s WINDOW):</label>
                <input
                  type="number"
                  value={reqCount}
                  onChange={(e) => setReqCount(parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-cyber-primary"
                />
              </div>

              <div>
                <label className="block text-cyber-muted mb-1">HOUR OF DAY (0-23):</label>
                <input
                  type="number"
                  min="0"
                  max="23"
                  value={hourOfDay}
                  onChange={(e) => setHourOfDay(parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-cyber-primary"
                />
              </div>

              <div>
                <label className="block text-cyber-muted mb-1">PACKET DATA SIZE (BYTES):</label>
                <input
                  type="number"
                  value={byteSize}
                  onChange={(e) => setByteSize(parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-cyber-primary"
                />
              </div>

              <button
                type="submit"
                disabled={testing}
                className="w-full py-2.5 bg-cyber-primary text-cyber-bg font-bold rounded-lg flex items-center justify-center gap-2 hover:bg-opacity-90"
              >
                {testing ? (
                  <span className="w-4 h-4 border-2 border-cyber-bg border-t-transparent rounded-full animate-spin"></span>
                ) : (
                  <>
                    <Terminal className="w-4 h-4" />
                    <span>ANALYZE METRICS</span>
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Test results visual */}
          {testResult && (
            <div className={`glass-panel p-6 border-opacity-35 ${
              testResult.is_anomaly 
                ? 'border-cyber-danger bg-cyber-danger bg-opacity-5' 
                : 'border-cyber-success bg-cyber-success bg-opacity-5'
            }`}>
              <div className="flex items-center gap-2 mb-3">
                {testResult.is_anomaly ? (
                  <AlertTriangle className="text-cyber-danger w-5 h-5" />
                ) : (
                  <Sparkles className="text-cyber-success w-5 h-5" />
                )}
                <h4 className={`text-xs font-bold font-mono uppercase tracking-wider ${
                  testResult.is_anomaly ? 'text-cyber-danger' : 'text-cyber-success'
                }`}>
                  {testResult.risk_level} Pattern
                </h4>
              </div>
              <p className="text-xs text-cyber-muted font-mono leading-relaxed mb-4">
                {testResult.description}
              </p>
              <div className="flex justify-between items-center text-[10px] font-mono border-t border-cyber-border pt-3">
                <span className="text-cyber-muted">IFOREST SCORE:</span>
                <span className="text-cyber-text">{testResult.score.toFixed(4)}</span>
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
