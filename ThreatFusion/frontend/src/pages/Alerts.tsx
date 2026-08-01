import React, { useEffect, useState } from 'react';
import { apiClient } from '../context/AuthContext';
import { 
  ShieldAlert, ShieldCheck, UserCheck, AlertTriangle, 
  Terminal, CheckCircle 
} from 'lucide-react';

interface Alert {
  _id: string;
  indicator_value: string;
  ioc_type: string;
  severity: string;
  risk_score: number;
  trigger_reason: string;
  status: string; // Unassigned, Assigned, Investigating, Resolved
  assigned_to: string | null;
  created_at: string;
}

export const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [notes, setNotes] = useState('');
  const [activeAlertId, setActiveAlertId] = useState<string | null>(null);

  const fetchAlerts = async () => {
    try {
      const response = await apiClient.get('/alerts');
      setAlerts(response.data);
    } catch (err) {
      console.error("Error loading alerts:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const handleAssign = async (alertId: string) => {
    try {
      await apiClient.post(`/alerts/${alertId}/assign`);
      fetchAlerts();
    } catch (err: any) {
      alert("Failed to assign alert: " + (err.response?.data?.detail || err.message));
    }
  };

  const handleResolve = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeAlertId || !notes.trim()) return;

    try {
      await apiClient.post(`/alerts/${activeAlertId}/resolve`, null, {
        params: { notes }
      });
      setNotes('');
      setActiveAlertId(null);
      fetchAlerts();
    } catch (err: any) {
      alert("Failed to resolve alert: " + (err.response?.data?.detail || err.message));
    }
  };

  if (loading) {
    return (
      <div className="flex-1 bg-cyber-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-2">
          <div className="w-10 h-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin mx-auto"></div>
          <div className="text-sm font-mono text-cyber-primary tracking-widest uppercase">SCANNING INCIDENTS DATABASE...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 p-8 overflow-y-auto max-h-screen">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-wide text-cyber-text">Incident Triage Command</h1>
        <p className="text-sm text-cyber-muted">Respond to high-risk Indicators of Compromise (XGBoost score ≥ 80.0) flagged in logs.</p>
      </div>

      <div className="grid grid-cols-3 gap-8">
        
        {/* Left column: List of Alerts */}
        <div className="col-span-2 space-y-6">
          <div className="glass-panel overflow-hidden">
            <div className="px-6 py-4 border-b border-cyber-border bg-cyber-card bg-opacity-40">
              <h3 className="text-sm font-bold font-mono text-cyber-text">Active Incidents Queue</h3>
            </div>

            {alerts.length > 0 ? (
              <div className="divide-y divide-cyber-border">
                {alerts.map((alert) => (
                  <div 
                    key={alert._id} 
                    className={`p-6 flex flex-col gap-3 transition-all hover:bg-cyber-card hover:bg-opacity-10 ${
                      alert.status === 'Resolved' ? 'opacity-55' : ''
                    }`}
                  >
                    <div className="flex justify-between items-start">
                      <div>
                        <div className="flex items-center gap-2.5">
                          <span className="text-sm font-bold font-mono text-cyber-text">{alert.indicator_value}</span>
                          <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold font-mono ${
                            alert.severity === 'Critical' ? 'bg-red-950 text-red-400 border border-red-500' : 'bg-red-900 text-red-300'
                          }`}>
                            {alert.severity}
                          </span>
                          <span className={`text-[9px] uppercase px-2 py-0.5 rounded font-mono ${
                            alert.status === 'Resolved' ? 'bg-emerald-950 text-emerald-400' :
                            alert.status === 'Assigned' ? 'bg-amber-950 text-amber-400' :
                            'bg-cyber-border text-cyber-muted'
                          }`}>
                            {alert.status}
                          </span>
                        </div>
                        <div className="text-xs text-cyber-muted mt-1 leading-relaxed font-mono">
                          Reason: {alert.trigger_reason}
                        </div>
                      </div>
                      <div className="text-right font-mono">
                        <div className="text-xs font-bold text-cyber-warning">{alert.risk_score.toFixed(1)} / 100</div>
                        <div className="text-[9px] text-cyber-muted mt-1">XGBoost Score</div>
                      </div>
                    </div>

                    <div className="flex justify-between items-center border-t border-cyber-border pt-3 mt-1 text-[10px] font-mono text-cyber-muted">
                      <div>
                        Timestamp: {new Date(alert.created_at).toLocaleString()} 
                        {alert.assigned_to && ` | Analyst: ${alert.assigned_to}`}
                      </div>
                      
                      {alert.status !== 'Resolved' && (
                        <div className="flex gap-2">
                          {alert.status === 'Unassigned' && (
                            <button
                              onClick={() => handleAssign(alert._id)}
                              className="px-2.5 py-1 bg-cyber-bg border border-cyber-secondary text-cyber-secondary rounded hover:bg-cyber-secondary hover:bg-opacity-10 flex items-center gap-1"
                            >
                              <UserCheck className="w-3 h-3" />
                              <span>CLAIM INCIDENT</span>
                            </button>
                          )}
                          <button
                            onClick={() => { setActiveAlertId(alert._id); setNotes(''); }}
                            className="px-2.5 py-1 bg-cyber-bg border border-cyber-success text-cyber-success rounded hover:bg-cyber-success hover:bg-opacity-10 flex items-center gap-1"
                          >
                            <ShieldCheck className="w-3 h-3" />
                            <span>RESOLVE INCIDENT</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-12 text-center text-sm text-cyber-muted font-mono">
                Queue cleared. No active critical incidents.
              </div>
            )}
          </div>
        </div>

        {/* Right column: Incident Resolution Console */}
        <div className="col-span-1 space-y-6">
          {activeAlertId ? (
            <div className="glass-panel p-6 border-cyber-success border-opacity-35 bg-cyber-success bg-opacity-5 font-mono">
              <div className="flex items-center gap-2 mb-4 border-b border-cyber-border pb-2.5">
                <CheckCircle className="text-cyber-success w-5 h-5" />
                <h3 className="text-xs font-bold text-cyber-success uppercase tracking-wider">Resolve Incident</h3>
              </div>
              
              <form onSubmit={handleResolve} className="space-y-4">
                <div className="text-xs text-cyber-muted">
                  Incident ID: <span className="text-cyber-text font-bold">{activeAlertId}</span>
                </div>
                <div>
                  <label className="block text-cyber-muted text-[10px] uppercase mb-1">Resolution Post-Incident Notes:</label>
                  <textarea
                    required
                    rows={4}
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="Provide details on investigations, actions taken, or mitigation strategies..."
                    className="w-full p-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs text-cyber-text focus:outline-none focus:border-cyber-success"
                  />
                </div>
                <div className="flex gap-2">
                  <button
                    type="submit"
                    className="flex-1 py-2 bg-cyber-success text-cyber-bg font-bold text-xs rounded hover:bg-opacity-95"
                  >
                    CONFIRM RESOLVE
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveAlertId(null)}
                    className="px-3 py-2 border border-cyber-border text-cyber-muted hover:text-cyber-text text-xs rounded"
                  >
                    CANCEL
                  </button>
                </div>
              </form>
            </div>
          ) : (
            <div className="glass-panel p-6 text-center py-12 text-cyber-muted font-mono text-xs">
              <ShieldAlert className="w-10 h-10 text-cyber-muted mx-auto mb-3" />
              <span>Select 'Resolve' on an incident to record investigation actions.</span>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
