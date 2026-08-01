import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { apiClient } from '../context/AuthContext';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, 
  PieChart, Pie, Cell, Legend
} from 'recharts';
import { 
  Activity, ShieldAlert, CheckCircle, Database, 
  RefreshCw, TrendingUp, AlertTriangle, Play 
} from 'lucide-react';
import { Link } from 'react-router-dom';

interface DashboardMetrics {
  total_indicators: number;
  total_alerts: number;
  active_alerts: number;
  average_risk_score: number;
  severity_distribution: Record<string, number>;
  type_distribution: Record<string, number>;
  feeds: Array<{ name: string; indicators_count: number; last_harvested: string | null; status: string }>;
}

interface QuickAlert {
  _id: string;
  indicator_value: string;
  ioc_type: string;
  severity: string;
  risk_score: number;
  trigger_reason: string;
  created_at: string;
}

export const Dashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<QuickAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchDashboardData = useCallback(async (signal?: AbortSignal) => {
    try {
      const metricRes = await apiClient.get('/reports/metrics', { signal });
      setMetrics(metricRes.data);
      
      const alertRes = await apiClient.get('/alerts?status_filter=Unassigned', { signal });
      setRecentAlerts(alertRes.data.slice(0, 5));
    } catch (err: any) {
      if (err.name !== 'CanceledError' && err.name !== 'AbortError') {
        console.error("Error loading dashboard metrics:", err);
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetchDashboardData(controller.signal);
    return () => controller.abort();
  }, [fetchDashboardData]);

  const handleManualHarvest = async () => {
    if (refreshing) return;
    setRefreshing(true);
    try {
      await apiClient.post('/settings/harvest');
      await fetchDashboardData();
    } catch (err) {
      console.error("Error triggering manual harvest:", err);
      setRefreshing(false);
    }
  };

  // Prep Chart Data
  const severityData = useMemo(() => {
    if (!metrics) return [];
    return [
      { name: 'Low', count: metrics.severity_distribution.Low || 0, fill: '#10b981' },
      { name: 'Medium', count: metrics.severity_distribution.Medium || 0, fill: '#f59e0b' },
      { name: 'High', count: metrics.severity_distribution.High || 0, fill: '#ef4444' },
      { name: 'Critical', count: metrics.severity_distribution.Critical || 0, fill: '#7f1d1d' },
    ];
  }, [metrics]);

  const typeData = useMemo(() => {
    if (!metrics) return [];
    return [
      { name: 'IP Addresses', value: metrics.type_distribution.ip || 0, color: '#06b6d4' },
      { name: 'Domains', value: metrics.type_distribution.domain || 0, color: '#8b5cf6' },
      { name: 'Hashes', value: metrics.type_distribution.hash || 0, color: '#eab308' },
      { name: 'URLs', value: metrics.type_distribution.url || 0, color: '#ec4899' },
    ];
  }, [metrics]);

  if (loading || !metrics) {
    return (
      <div className="flex-1 min-h-screen bg-cyber-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-2">
          <div className="w-10 h-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <div className="text-sm font-mono text-cyber-primary tracking-widest uppercase">LOADING SYSTEM METRICS...</div>
        </div>
      </div>
    );
  }

  const COLORS = ['#06b6d4', '#8b5cf6', '#eab308', '#ec4899'];

  const getSystemStatus = () => {
    if (metrics.active_alerts > 15) return { text: "BREACHED POSTURE", color: "text-cyber-danger border-cyber-danger bg-red-500 bg-opacity-10", icon: AlertTriangle };
    if (metrics.active_alerts > 0) return { text: "SUSPICIOUS THREATS DETECTED", color: "text-cyber-warning border-cyber-warning bg-amber-500 bg-opacity-10", icon: ShieldAlert };
    return { text: "SECURE POSTURE", color: "text-cyber-success border-cyber-success bg-emerald-500 bg-opacity-10", icon: CheckCircle };
  };

  const StatusIcon = getSystemStatus().icon;

  return (
    <div className="flex-1 p-8 overflow-y-auto max-h-screen">
      {/* Header section */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-wide text-cyber-text">SOC Operations Center</h1>
          <p className="text-sm text-cyber-muted">Aggregated Cyber Threat Intelligence and automated ML classifications.</p>
        </div>
        <div className="flex items-center gap-4">
          <div className={`px-4 py-2 border rounded-xl flex items-center gap-2 font-mono text-xs font-semibold ${getSystemStatus().color}`}>
            <StatusIcon className="w-4 h-4 animate-pulse" />
            <span>{getSystemStatus().text}</span>
          </div>
          <button
            onClick={handleManualHarvest}
            disabled={refreshing}
            className="px-4 py-2 bg-cyber-card border border-cyber-border rounded-xl text-xs hover:border-cyber-primary transition-all flex items-center gap-2 font-semibold"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>{refreshing ? 'HARVESTING FEEDS...' : 'POLL FEEDS'}</span>
          </button>
        </div>
      </div>

      {/* Grid of metrics */}
      <div className="grid grid-cols-4 gap-6 mb-8">
        <div className="glass-panel p-6 flex items-center justify-between">
          <div>
            <div className="text-xs text-cyber-muted uppercase tracking-wider font-mono">Aggregated IOCs</div>
            <div className="text-3xl font-bold mt-1 text-cyber-primary">{metrics.total_indicators}</div>
          </div>
          <div className="p-3 bg-cyber-primary bg-opacity-10 rounded-xl text-cyber-primary">
            <Database className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-panel p-6 flex items-center justify-between">
          <div>
            <div className="text-xs text-cyber-muted uppercase tracking-wider font-mono">Unresolved Incidents</div>
            <div className="text-3xl font-bold mt-1 text-cyber-danger">{metrics.active_alerts}</div>
          </div>
          <div className="p-3 bg-cyber-danger bg-opacity-10 rounded-xl text-cyber-danger">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-panel p-6 flex items-center justify-between">
          <div>
            <div className="text-xs text-cyber-muted uppercase tracking-wider font-mono">Avg ML Risk Score</div>
            <div className="text-3xl font-bold mt-1 text-cyber-warning">{metrics.average_risk_score} <span className="text-xs text-cyber-muted font-normal">/100</span></div>
          </div>
          <div className="p-3 bg-cyber-warning bg-opacity-10 rounded-xl text-cyber-warning">
            <Activity className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-panel p-6 flex items-center justify-between">
          <div>
            <div className="text-xs text-cyber-muted uppercase tracking-wider font-mono">Active CTI Feeds</div>
            <div className="text-3xl font-bold mt-1 text-cyber-success">
              {metrics.feeds.filter(f => f.status === 'active').length}
              <span className="text-xs text-cyber-muted font-normal"> / {metrics.feeds.length}</span>
            </div>
          </div>
          <div className="p-3 bg-cyber-success bg-opacity-10 rounded-xl text-cyber-success">
            <CheckCircle className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Visual Charts section */}
      <div className="grid grid-cols-2 gap-8 mb-8">
        <div className="glass-panel p-6">
          <h3 className="text-md font-bold mb-4 font-mono text-cyber-text">Threat Severity Profiles (Random Forest Classifier)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <XAxis dataKey="name" stroke="#9ca3af" fontSize={11} tickLine={false} />
                <YAxis stroke="#9ca3af" fontSize={11} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #1f2937', color: '#f3f4f6' }}
                  cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel p-6">
          <h3 className="text-md font-bold mb-4 font-mono text-cyber-text">Normalized STIX 2.1 Indicators Types</h3>
          <div className="h-64 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={typeData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {typeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#111827', border: '1px solid #1f2937', color: '#f3f4f6' }} />
                <Legend formatter={(value, entry) => <span className="text-xs text-cyber-muted font-mono">{value}</span>} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Alerts and Threat Feeds list */}
      <div className="grid grid-cols-3 gap-8">
        {/* Critical Alerts panel */}
        <div className="col-span-2 glass-panel p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-md font-bold font-mono text-cyber-text">Incident Triage (Active Critical Alerts)</h3>
            <Link to="/alerts" className="text-xs text-cyber-primary hover:underline font-semibold font-mono">VIEW ALL TRIAGE →</Link>
          </div>
          <div className="divide-y divide-cyber-border">
            {recentAlerts.length > 0 ? (
              recentAlerts.map(alert => (
                <div key={alert._id} className="py-3.5 flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold font-mono text-cyber-text">{alert.indicator_value}</span>
                      <span className={`text-[10px] uppercase px-2 py-0.5 rounded-full font-mono font-bold ${
                        alert.severity === 'Critical' ? 'bg-red-950 text-red-400' : 'bg-orange-950 text-orange-400'
                      }`}>
                        {alert.severity}
                      </span>
                    </div>
                    <div className="text-xs text-cyber-muted mt-1">{alert.trigger_reason}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs font-mono font-bold text-cyber-warning">{alert.risk_score.toFixed(1)} / 100</div>
                    <div className="text-[10px] text-cyber-muted mt-1">XGBoost Score</div>
                  </div>
                </div>
              ))
            ) : (
              <div className="py-8 text-center text-sm text-cyber-muted font-mono">
                No active critical alerts found. Posture is secure.
              </div>
            )}
          </div>
        </div>

        {/* Public Feed Status panel */}
        <div className="glass-panel p-6">
          <h3 className="text-md font-bold mb-4 font-mono text-cyber-text">Public Feeds Status</h3>
          <div className="space-y-4">
            {metrics.feeds.map(feed => (
              <div key={feed.name} className="flex items-center justify-between">
                <div>
                  <div className="text-sm font-bold text-cyber-text">{feed.name}</div>
                  <div className="text-[10px] text-cyber-muted font-mono">
                    Ingested: {feed.indicators_count} IOCs
                  </div>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className={`w-2.5 h-2.5 rounded-full ${feed.status === 'active' ? 'bg-cyber-success animate-pulse' : 'bg-cyber-danger'}`}></span>
                  <span className="text-xs font-mono uppercase text-cyber-muted">{feed.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
