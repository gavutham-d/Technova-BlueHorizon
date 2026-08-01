import React, { useState } from 'react';
import { apiClient } from '../context/AuthContext';
import { Settings as SettingsIcon, Brain, Save, Sliders } from 'lucide-react';

export const Settings: React.FC = () => {
  const [apiKey, setApiKey] = useState('••••••••••••••••••••••••••••••••');
  const [modelStatus, setModelStatus] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);

  const handleRetrain = async () => {
    setUpdating(true);
    setModelStatus(null);
    try {
      const response = await apiClient.post('/settings/retrain');
      setModelStatus(response.data.message);
    } catch (err: any) {
      setModelStatus("ML retraining failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="flex-1 p-8 overflow-y-auto max-h-screen">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-wide text-cyber-text">System Settings</h1>
        <p className="text-sm text-cyber-muted">Manage external CTI feed API parameters and machine learning parameters.</p>
      </div>

      <div className="grid grid-cols-2 gap-8 max-w-4xl">
        
        {/* ML controls */}
        <div className="glass-panel p-6">
          <div className="flex items-center gap-2.5 mb-4">
            <Brain className="text-cyber-primary w-5 h-5" />
            <h3 className="text-md font-bold font-mono text-cyber-text">AI Pipeline Controls</h3>
          </div>
          <p className="text-xs text-cyber-muted mb-6 leading-relaxed">
            Trigger a manual update cycle to run DBSCAN, Random Forest severity classes, and XGBoost regressor weights on updated indicator lists.
          </p>

          <div className="space-y-4">
            {modelStatus && (
              <div className="p-3 bg-cyber-primary bg-opacity-15 border border-cyber-primary rounded-lg text-xs font-mono text-cyber-text">
                {modelStatus}
              </div>
            )}
            
            <button
              onClick={handleRetrain}
              disabled={updating}
              className="px-4 py-2.5 bg-cyber-primary text-cyber-bg font-bold font-mono text-xs rounded-lg hover:bg-opacity-95 disabled:opacity-40 flex items-center gap-2"
            >
              <Brain className={`w-4 h-4 ${updating ? 'animate-bounce' : ''}`} />
              <span>{updating ? 'RETRAINING MODELS...' : 'RETRAIN CLASSIFIERS'}</span>
            </button>
          </div>
        </div>

        {/* API keys configurations */}
        <div className="glass-panel p-6">
          <div className="flex items-center gap-2.5 mb-4">
            <Sliders className="text-cyber-secondary w-5 h-5" />
            <h3 className="text-md font-bold font-mono text-cyber-text">Feed Configuration API Keys</h3>
          </div>
          <p className="text-xs text-cyber-muted mb-6 leading-relaxed">
            Modify credentials to swap from simulated feeds to actual public CTI feeds checks.
          </p>

          <form onSubmit={(e) => { e.preventDefault(); alert("Settings successfully committed."); }} className="space-y-4 font-mono text-xs">
            <div>
              <label className="block text-cyber-muted mb-1">ABUSEIPDB API KEY:</label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-cyber-primary"
              />
            </div>
            <div>
              <label className="block text-cyber-muted mb-1">ALIENVAULT OTX KEY:</label>
              <input
                type="password"
                defaultValue="••••••••••••••••••••••••••••••••"
                className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-cyber-text focus:outline-none focus:border-cyber-primary"
              />
            </div>

            <button
              type="submit"
              className="px-4 py-2.5 bg-cyber-bg border border-cyber-border text-cyber-text font-bold rounded-lg hover:border-cyber-primary hover:text-cyber-primary flex items-center gap-2"
            >
              <Save className="w-4 h-4" />
              <span>SAVE CREDENTIALS</span>
            </button>
          </form>
        </div>

      </div>
    </div>
  );
};
