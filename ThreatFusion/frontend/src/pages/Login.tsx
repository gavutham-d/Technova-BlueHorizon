import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth, apiClient } from '../context/AuthContext';
import { Shield, Lock, User, Terminal } from 'lucide-react';

export const Login: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      const response = await apiClient.post('/auth/login', { username, password });
      login(response.data.access_token, response.data.username, response.data.role);
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.detail || "Authentication Failed. Please check credentials.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickSelect = async (userType: 'admin' | 'analyst' | 'readonly') => {
    setError(null);
    setIsSubmitting(true);
    
    // Credentials mapping
    const creds = {
      admin: { u: 'admin', p: 'admin123', r: 'Admin' },
      analyst: { u: 'analyst_soc', p: 'analyst123', r: 'Analyst' },
      readonly: { u: 'guest_observer', p: 'guest123', r: 'Read-Only' }
    };

    const target = creds[userType];
    
    try {
      // First try to register in case db was cleared/newly seeded
      try {
        await apiClient.post('/auth/register', { 
          username: target.u, 
          email: `${target.u}@threatfusion.local`, 
          password: target.p,
          role: target.r
        });
      } catch (e) {
        // user might already exist, proceed to login
      }
      
      const response = await apiClient.post('/auth/login', { username: target.u, password: target.p });
      login(response.data.access_token, response.data.username, response.data.role);
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.detail || "Quick login failed. Database might be initializing.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background visual neon matrices */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyber-primary bg-opacity-5 rounded-full blur-[100px] pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyber-secondary bg-opacity-5 rounded-full blur-[100px] pointer-events-none"></div>
      
      <div className="w-full max-w-md glass-panel p-8 glow-cyan relative z-10">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center p-3 bg-cyber-primary bg-opacity-10 rounded-full mb-3">
            <Shield className="w-8 h-8 text-cyber-primary" />
          </div>
          <h2 className="text-2xl font-bold tracking-wider text-cyber-text">THREAT FUSION</h2>
          <p className="text-xs text-cyber-muted font-mono uppercase tracking-widest mt-1">SOC GATEWAY ACCESS</p>
        </div>

        {error && (
          <div className="mb-6 p-3 bg-cyber-danger bg-opacity-10 border border-cyber-danger text-cyber-danger text-xs rounded-lg font-mono">
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-cyber-muted uppercase mb-1">Username</label>
            <div className="relative">
              <User className="absolute left-3 top-3 w-4 h-4 text-cyber-muted" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter SOC username"
                className="w-full pl-10 pr-4 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-cyber-text focus:outline-none focus:border-cyber-primary transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-cyber-muted uppercase mb-1">Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 w-4 h-4 text-cyber-muted" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full pl-10 pr-4 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-cyber-text focus:outline-none focus:border-cyber-primary transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full py-3 bg-cyber-primary text-cyber-bg font-bold rounded-lg text-sm transition-all duration-200 hover:bg-opacity-90 active:scale-95 flex items-center justify-center gap-2"
          >
            {isSubmitting ? (
              <span className="w-5 h-5 border-2 border-cyber-bg border-t-transparent rounded-full animate-spin"></span>
            ) : (
              <>
                <Terminal className="w-4 h-4" />
                <span>ESTABLISH SESSION</span>
              </>
            )}
          </button>
        </form>

        <div className="mt-8 pt-6 border-t border-cyber-border">
          <div className="text-[10px] text-center font-mono text-cyber-muted uppercase tracking-widest mb-3">
            Bypass / Evaluation Profiles
          </div>
          <div className="grid grid-cols-3 gap-2">
            <button
              onClick={() => handleQuickSelect('admin')}
              className="px-2 py-1.5 bg-cyber-bg border border-cyber-danger border-opacity-40 text-cyber-danger text-[10px] font-mono rounded hover:bg-cyber-danger hover:bg-opacity-10 transition-colors"
            >
              ADMIN
            </button>
            <button
              onClick={() => handleQuickSelect('analyst')}
              className="px-2 py-1.5 bg-cyber-bg border border-cyber-warning border-opacity-40 text-cyber-warning text-[10px] font-mono rounded hover:bg-cyber-warning hover:bg-opacity-10 transition-colors"
            >
              ANALYST
            </button>
            <button
              onClick={() => handleQuickSelect('readonly')}
              className="px-2 py-1.5 bg-cyber-bg border border-cyber-success border-opacity-40 text-cyber-success text-[10px] font-mono rounded hover:bg-cyber-success hover:bg-opacity-10 transition-colors"
            >
              OBSERVER
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
