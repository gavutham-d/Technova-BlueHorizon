import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { 
  LayoutDashboard, 
  Rss, 
  Network, 
  Search, 
  Grid, 
  ShieldAlert, 
  FileSpreadsheet, 
  Users, 
  Settings, 
  LogOut,
  ShieldAlert as AlertIcon,
  BookOpen
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const navItems = [
    { to: '/', label: 'Home Dashboard', icon: LayoutDashboard },
    { to: '/feed', label: 'Threat Feed', icon: Rss },
    { to: '/campaigns', label: 'Campaign Graph', icon: Network },
    { to: '/hunting', label: 'Threat Hunting', icon: Search },
    { to: '/mitre', label: 'MITRE ATT&CK', icon: Grid },
    { to: '/cves', label: 'CVE Dashboard', icon: BookOpen },
    { to: '/alerts', label: 'Alerts Panel', icon: ShieldAlert },
    { to: '/reports', label: 'Reports Gen', icon: FileSpreadsheet },
    { to: '/users', label: 'Compliance Audits', icon: Users },
    { to: '/settings', label: 'Settings Panel', icon: Settings },
  ];

  return (
    <div className="w-64 h-screen bg-cyber-card border-r border-cyber-border flex flex-col justify-between py-6">
      <div>
        <div className="px-6 mb-8">
          <div className="flex items-center gap-2">
            <AlertIcon className="text-cyber-primary w-8 h-8 animate-pulse" />
            <span className="text-xl font-bold tracking-wider text-cyber-text">
              THREAT<span className="text-cyber-primary">FUSION</span>
            </span>
          </div>
          <div className="text-[10px] text-cyber-primary font-mono tracking-widest mt-1">
            SEC OPS COMMAND CENTER
          </div>
        </div>

        <nav className="flex flex-col gap-1 px-4">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => 
                  `flex items-center gap-3 px-4 py-3 rounded-lg text-sm transition-all duration-200 ${
                    isActive 
                      ? 'bg-cyber-primary bg-opacity-20 text-cyber-primary font-semibold border-l-4 border-cyber-primary' 
                      : 'text-cyber-muted hover:bg-cyber-bg hover:text-cyber-text'
                  }`
                }
              >
                <Icon className="w-5 h-5" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>
      </div>

      <div className="px-4">
        {user && (
          <div className="mb-4 px-4 py-3 bg-cyber-bg bg-opacity-50 border border-cyber-border rounded-xl">
            <div className="text-xs text-cyber-muted">Logged in as</div>
            <div className="font-semibold text-sm truncate text-cyber-text">{user.username}</div>
            <div className={`text-[10px] uppercase font-mono mt-1 ${
              user.role === 'Admin' 
                ? 'text-cyber-danger' 
                : user.role === 'Analyst' 
                  ? 'text-cyber-warning' 
                  : 'text-cyber-success'
            }`}>
              {user.role}
            </div>
          </div>
        )}
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm text-cyber-muted hover:bg-red-500 hover:bg-opacity-15 hover:text-cyber-danger transition-all duration-200"
        >
          <LogOut className="w-5 h-5" />
          <span>Sign Out</span>
        </button>
      </div>
    </div>
  );
};
