import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Sidebar } from './components/Sidebar';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { ThreatFeed } from './pages/ThreatFeed';
import { ThreatDetails } from './pages/ThreatDetails';
import { ThreatHunting } from './pages/ThreatHunting';
import { CampaignGraph } from './pages/CampaignGraph';
import { MitreDashboard } from './pages/MitreDashboard';
import { CveDashboard } from './pages/CveDashboard';
import { Alerts } from './pages/Alerts';
import { Reports } from './pages/Reports';
import { UserManagement } from './pages/UserManagement';
import { Settings } from './pages/Settings';

const PrivateRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { token, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-cyber-bg flex items-center justify-center">
        <div className="w-10 h-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return token ? <>{children}</> : <Navigate to="/login" replace />;
};

const AppLayout: React.FC = () => {
  return (
    <div className="flex h-screen bg-cyber-bg overflow-hidden">
      <Sidebar />
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/feed" element={<ThreatFeed />} />
        <Route path="/indicator/:id" element={<ThreatDetails />} />
        <Route path="/hunting" element={<ThreatHunting />} />
        <Route path="/campaigns" element={<CampaignGraph />} />
        <Route path="/mitre" element={<MitreDashboard />} />
        <Route path="/cves" element={<CveDashboard />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/users" element={<UserManagement />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
};

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/*"
            element={
              <PrivateRoute>
                <AppLayout />
              </PrivateRoute>
            }
          />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
