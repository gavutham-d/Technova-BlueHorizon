import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

interface User {
  username: string;
  role: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (token: string, username: string, role: string) => void;
  logout: () => void;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Set default backend API base URL
export const API_BASE = "http://localhost:8000/api";
export const apiClient = axios.create({
  baseURL: API_BASE
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const savedToken = localStorage.getItem('tf_token');
    const savedUsername = localStorage.getItem('tf_username');
    const savedRole = localStorage.getItem('tf_role');

    if (savedToken && savedUsername && savedRole) {
      setToken(savedToken);
      setUser({ username: savedUsername, role: savedRole });
      apiClient.defaults.headers.common['Authorization'] = `Bearer ${savedToken}`;
    }
    setIsLoading(false);
  }, []);

  const login = (newToken: string, username: string, role: string) => {
    localStorage.setItem('tf_token', newToken);
    localStorage.setItem('tf_username', username);
    localStorage.setItem('tf_role', role);
    setToken(newToken);
    setUser({ username, role });
    apiClient.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
  };

  const logout = () => {
    localStorage.removeItem('tf_token');
    localStorage.removeItem('tf_username');
    localStorage.removeItem('tf_role');
    setToken(null);
    setUser(null);
    delete apiClient.defaults.headers.common['Authorization'];
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout, isLoading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
