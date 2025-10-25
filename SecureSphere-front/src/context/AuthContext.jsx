// src/context/AuthContext.jsx (FIXED - Complete)
import React, { createContext, useState, useContext, useEffect } from 'react';
import { authAPI, setTokens, clearTokens, getAccessToken } from '../services/api';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    const token = getAccessToken();
    if (token) {
      try {
        const response = await authAPI.getMe();
        setUser(response.user);
      } catch (error) {
        console.error('Auth check failed:', error);
        clearTokens();
      }
    }
    setLoading(false);
  };

  const login = async (userData, tokens) => {
    try {
      // Store tokens
      if (tokens) {
        setTokens(tokens);
      }
      // Update user state
      setUser(userData);
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  };

  const logout = async () => {
    try {
      await authAPI.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setUser(null);
      clearTokens();
    }
  };

  const getCredentials = () => {
    // For backward compatibility
    return {
      username: user?.username,
      password: 'jwt_authenticated' // Placeholder since we're using JWT now
    };
  };

  const value = {
    user,
    login,
    logout,
    loading,
    getCredentials
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};