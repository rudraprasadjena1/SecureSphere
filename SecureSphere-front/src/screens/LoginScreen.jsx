// src/screens/LoginScreen.jsx (FIXED - Complete with Icons)
import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { authAPI, setTokens } from '../services/api';

// Icon Components
const GoogleIcon = () => (
  <svg className="h-5 w-5" viewBox="0 0 24 24">
    <path
      fill="currentColor"
      d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
    />
    <path
      fill="currentColor"
      d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
    />
    <path
      fill="currentColor"
      d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
    />
    <path
      fill="currentColor"
      d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
    />
  </svg>
);

const FacebookIcon = () => (
  <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
    <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" />
  </svg>
);

const LogoIcon = () => (
  <div className="flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-primary to-primary/80 shadow-lg">
    <svg
      className="h-8 w-8 text-white"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
      />
    </svg>
  </div>
);

const LoginScreen = ({ onLoginSuccess, onNavigate }) => {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await authAPI.login(email, password);

      if (response.message === 'Login successful') {
        // Store tokens using the imported setTokens function
        setTokens({
          access_token: response.tokens.access_token,
          refresh_token: response.tokens.refresh_token
        });
        
        // Update auth context - pass both user data and tokens
        await login(response.user, response.tokens);
        onLoginSuccess(); // This can be used for any additional side-effects
      } else {
        // Handle cases where the API returns a 200 OK but login is not successful
        setError(response.error || 'Login failed. Please try again.');
      }
    } catch (error) {
      // This will now correctly handle actual network or server errors (like 401)
      console.error('Login error:', error);
      setError(error.message || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const fillDemoCredentials = () => {
    setEmail('demo@user.com');
    setPassword('password123');
  };

  return (
    <div className="font-display bg-background-light dark:bg-background-dark text-slate-800 dark:text-slate-200 min-h-screen">
      <main className="flex flex-1 items-center justify-center py-12 sm:px-6 lg:px-8 min-h-screen">
        <div className="w-full max-w-md space-y-8 p-8 rounded-2xl bg-white/80 dark:bg-black/20 backdrop-blur-sm shadow-2xl">
          <div className="text-center">
            <div className="flex justify-center mb-4">
              <LogoIcon />
            </div>
            <h2 className="text-3xl font-extrabold text-slate-900 dark:text-white">
              Log in to Connect
            </h2>
            <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
              Welcome back! Please enter your details.
            </p>
          </div>

          {error && (
            <div className="bg-red-100 border-l-4 border-red-500 text-red-700 px-4 py-3 rounded-md">
              <p className="font-bold">Error</p>
              <p>{error}</p>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-6">
            <div className="space-y-4">
              <div>
                <label className="sr-only" htmlFor="email">
                  Email or Username
                </label>
                <input
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  className="w-full rounded-lg border-slate-300 bg-background-light p-3 text-sm placeholder-slate-400 focus:border-primary focus:ring-2 focus:ring-primary/50 dark:border-slate-700 dark:bg-background-dark dark:placeholder-slate-500 transition-shadow"
                  id="email"
                  name="email"
                  placeholder="Email or Username"
                  required
                  type="text"
                />
              </div>
              <div>
                <label className="sr-only" htmlFor="password">
                  Password
                </label>
                <input
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  className="w-full rounded-lg border-slate-300 bg-background-light p-3 text-sm placeholder-slate-400 focus:border-primary focus:ring-2 focus:ring-primary/50 dark:border-slate-700 dark:bg-background-dark dark:placeholder-slate-500 transition-shadow"
                  id="password"
                  name="password"
                  placeholder="Password"
                  required
                  type="password"
                />
              </div>
              <div className="text-right">
                <a
                  className="text-sm font-medium text-primary hover:text-primary/90"
                  href="#"
                >
                  Forgot password?
                </a>
              </div>
              <div>
                <button
                  disabled={loading}
                  className="w-full rounded-lg bg-primary py-3 text-sm font-bold text-white shadow-lg shadow-primary/30 transition-all hover:bg-primary/90 hover:shadow-primary/50 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 dark:focus:ring-offset-background-dark disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none"
                  type="submit"
                >
                  {loading ? 'Logging in...' : 'Log In'}
                </button>
              </div>
            </div>
          </form>

          <div className="text-center">
            <button
              type="button"
              onClick={fillDemoCredentials}
              className="text-sm text-primary hover:text-primary/90 font-medium"
            >
              Fill Demo Credentials
            </button>
          </div>

          <div className="relative">
            <div
              aria-hidden="true"
              className="absolute inset-0 flex items-center"
            >
              <div className="w-full border-t border-slate-300 dark:border-slate-700"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="bg-white/80 dark:bg-black/20 px-2 text-slate-500 dark:text-slate-400">
                Or continue with
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <button
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white py-2.5 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 transition-colors"
              type="button"
            >
              <GoogleIcon />
              Google
            </button>
            <button
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white py-2.5 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 transition-colors"
              type="button"
            >
              <FacebookIcon />
              Facebook
            </button>
          </div>

          <p className="text-center text-sm text-slate-500 dark:text-slate-400">
            Don't have an account?
            <button
              onClick={() => onNavigate('register')}
              className="font-medium text-primary hover:text-primary/90 ml-1"
            >
              Sign up
            </button>
          </p>
        </div>
      </main>
    </div>
  );
};

export default LoginScreen;