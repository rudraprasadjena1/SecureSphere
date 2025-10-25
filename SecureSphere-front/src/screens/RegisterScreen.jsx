// src/screens/RegisterScreen.jsx
import React, { useState, useEffect } from 'react';
import { authAPI } from '../services/api'; // Make sure this is imported

// --- Helper Components for UI Feedback (No changes needed here) ---
const UsernameStatusIcon = ({ status }) => {
  if (status === 'checking') {
    return (
      <div className="w-5 h-5 border-2 border-gray-300 border-t-primary rounded-full animate-spin"></div>
    );
  }
  if (status === 'available') {
    return (
      <span className="material-symbols-outlined text-green-500">check_circle</span>
    );
  }
  if (status === 'unavailable') {
    return (
      <span className="material-symbols-outlined text-red-500">cancel</span>
    );
  }
  return null;
};

const PasswordStrengthIndicator = ({ password }) => {
  const getPasswordStrength = () => {
    let score = 0;
    if (password.length > 8) score++;
    if (password.length > 12) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;

    switch (score) {
      case 5: return { strength: 'Very Strong', color: 'bg-green-500', width: 'w-full' };
      case 4: return { strength: 'Strong', color: 'bg-green-400', width: 'w-4/5' };
      case 3: return { strength: 'Good', color: 'bg-yellow-500', width: 'w-3/5' };
      case 2: return { strength: 'Weak', color: 'bg-orange-500', width: 'w-2/5' };
      default: return { strength: 'Very Weak', color: 'bg-red-500', width: 'w-1/5' };
    }
  };

  if (!password) return null;

  const { strength, color, width } = getPasswordStrength();

  return (
    <div className="flex items-center gap-2 mt-2">
      <div className="flex w-full h-1.5 rounded-full bg-gray-200 dark:bg-gray-700">
        <div className={`h-1.5 rounded-full ${color} ${width} transition-all`}></div>
      </div>
      <p className={`text-xs font-medium text-gray-500 dark:text-gray-400 ${color.replace('bg-', 'text-')}`}>{strength}</p>
    </div>
  );
};

// --- Main Register Screen Component ---

const RegisterScreen = ({ onNavigate }) => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  const [usernameStatus, setUsernameStatus] = useState('idle');
  const [usernameError, setUsernameError] = useState('');
  const [usernameSuggestions, setUsernameSuggestions] = useState([]);

  // --- THIS useEffect NOW CALLS YOUR REAL BACKEND ---
  useEffect(() => {
    const handler = setTimeout(async () => {
      if (username.length < 3) {
        setUsernameStatus('idle');
        setUsernameError('');
        setUsernameSuggestions([]);
        return;
      }
      
      setUsernameStatus('checking');
      setUsernameSuggestions([]);

      try {
        // Calling the real API service now
        const response = await authAPI.checkUsername(username); 
        if (response.available) {
          setUsernameStatus('available');
          setUsernameError('');
        } else {
          setUsernameStatus('unavailable');
          setUsernameError(`Username "${username}" is already taken.`);
          setUsernameSuggestions([
            `${username}${Math.floor(Math.random() * 90 + 10)}`,
            `${username}_dev`,
            `the_${username}`,
          ]);
        }
      } catch (err) {
        setUsernameStatus('idle');
        setUsernameError('Could not verify username. Please try again.');
      }
    }, 500);

    return () => {
      clearTimeout(handler);
    };
  }, [username]);

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');

    if (usernameStatus !== 'available') {
      setError("Please choose an available username.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    
    setLoading(true);

    try {
      const response = await authAPI.register(username, email, password);
      if (response.message === "User registered successfully") {
        alert("Registration successful! Please log in.");
        onNavigate('login');
      }
    } catch (err) {
      setError(err.message || "Registration failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleSuggestionClick = (suggestion) => {
    setUsername(suggestion);
    setUsernameSuggestions([]);
  };

  return (
    <div className="font-display bg-background-light dark:bg-background-dark text-slate-800 dark:text-slate-200 min-h-screen">
      <main className="flex flex-1 items-center justify-center py-12 sm:px-6 lg:px-8 min-h-screen">
        <div className="w-full max-w-md space-y-8 p-8 rounded-2xl bg-white/80 dark:bg-black/20 backdrop-blur-sm shadow-2xl">
          <div className="text-center">
            <h2 className="text-3xl font-extrabold text-slate-900 dark:text-white">
              Create your account
            </h2>
            <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
              Welcome to the Messaging App
            </p>
          </div>

          {error && (
            <div className="bg-red-100 border-l-4 border-red-500 text-red-700 px-4 py-3 rounded-md">
              <p className="font-bold">Error</p>
              <p>{error}</p>
            </div>
          )}

          <form onSubmit={handleRegister} className="space-y-6">
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 block" htmlFor="username">
                  Username
                </label>
                <div className="relative">
                  <input
                    id="username"
                    type="text"
                    autoComplete="username"
                    className="w-full rounded-lg border-slate-300 bg-background-light p-3 text-sm placeholder-slate-400 focus:border-primary focus:ring-2 focus:ring-primary/50 dark:border-slate-700 dark:bg-background-dark dark:placeholder-slate-500 transition-shadow pr-10"
                    placeholder="e.g., john_doe"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                  />
                  <div className="absolute inset-y-0 right-0 px-3 flex items-center">
                    <UsernameStatusIcon status={usernameStatus} />
                  </div>
                </div>
                {usernameError && <p className="text-xs text-red-500 mt-1">{usernameError}</p>}
                {usernameSuggestions.length > 0 && (
                  <div className="mt-2">
                    <span className="text-xs text-gray-500 dark:text-gray-400">Suggestions:</span>
                    <div className="flex gap-2 mt-1">
                      {usernameSuggestions.map(s => (
                        <button
                          key={s}
                          type="button"
                          onClick={() => handleSuggestionClick(s)}
                          className="px-2 py-1 bg-primary/10 text-primary text-xs rounded-full hover:bg-primary/20"
                        >
                          {s}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div>
                <label className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 block" htmlFor="email">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  className="w-full rounded-lg border-slate-300 bg-background-light p-3 text-sm placeholder-slate-400 focus:border-primary focus:ring-2 focus:ring-primary/50 dark:border-slate-700 dark:bg-background-dark dark:placeholder-slate-500 transition-shadow"
                  placeholder="e.g., yourname@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>

              <div>
                <label className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 block" htmlFor="password">
                  Password
                </label>
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    className="w-full rounded-lg border-slate-300 bg-background-light p-3 text-sm placeholder-slate-400 focus:border-primary focus:ring-2 focus:ring-primary/50 dark:border-slate-700 dark:bg-background-dark dark:placeholder-slate-500 transition-shadow pr-10"
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 px-3 flex items-center text-gray-500 dark:text-gray-400 hover:text-primary"
                  >
                    <span className="material-symbols-outlined text-lg">
                      {showPassword ? 'visibility_off' : 'visibility'}
                    </span>
                  </button>
                </div>
                <PasswordStrengthIndicator password={password} />
              </div>

              <div>
                <label className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 block" htmlFor="confirm-password">
                  Confirm Password
                </label>
                <div className="relative">
                  <input
                    id="confirm-password"
                    type={showConfirmPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    className="w-full rounded-lg border-slate-300 bg-background-light p-3 text-sm placeholder-slate-400 focus:border-primary focus:ring-2 focus:ring-primary/50 dark:border-slate-700 dark:bg-background-dark dark:placeholder-slate-500 transition-shadow pr-10"
                    placeholder="Confirm your password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute inset-y-0 right-0 px-3 flex items-center text-gray-500 dark:text-gray-400 hover:text-primary"
                  >
                    <span className="material-symbols-outlined text-lg">
                      {showConfirmPassword ? 'visibility_off' : 'visibility'}
                    </span>
                  </button>
                </div>
              </div>
            </div>

            <button
              disabled={loading || usernameStatus !== 'available'}
              className="w-full rounded-lg bg-primary py-3 text-sm font-bold text-white shadow-lg shadow-primary/30 transition-all hover:bg-primary/90 hover:shadow-primary/50 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 dark:focus:ring-offset-background-dark disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none"
              type="submit"
            >
              <span className="truncate">{loading ? 'Creating Account...' : 'Create Account'}</span>
            </button>
          </form>

          <div className="text-center">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Already have an account?{' '}
              <button
                onClick={() => onNavigate('login')}
                className="font-semibold text-primary hover:underline"
              >
                Sign In
              </button>
            </p>
          </div>
        </div>
      </main>
    </div>
  );
};

export default RegisterScreen;