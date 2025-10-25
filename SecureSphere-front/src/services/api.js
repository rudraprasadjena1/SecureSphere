// src/services/api.js (FIXED - Complete with proper exports)
const API_BASE_URL = 'http://localhost:5000/api';

// Token management
let accessToken = localStorage.getItem('access_token');
let refreshToken = localStorage.getItem('refresh_token');

// Export token management functions
export const setTokens = (tokens) => {
  accessToken = tokens.access_token;
  refreshToken = tokens.refresh_token;
  localStorage.setItem('access_token', accessToken);
  localStorage.setItem('refresh_token', refreshToken);
};

export const clearTokens = () => {
  accessToken = null;
  refreshToken = null;
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
};

export const getAccessToken = () => accessToken;

export const getRefreshToken = () => refreshToken;

async function apiCall(endpoint, options = {}) {
  try {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    // Add Authorization header if token exists
    if (accessToken) {
      headers['Authorization'] = `Bearer ${accessToken}`;
    }

    console.log(`API Call: ${endpoint}`, {
      method: options.method || 'GET',
      headers: headers
    });

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      headers,
      ...options,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    // Handle token expiration
    if (response.status === 401 && refreshToken) {
      try {
        const refreshResponse = await fetch(`${API_BASE_URL}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });

        if (refreshResponse.ok) {
          const refreshData = await refreshResponse.json();
          setTokens(refreshData);
          
          // Retry original request with new token
          headers['Authorization'] = `Bearer ${refreshData.access_token}`;
          const retryResponse = await fetch(`${API_BASE_URL}${endpoint}`, {
            headers,
            ...options,
            body: options.body ? JSON.stringify(options.body) : undefined,
          });
          return await retryResponse.json();
        } else {
          clearTokens();
          window.location.href = '/login';
          throw new Error('Session expired. Please login again.');
        }
      } catch (error) {
        clearTokens();
        window.location.href = '/login';
        throw error;
      }
    }

    const data = await response.json();
    
    console.log(`API Response: ${endpoint}`, {
      status: response.status,
      data: data
    });

    if (!response.ok) {
      throw new Error(data.error || 'API request failed');
    }

    return data;
  } catch (error) {
    console.error('API call error:', error);
    throw error;
  }
}

// Auth API calls
export const authAPI = {
  login: (username, password) => 
    apiCall('/auth/login', {
      method: 'POST',
      body: { username, password }
    }),
  
  register: (username, email, password) => 
    apiCall('/auth/register', {
      method: 'POST',
      body: { username, email, password }
    }),

  refresh: (refreshToken) =>
    apiCall('/auth/refresh', {
      method: 'POST',
      body: { refresh_token: refreshToken }
    }),

  logout: () => 
    apiCall('/auth/logout', {
      method: 'POST'
    }),

  getMe: () =>
    apiCall('/auth/me'),

  checkUsername: (username) =>
    apiCall('/auth/check-username', {
      method: 'POST',
      body: { username }
    }),
  
  getUsers: () => 
    apiCall('/auth/users'),
};

// Message API calls (updated to not require password in request body)
export const messageAPI = {
  send: (recipient, message) =>
    apiCall('/message/send', {
      method: 'POST',
      body: { recipient, message }
    }),

  getHistory: (user2) =>
    apiCall('/message/history', {
      method: 'POST',
      body: { user2 }
    }),

  getConversations: () =>
    apiCall('/message/conversations', {
      method: 'POST'
    }),

  // Add the POST method for conversations
  getConversationsPost: () =>
    apiCall('/message/conversations', {
      method: 'POST',
      body: {}
    })
};

// Export the main apiCall function for custom requests
export { apiCall };