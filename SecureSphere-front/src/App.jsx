// src/App.jsx (with error handling)
import React, { useState } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoginScreen from "./screens/LoginScreen";
import RegisterScreen from "./screens/RegisterScreen";
import ChatListScreen from "./screens/ChatListScreen";
import ChatScreen from "./screens/ChatScreen";
import ContactScreen from "./screens/ContactScreen";
import Sidebar from "./components/Sidebar";

// Error Boundary Component
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Error caught by boundary:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-screen items-center justify-center bg-background-light dark:bg-background-dark">
          <div className="text-center p-8 bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md">
            <h1 className="text-2xl font-bold text-red-600 mb-4">Something went wrong</h1>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              {this.state.error?.message || "An unexpected error occurred"}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Inner component that uses the auth context
function AppContent() {
  const { user, loading } = useAuth();
  const [selectedChat, setSelectedChat] = useState(null);
  const [authScreen, setAuthScreen] = useState("login");
  const [activeScreen, setActiveScreen] = useState("chats");

  const handleNavigate = (screen) => setAuthScreen(screen);
  const handleSelectChat = (chatData) => {
    setSelectedChat(chatData);
    setActiveScreen("chats");
  };
  const handleGoBack = () => setSelectedChat(null);

  const handleStartChatFromContacts = (contactData) => {
    setSelectedChat(contactData);
    setActiveScreen("chats");
  };

  // Show loading spinner while checking authentication state
  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background-light dark:bg-background-dark">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <div className="text-lg text-black dark:text-white">Loading...</div>
        </div>
      </div>
    );
  }

  if (!user) {
    if (authScreen === "login") {
      return (
        <LoginScreen onNavigate={handleNavigate} onLoginSuccess={() => {}} />
      );
    }
    return <RegisterScreen onNavigate={handleNavigate} />;
  }

  // Render the main app layout with sidebar and conditional screens
  return (
    <div className="flex h-screen bg-background-light dark:bg-background-dark font-display">
      <Sidebar activeScreen={activeScreen} setActiveScreen={setActiveScreen} />
      <main className="flex-1 flex flex-col">
        {selectedChat ? (
          <ChatScreen chatData={selectedChat} onGoBack={handleGoBack} />
        ) : (
          <>
            {activeScreen === "chats" && (
              <ChatListScreen onSelectChat={handleSelectChat} />
            )}
            {activeScreen === "contacts" && (
              <ContactScreen onStartChat={handleStartChatFromContacts} />
            )}
          </>
        )}
      </main>
    </div>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ErrorBoundary>
  );
}

export default App;