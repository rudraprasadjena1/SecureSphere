// src/components/Sidebar.jsx
import React from 'react';
import { useAuth } from '../context/AuthContext';

const Sidebar = ({ activeScreen, setActiveScreen }) => {
  const { user, logout } = useAuth();

  const NavButton = ({ screen, icon, label }) => (
    <button
      onClick={() => setActiveScreen(screen)}
      className={`flex flex-col items-center justify-center gap-1 p-2 w-16 h-16 rounded-lg transition-colors ${
        activeScreen === screen
          ? 'bg-primary text-white'
          : 'text-black/60 dark:text-white/60 hover:bg-black/5 dark:hover:bg-white/5'
      }`}
    >
      <span className="material-symbols-outlined">{icon}</span>
      <span className="text-xs font-medium">{label}</span>
    </button>
  );

  const handleLogout = async () => {
    if (window.confirm('Are you sure you want to logout?')) {
      await logout();
    }
  };

  return (
    <aside className="w-20 bg-background-light dark:bg-gray-900 flex flex-col items-center gap-4 p-2 border-r border-black/10 dark:border-white/10">
      <div className="h-12 w-12 flex items-center justify-center rounded-full bg-primary text-white text-2xl font-bold mb-4">
        C
      </div>
      <nav className="flex flex-col items-center gap-2 w-full">
        <NavButton screen="chats" icon="chat" label="Chats" />
        <NavButton screen="contacts" icon="contacts" label="Contacts" />
        <NavButton screen="settings" icon="settings" label="Settings" />
      </nav>
      
      <div className="mt-auto w-full flex flex-col items-center gap-4">
         <img 
          src="https://i.pravatar.cc/150?u=currentuser" 
          alt="User Avatar" 
          className="h-12 w-12 rounded-full cursor-pointer" 
          onClick={() => setActiveScreen('settings')}
        />
        <button
          onClick={handleLogout}
          className="flex flex-col items-center justify-center gap-1 p-2 w-16 h-16 rounded-lg text-black/60 dark:text-white/60 hover:bg-red-500/10 hover:text-red-500 dark:hover:text-red-400 transition-colors"
          title="Logout"
        >
          <span className="material-symbols-outlined">logout</span>
          <span className="text-xs font-medium">Logout</span>
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;