// src/components/SettingsMenuItem.jsx
import React from 'react';

const SettingsMenuItem = ({ icon, label, isActive, onClick }) => (
  <button
    onClick={onClick}
    className={`w-full flex items-center gap-3 rounded-lg px-3 py-2 transition-colors text-left ${
      isActive
        ? 'bg-primary/10 dark:bg-primary/20 text-primary'
        : 'text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800'
    }`}
  >
    {icon}
    <span className={`font-medium ${isActive ? 'text-primary' : ''}`}>{label}</span>
  </button>
);

export default SettingsMenuItem;