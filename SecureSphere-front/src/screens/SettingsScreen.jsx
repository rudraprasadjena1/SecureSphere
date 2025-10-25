// src/screens/SettingsScreen.jsx
import React, { useState } from 'react';
import SettingsMenuItem from "../components/SettingsMenuItem.jsx";

const SettingsScreen = () => {
  const [activeTab, setActiveTab] = useState('Profile');

  return (
    <div className="bg-background-light dark:bg-background-dark font-display h-screen flex text-zinc-900 dark:text-white">
      {/* Sidebar Navigation */}
      <aside className="w-64 flex-shrink-0 border-r border-zinc-200/50 dark:border-zinc-800/50 flex flex-col p-4">
        <h1 className="text-xl font-bold px-3 py-2 mb-4">Settings</h1>
        <div className="flex items-center gap-4 mb-6 p-3">
          <div className="relative">
            <img alt="User's avatar" className="size-14 rounded-full" src="https://i.pravatar.cc/150?u=currentuser" />
            <span className="absolute bottom-0 right-0 block h-3.5 w-3.5 rounded-full border-2 border-background-light dark:border-background-dark bg-green-500"></span>
          </div>
          <div>
            <p className="font-bold">Sophia Clark</p>
            <p className="text-sm text-zinc-500 dark:text-zinc-400">Available</p>
          </div>
        </div>
        <nav className="space-y-1">
          <SettingsMenuItem isActive={activeTab === 'Profile'} label="Profile" onClick={() => setActiveTab('Profile')} icon={<span className="material-symbols-outlined">person</span>} />
          <SettingsMenuItem isActive={activeTab === 'Account'} label="Account" onClick={() => setActiveTab('Account')} icon={<span className="material-symbols-outlined">key</span>} />
          <SettingsMenuItem isActive={activeTab === 'Notifications'} label="Notifications" onClick={() => setActiveTab('Notifications')} icon={<span className="material-symbols-outlined">notifications</span>} />
          <SettingsMenuItem isActive={activeTab === 'Privacy'} label="Privacy" onClick={() => setActiveTab('Privacy')} icon={<span className="material-symbols-outlined">lock</span>} />
          <SettingsMenuItem isActive={activeTab === 'Help'} label="Help" onClick={() => setActiveTab('Help')} icon={<span className="material-symbols-outlined">help</span>} />
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto p-8">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-3xl font-bold mb-8">{activeTab}</h2>
          
          {/* Profile Section */}
          {activeTab === 'Profile' && (
            <div className="space-y-8">
              {/* Photo */}
              <div className="flex items-center gap-8 pb-8 border-b border-zinc-200/50 dark:border-zinc-800/50">
                <div className="w-1/3">
                  <h3 className="font-semibold text-lg">Photo</h3>
                  <p className="text-sm text-zinc-500 dark:text-zinc-400">Your profile picture.</p>
                </div>
                <div className="flex-1 flex items-center gap-6">
                  <img alt="User's avatar" className="size-20 rounded-full" src="https://i.pravatar.cc/150?u=currentuser" />
                  <div className="flex gap-2">
                    <button className="px-4 py-2 rounded-lg text-sm font-semibold bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors">Change</button>
                    <button className="px-4 py-2 rounded-lg text-sm font-semibold text-red-500 hover:bg-red-500/10 transition-colors">Remove</button>
                  </div>
                </div>
              </div>
              {/* Name */}
              <div className="flex items-start gap-8">
                <div className="w-1/3">
                  <h3 className="font-semibold text-lg">Name</h3>
                  <p className="text-sm text-zinc-500 dark:text-zinc-400">This will be visible to your contacts.</p>
                </div>
                <div className="flex-1">
                  <input className="w-full bg-zinc-100 dark:bg-zinc-800 border-transparent rounded-lg p-3 focus:ring-2 focus:ring-primary focus:border-transparent transition" type="text" defaultValue="Sophia Clark" />
                </div>
              </div>
              {/* Bio */}
              <div className="flex items-start gap-8">
                <div className="w-1/3">
                  <h3 className="font-semibold text-lg">Bio</h3>
                  <p className="text-sm text-zinc-500 dark:text-zinc-400">A short description about yourself.</p>
                </div>
                <div className="flex-1">
                  <textarea className="w-full bg-zinc-100 dark:bg-zinc-800 border-transparent rounded-lg p-3 focus:ring-2 focus:ring-primary focus:border-transparent transition" rows="3" defaultValue="Available"></textarea>
                </div>
              </div>
              
              <div className="flex justify-end gap-4 pt-6">
                <button className="px-6 py-2.5 rounded-lg text-sm font-semibold bg-zinc-200 dark:bg-zinc-800 hover:bg-zinc-300 dark:hover:bg-zinc-700 transition-colors">Cancel</button>
                <button className="px-6 py-2.5 rounded-lg text-sm font-semibold bg-primary text-white hover:bg-primary/90 transition-opacity">Save Changes</button>
              </div>
            </div>
          )}
          
          {/* Placeholder for other tabs */}
          {activeTab !== 'Profile' && (
            <div className="text-center py-20">
              <p className="text-zinc-500 dark:text-zinc-400">{activeTab} settings will be displayed here.</p>
            </div>
          )}

        </div>
      </main>
    </div>
  );
};

export default SettingsScreen;