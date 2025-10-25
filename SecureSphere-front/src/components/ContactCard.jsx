// src/components/ContactCard.jsx
import React from 'react';

const ContactCard = ({ user, onAdd, onMessage, isContact, hasPendingRequest }) => {
  const username = user.username || user.id || 'Unknown User';
  const email = user.email || `${username}@example.com`;
  const avatar = user.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=random`;
  const isOnline = user.is_online || (Math.random() > 0.5); // Mock online status
  
  return (
    <div className="flex flex-col items-center gap-4 rounded-xl bg-black/5 dark:bg-white/5 p-4 transition-colors hover:bg-black/10 dark:hover:bg-white/10 text-center">
      <div className="relative">
        <img
          className="h-20 w-20 rounded-full object-cover shadow-md"
          src={avatar}
          alt={username}
        />
        <div className={`absolute -bottom-1 -right-1 h-4 w-4 rounded-full border-2 border-white dark:border-gray-800 ${
          isOnline ? 'bg-green-500' : 'bg-gray-400'
        }`}></div>
      </div>
      
      <div className="flex-1 min-w-0">
        <p className="font-bold text-black dark:text-white truncate">{username}</p>
        <p className="text-sm text-black/60 dark:text-white/60 truncate">{email}</p>
      </div>
      
      <div className="flex gap-2 w-full justify-center">
        {isContact && onMessage && (
          <button
            onClick={() => onMessage(user)}
            className="w-full rounded-lg bg-primary px-3 py-2 text-sm text-white font-semibold hover:bg-primary/90 transition-colors flex items-center justify-center gap-1"
          >
            <span className="material-symbols-outlined text-base">message</span>
            Chat
          </button>
        )}
        
        {!isContact && (
          <button
            onClick={() => onAdd(user.id)}
            disabled={hasPendingRequest}
            className="w-full rounded-lg bg-blue-500 px-3 py-2 text-sm text-white font-semibold hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-1.5"
          >
            {hasPendingRequest ? (
              <>
                <span className="material-symbols-outlined text-base">schedule</span>
                Pending
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-base">person_add</span>
                Add
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
};

export default ContactCard;