// src/components/ChatListItem.jsx
import React from 'react';

const ChatListItem = ({ avatar, name, time, message, unreadCount, isActive, onClick }) => {
  const activeClasses = 'bg-primary/10 dark:bg-primary/20';
  const hoverClasses = 'hover:bg-black/5 dark:hover:bg-white/10';

  return (
    <div
      onClick={onClick}
      className={`flex items-center gap-4 p-3 mx-2 my-1 rounded-lg cursor-pointer transition-colors ${isActive ? activeClasses : hoverClasses}`}
    >
      <div className="relative flex-shrink-0">
        <img
          alt={name}
          className="h-12 w-12 rounded-full object-cover"
          src={avatar}
        />
        <span className="absolute bottom-0 right-0 block h-3 w-3 rounded-full border-2 border-background-light dark:border-background-dark bg-green-500"></span>
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex justify-between items-baseline">
          <p className={`font-bold text-black dark:text-white truncate ${unreadCount > 0 ? 'font-extrabold' : ''}`}>
            {name}
          </p>
          <p className="text-xs text-black/60 dark:text-white/60 flex-shrink-0 ml-2">{time}</p>
        </div>
        <div className="flex justify-between items-center mt-1">
            <p className="text-sm text-black/60 dark:text-white/60 truncate pr-2">{message}</p>
            {unreadCount > 0 && (
                <span className="bg-primary text-white text-xs font-bold rounded-full h-5 w-5 flex items-center justify-center flex-shrink-0">
                    {unreadCount}
                </span>
            )}
        </div>
      </div>
    </div>
  );
};

export default ChatListItem;