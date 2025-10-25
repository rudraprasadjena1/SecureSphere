// src/components/Message.jsx
import React from 'react';

const Message = ({ text, time, user, isSender, avatar }) => {
  const messageClass = isSender ? 'items-end' : 'items-start';
  const bubbleClass = isSender 
    ? 'bg-primary text-white rounded-br-none' 
    : 'bg-gray-200 dark:bg-gray-700 text-black dark:text-white rounded-bl-none';

  return (
    <div className={`flex flex-col ${messageClass}`}>
      <div className={`flex items-end gap-2 max-w-md ${isSender ? 'flex-row-reverse' : 'flex-row'}`}>
        <img
          className="h-8 w-8 rounded-full object-cover"
          src={avatar}
          alt={user}
        />
        <div
          className={`px-4 py-2.5 rounded-2xl ${bubbleClass}`}
          style={{ wordBreak: 'break-word' }}
        >
          <p className="text-sm">{text}</p>
        </div>
      </div>
      <p className={`text-xs text-black/60 dark:text-white/60 mt-1 ${isSender ? 'mr-10 text-right' : 'ml-10 text-left'}`}>
        {time}
      </p>
    </div>
  );
};

export default Message;