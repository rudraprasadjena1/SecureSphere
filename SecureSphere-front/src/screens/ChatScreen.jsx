// src/screens/ChatScreen.jsx (COMPLETE UPDATED WITH JWT)
import React, { useState, useEffect, useRef } from "react";
import Message from "../components/Message.jsx";
import { messageAPI } from "../services/api";
import { useAuth } from "../context/AuthContext";

const ChatScreen = ({ chatData, onGoBack }) => {
  const [messages, setMessages] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [newMessage, setNewMessage] = useState("");
  const { user } = useAuth(); // Get user from auth context
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    if (chatData) {
      loadMessageHistory();
    }
  }, [chatData]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const loadMessageHistory = async () => {
    if (!chatData) return;

    setIsLoading(true);
    try {
      // Use the new JWT-based API call
      const response = await messageAPI.getHistory(chatData.name);
      if (response.success) {
        setMessages(response.history);
      }
    } catch (error) {
      console.error("Failed to load message history:", error);
      setMessages([]);
    }
    setIsLoading(false);
  };

  const handleSendMessage = async () => {
    if (!newMessage.trim() || !chatData) return;

    const tempId = Date.now();
    const sentMessage = {
      id: tempId,
      message: newMessage,
      timestamp: new Date().toISOString(),
      sender: user?.username, // Get from auth context
      isSender: true,
    };

    // Optimistic update
    setMessages((prev) => [...prev, sentMessage]);
    setNewMessage("");

    try {
      // Use the new JWT-based API call
      await messageAPI.send(chatData.name, newMessage);

      // Reload history to get the actual message from server with proper encryption
      await loadMessageHistory();
    } catch (error) {
      console.error("Failed to send message:", error);
      alert("Failed to send message: " + error.message);
      // Revert optimistic update
      setMessages((prev) => prev.filter((msg) => msg.id !== tempId));
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  if (!chatData) {
    return (
      <div className="flex flex-col items-center justify-center h-screen bg-gray-50 dark:bg-gray-900 text-center">
        <span className="material-symbols-outlined text-6xl text-gray-400 dark:text-gray-600">
          chat_bubble
        </span>
        <p className="text-gray-600 dark:text-gray-400 mt-4 text-lg">
          Select a chat to start messaging
        </p>
      </div>
    );
  }

  return (
    <div className="bg-background-light dark:bg-background-dark font-display flex flex-col h-screen">
      <header className="flex items-center justify-between whitespace-nowrap border-b border-black/10 dark:border-white/10 px-4 py-3 shadow-sm">
        <div className="flex items-center gap-3 text-black dark:text-white">
          <button
            onClick={onGoBack}
            className="flex h-10 w-10 items-center justify-center rounded-full hover:bg-black/5 dark:hover:bg-white/10"
          >
            <span className="material-symbols-outlined">arrow_back</span>
          </button>
          <div className="relative">
            <img
              className="h-10 w-10 rounded-full bg-cover bg-center"
              src={chatData.avatar}
              alt={chatData.name}
            />
            <span className="absolute bottom-0 right-0 block h-2.5 w-2.5 rounded-full border-2 border-background-light dark:border-background-dark bg-green-500"></span>
          </div>
          <div>
            <h2 className="text-lg font-bold">{chatData.name}</h2>
            <p className="text-sm text-green-500 dark:text-green-400">Online</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex h-10 w-10 items-center justify-center rounded-full text-black/60 dark:text-white/60 hover:bg-black/5 dark:hover:bg-white/10">
            <span className="material-symbols-outlined">call</span>
          </button>
          <button className="flex h-10 w-10 items-center justify-center rounded-full text-black/60 dark:text-white/60 hover:bg-black/5 dark:hover:bg-white/10">
            <span className="material-symbols-outlined">videocam</span>
          </button>
          <button className="flex h-10 w-10 items-center justify-center rounded-full text-black/60 dark:text-white/60 hover:bg-black/5 dark:hover:bg-white/10">
            <span className="material-symbols-outlined">info</span>
          </button>
        </div>
      </header>

      <div className="flex-1 overflow-y-auto p-6 md:p-8">
        <div className="space-y-4">
          {isLoading ? (
            <div className="flex justify-center items-center h-full">
              <p className="text-black/60 dark:text-white/60">
                Loading messages...
              </p>
            </div>
          ) : messages.length === 0 ? (
            <div className="text-center text-black/60 dark:text-white/60 py-10">
              <p>No messages yet. Start the conversation!</p>
            </div>
          ) : (
            messages.map((msg, index) => (
              <Message
                key={msg.id || index}
                text={msg.message}
                time={new Date(msg.timestamp).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
                user={msg.sender}
                isSender={msg.isSender}
                avatar={
                  msg.isSender
                    ? "https://i.pravatar.cc/150?u=currentuser" // Placeholder for current user avatar
                    : chatData.avatar
                }
              />
            ))
          )}
          <div ref={messagesEndRef} />
        </div>
      </div>

      <div className="p-4 border-t border-black/10 dark:border-white/10">
        <div className="relative flex items-center">
          <textarea
            className="w-full rounded-lg bg-black/5 dark:bg-white/5 py-3 pl-12 pr-28 text-sm text-black dark:text-white placeholder-black/40 dark:placeholder-white/40 border-none focus:ring-2 focus:ring-primary/50 resize-none"
            placeholder="Type a message..."
            rows="1"
            value={newMessage}
            onChange={(e) => setNewMessage(e.target.value)}
            onKeyPress={handleKeyPress}
            disabled={isLoading}
          />
          <div className="absolute left-2 flex items-center gap-1">
            <button className="flex h-8 w-8 items-center justify-center rounded-full text-black/60 dark:text-white/60 hover:bg-black/10 dark:hover:bg-white/20">
              <span className="material-symbols-outlined text-xl">mood</span>
            </button>
          </div>
          <div className="absolute right-2 flex items-center gap-2">
            <button className="flex h-8 w-8 items-center justify-center rounded-full text-black/60 dark:text-white/60 hover:bg-black/10 dark:hover:bg-white/20">
              <span className="material-symbols-outlined text-xl">
                attach_file
              </span>
            </button>
            <button
              className="flex h-9 w-9 items-center justify-center rounded-full bg-primary text-white shadow-md hover:bg-primary/90 disabled:bg-primary/50 disabled:cursor-not-allowed"
              onClick={handleSendMessage}
              disabled={!newMessage.trim() || isLoading}
            >
              <span className="material-symbols-outlined text-xl">send</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ChatScreen;