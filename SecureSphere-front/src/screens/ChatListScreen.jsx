// src/screens/ChatListScreen.jsx
import React, { useState, useEffect } from "react";
import ChatListItem from "../components/ChatListItem.jsx";
import { useAuth } from "../context/AuthContext";
import { messageAPI } from "../services/api";

const ChatListScreen = ({ onSelectChat, currentChat }) => {
  const { user } = useAuth();
  const [chats, setChats] = useState([]);
  const [filteredChats, setFilteredChats] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    if (!user) return;
    loadConversations();
  }, [user]);

  useEffect(() => {
    const results = chats.filter(chat =>
      chat.username.toLowerCase().includes(searchQuery.toLowerCase())
    );
    setFilteredChats(results);
  }, [searchQuery, chats]);

  const loadConversations = async () => {
    setIsLoading(true);
    try {
      // Use the new JWT-based API call (no password needed)
      const response = await messageAPI.getConversations();
      
      if (response.success && Array.isArray(response.conversations)) {
        const chatList = response.conversations.map(conv => ({
          id: conv.conversation_id,
          username: conv.other_user,
          status: "online",
          lastMessage: conv.last_message ? "Encrypted message" : "No messages yet",
          lastUpdated: conv.last_updated,
          avatar: `https://i.pravatar.cc/150?u=${conv.other_user}`,
          unreadCount: Math.floor(Math.random() * 3), // Mock unread count
        }));
        setChats(chatList);
        setFilteredChats(chatList);
      } else {
        await loadContactsFallback();
      }
    } catch (error) {
      console.error("Failed to fetch conversations:", error);
      await loadContactsFallback();
    }
    setIsLoading(false);
  };

  const loadContactsFallback = async () => {
    // Using mock data as a fallback
    const mockContacts = [
      { id: "Sophia123", username: "Sophia123", status: "online", lastMessage: "Let's catch up later!", lastUpdated: new Date().toISOString(), avatar: `https://i.pravatar.cc/150?u=Sophia123`, unreadCount: 2 },
      { id: "Jackson456", username: "Jackson456", status: "offline", lastMessage: "Sounds good.", lastUpdated: new Date(Date.now() - 3600 * 1000 * 5).toISOString(), avatar: `https://i.pravatar.cc/150?u=Jackson456`, unreadCount: 0 },
      { id: "Emma789", username: "Emma789", status: "online", lastMessage: "Can you send me the file?", lastUpdated: new Date(Date.now() - 3600 * 1000 * 24 * 2).toISOString(), avatar: `https://i.pravatar.cc/150?u=Emma789`, unreadCount: 0 },
    ];
    setChats(mockContacts);
    setFilteredChats(mockContacts);
  };

  // ... (keep the rest of the component the same)
  const formatTime = (timestamp) => {
    if (!timestamp) return "";
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.round(diffMs / 60000);
    const diffHours = Math.round(diffMs / 3600000);
    const diffDays = Math.round(diffMs / 86400000);

    if (diffMins < 1) return "Now";
    if (diffMins < 60) return `${diffMins}m`;
    if (diffHours < 24) return `${diffHours}h`;
    if (diffDays < 7) return `${diffDays}d`;
    return date.toLocaleDateString();
  };

  return (
    <div className="w-full md:w-96 border-r border-black/10 dark:border-white/10 flex flex-col h-full bg-background-light dark:bg-background-dark">
      <div className="p-4 border-b border-black/10 dark:border-white/10">
        <h1 className="text-2xl font-bold text-black dark:text-white">Chats</h1>
        <div className="relative mt-4">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-black/40 dark:text-white/40">
            search
          </span>
          <input
            className="w-full rounded-full bg-black/5 dark:bg-white/5 py-2 pl-10 pr-4 text-sm placeholder:text-black/40 dark:placeholder:text-white/40 border-none focus:ring-2 focus:ring-primary"
            placeholder="Search chats..."
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>
      
      <div className="flex-grow overflow-y-auto">
        <nav className="flex flex-col">
          {isLoading ? (
            <p className="p-4 text-black/60 dark:text-white/60 text-center">Loading chats...</p>
          ) : filteredChats.length === 0 ? (
            <p className="p-4 text-black/60 dark:text-white/60 text-center">
              {searchQuery ? "No chats found" : "No conversations yet"}
            </p>
          ) : (
            filteredChats.map((chat) => (
              <ChatListItem
                key={chat.id}
                onClick={() => onSelectChat({
                  name: chat.username,
                  avatar: chat.avatar
                })}
                name={chat.username}
                time={formatTime(chat.lastUpdated)}
                message={chat.lastMessage}
                avatar={chat.avatar}
                unreadCount={chat.unreadCount}
                isActive={currentChat?.name === chat.username}
              />
            ))
          )}
        </nav>
      </div>
    </div>
  );
};

export default ChatListScreen;