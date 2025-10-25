// src/screens/ContactScreen.jsx
import React, { useState, useEffect } from "react";
import ContactCard from "../components/ContactCard.jsx";
import axios from "axios";
import { useAuth } from "../context/AuthContext";

const API_URL = "http://localhost:5000/api";

const ContactScreen = ({ onStartChat }) => {
  const { user, getCredentials } = useAuth();
  const [contacts, setContacts] = useState([]);
  const [searchResults, setSearchResults] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const currentUserId = getCredentials()?.username;

  useEffect(() => {
    if (!currentUserId) return;
    fetchContacts();
  }, [currentUserId]);

  const fetchContacts = async () => {
    setIsLoading(true);
    setError("");
    try {
      const response = await axios.get(`${API_URL}/contacts/contacts`, {
        params: { user_id: currentUserId },
      });
      if (response.data.success && Array.isArray(response.data.contacts)) {
        setContacts(response.data.contacts);
      }
    } catch (err) {
      console.error("Failed to fetch contacts:", err);
      setError("Could not load your contacts. Please try again later.");
      setContacts([]);
    }
    setIsLoading(false);
  };

  const handleSearch = async (query) => {
    setSearchQuery(query);
    if (query.length < 2) {
      setSearchResults([]);
      return;
    }
    try {
      const response = await axios.get(`${API_URL}/contacts/search`, {
        params: { q: query, current_user_id: currentUserId },
      });
      if (response.data.success && Array.isArray(response.data.results)) {
        setSearchResults(response.data.results);
      }
    } catch (error) {
      console.error("Failed to search users:", error);
    }
  };

  const handleAddContact = async (toUserId) => {
    if (!currentUserId) {
      alert("Could not identify current user. Please log in again.");
      return;
    }
    try {
      const requestResponse = await axios.post(`${API_URL}/contacts/request`, {
        from_user: currentUserId,
        to_user: toUserId,
        message: "Hi, I'd like to add you as a contact.",
      });

      if (requestResponse.data.success) {
        const acceptResponse = await axios.post(`${API_URL}/contacts/accept`, {
          request_id: requestResponse.data.request.id,
          user_id: toUserId,
        });

        if (acceptResponse.data.success) {
          alert("Contact added successfully! (Auto-accepted for testing)");
          setSearchResults((prev) =>
            prev.map((u) =>
              u.id === toUserId ? { ...u, status: "accepted" } : u
            )
          );
          fetchContacts(); // Refresh the main contact list
        } else {
          alert("Request sent but auto-accept failed: " + (acceptResponse.data.error || "Unknown error"));
        }
      } else {
        alert(requestResponse.data.error || "Failed to send contact request");
      }
    } catch (error) {
      console.error("Failed to send/accept contact request:", error);
      alert(error.response?.data?.error || "An error occurred while sending the request.");
    }
  };

  const handleStartChat = (contact) => {
    if (onStartChat) {
      onStartChat({
        name: contact.username || contact.id,
        avatar:
          contact.avatar ||
          `https://ui-avatars.com/api/?name=${encodeURIComponent(
            contact.username || contact.id
          )}&background=random`,
      });
    }
  };

  const displayList = searchQuery ? searchResults : contacts;

  return (
    <div className="bg-background-light dark:bg-background-dark font-display text-black dark:text-white flex flex-col h-screen">
      <header className="flex items-center justify-between border-b border-black/10 dark:border-white/10 p-4 shadow-sm">
        <h1 className="text-2xl font-bold">Contacts</h1>
        <div className="text-sm bg-yellow-100 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-200 px-3 py-1 rounded-full font-medium">
          TEST MODE: Auto-accept enabled
        </div>
      </header>
      
      <div className="p-4 border-b border-black/10 dark:border-white/10">
        <div className="relative">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-black/40 dark:text-white/40">
            search
          </span>
          <input
            className="w-full rounded-full bg-black/5 dark:bg-white/5 py-2.5 pl-10 pr-4 text-sm placeholder:text-black/40 dark:placeholder:text-white/40 border-none focus:ring-2 focus:ring-primary"
            placeholder="Search users to add as contacts..."
            type="text"
            value={searchQuery}
            onChange={(e) => handleSearch(e.target.value)}
          />
        </div>
      </div>

      <main className="flex-1 overflow-y-auto p-4">
        <h3 className="mb-4 text-lg font-bold px-2">
          {searchQuery
            ? `Search Results for "${searchQuery}"`
            : `Your Contacts (${contacts.length})`}
        </h3>
        
        {isLoading ? (
          <div className="text-center py-10">Loading contacts...</div>
        ) : error ? (
           <div className="text-center py-10 text-red-500">{error}</div>
        ) : displayList.length === 0 ? (
          <div className="text-center py-10 text-gray-500">
            {searchQuery ? "No users found" : "You haven't added any contacts yet."}
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {displayList.map((user) => (
              <ContactCard
                key={user.id}
                user={user}
                isContact={user.status === "accepted"}
                hasPendingRequest={user.status === "pending"}
                onAdd={handleAddContact}
                onMessage={handleStartChat}
              />
            ))}
          </div>
        )}
      </main>
    </div>
  );
};

export default ContactScreen;