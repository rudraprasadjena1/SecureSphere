// src/services/messageService.js (updated)
import { messageAPI } from "./api";
import { useAuth } from '../context/AuthContext';

// Note: This might need to be used within a React component or hook
// Alternatively, we can export a hook for message operations

export const useMessageService = () => {
  const { getCredentials } = useAuth();

  const sendMessage = async (recipient, message) => {
    try {
      const { username, password } = getCredentials();

      if (!username || !password) {
        throw new Error("User not authenticated");
      }

      const response = await messageAPI.send(username, password, recipient, message);
      return response;
    } catch (error) {
      console.error("Error sending message:", error);
      throw error;
    }
  };

  const receiveMessage = async (sender, messageData) => {
    try {
      const { username, password } = getCredentials();

      if (!username || !password) {
        throw new Error("User not authenticated");
      }

      const response = await messageAPI.receive(username, password, sender, messageData);
      return response;
    } catch (error) {
      console.error("Error receiving message:", error);
      throw error;
    }
  };

  const getMessageHistory = async (otherUser) => {
    try {
      const { username, password } = getCredentials();

      if (!username || !password) {
        throw new Error("User not authenticated");
      }

      const response = await messageAPI.getHistory(username, otherUser, password);
      return response;
    } catch (error) {
      console.error("Error getting message history:", error);
      throw error;
    }
  };

  const getConversations = async () => {
    try {
      const { username, password } = getCredentials();

      if (!username || !password) {
        throw new Error("User not authenticated");
      }

      const response = await messageAPI.getConversations(username, password);
      return response;
    } catch (error) {
      console.error("Error getting conversations:", error);
      throw error;
    }
  };

  return {
    sendMessage,
    receiveMessage,
    getMessageHistory,
    getConversations
  };
};