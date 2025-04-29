// src/Chat.js
import { useState, useEffect } from "react";
import { db } from "./firebase";
import {
  collection,
  addDoc,
  serverTimestamp,
  query,
  orderBy,
  onSnapshot,
} from "firebase/firestore";

const Chat = ({ senderId = 1, receiverId = 2 }) => {
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([]);

  // Send message
  const sendMessage = async () => {
    if (message.trim() === "") return;

    await addDoc(collection(db, "messages"), {
      sender_id: senderId,
      receiver_id: receiverId,
      message: message,
      timestamp: serverTimestamp(),
    });

    setMessage(""); // clear input
  };

  // Load messages in real-time
  useEffect(() => {
    const q = query(collection(db, "messages"), orderBy("timestamp"));

    const unsubscribe = onSnapshot(q, (snapshot) => {
      const msgs = snapshot.docs.map((doc) => doc.data());
      setMessages(msgs);
    });

    return () => unsubscribe();
  }, []);

  return (
    <div className="p-4 max-w-xl mx-auto">
      <h2 className="text-2xl font-bold mb-4">Live Chat</h2>

      <div className="border h-64 overflow-y-scroll p-2 rounded mb-4 bg-white shadow">
        {messages.map((msg, index) => (
          <div
            key={index}
            className={`mb-2 p-2 rounded ${
              msg.sender_id === senderId ? "bg-green-100" : "bg-blue-100"
            }`}
          >
            <strong>{msg.sender_id === senderId ? "You" : "Manager"}:</strong>{" "}
            {msg.message}
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        <input
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          className="flex-1 border p-2 rounded"
          placeholder="Type your message..."
        />
        <button
          onClick={sendMessage}
          className="bg-blue-600 text-white px-4 py-2 rounded"
        >
          Send
        </button>
      </div>
    </div>
  );
};

export default Chat;
