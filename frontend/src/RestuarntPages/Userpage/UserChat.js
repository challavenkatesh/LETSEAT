import React, { useEffect, useState } from 'react';
import { db } from '../../firebase';
import {
  addDoc,
  collection,
  query,
  orderBy,
  onSnapshot,
  serverTimestamp,
} from 'firebase/firestore';
import { IoClose, IoSend } from 'react-icons/io5';

const UserChat = ({ toggleChat }) => {
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);
  const userId = 'user1';
  const managerId = 'manager1';

  useEffect(() => {
    const q = query(
      collection(db, 'chats', userId, 'messages'),
      orderBy('timestamp')
    );

    const unsubscribe = onSnapshot(q, (snapshot) => {
      setMessages(snapshot.docs.map((doc) => doc.data()));
    });

    return () => unsubscribe();
  }, []);

  const handleSend = async () => {
    if (message.trim() === '') return;

    const newMsg = {
      sender: userId,
      receiver: managerId,
      message,
      timestamp: serverTimestamp(),
    };

    await addDoc(collection(db, 'chats', userId, 'messages'), newMsg);
    await addDoc(collection(db, 'chats', managerId, 'messages'), newMsg);

    setMessage('');
  };

  return (
    <div className="fixed bottom-6 right-6 z-50 w-80 h-[500px] rounded-xl overflow-hidden bg-white p-0 text-black shadow-xl font-serif">
      {/* Top Red Header */}
      <div className=" text-red-500 font-serif text-center py-3 relative  border-red-600 border-t-8">
        <div className="text-lg font-semibold"> Chat With Us</div>
        <IoClose
          onClick={toggleChat}
          className="absolute top-3 right-3 text-red-600 text-2xl cursor-pointer hover:text-gray-200"
        />
      </div>

      {/* Body */}
      <div className="flex flex-col h-[440px] px-4 py-3">
        {/* Chat Messages */}
        <div className="flex-1 overflow-y-auto space-y-2 px-1 custom-scrollbar">
          {messages.map((msg, index) => (
            <div
              key={index}
              className={`p-2 my-1 rounded-md w-fit max-w-xs ${
                msg.sender === userId ? 'bg-red-500 ml-auto' : 'bg-gray-200'
              }`}
            >
              {msg.message}
            </div>
          ))}
        </div>

        {/* Input Field */}
        <div className="mt-2 flex items-center border border-gray-300 rounded-lg overflow-hidden">
          <input
            className="flex-1 px-4 py-2 text-black placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-600 rounded-l-lg"
            placeholder="Type a message..."
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          />
          <button
            onClick={handleSend}
            className="bg-red-600 hover:bg-red-700 text-white p-2 rounded-r-lg"
          >
            <IoSend className="text-xl" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default UserChat;
