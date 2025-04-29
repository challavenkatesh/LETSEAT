import React, { useEffect, useState } from 'react';
import { db } from '../../firebase';
import {
  addDoc,
  collection,
  query,
  orderBy,
  onSnapshot,
  serverTimestamp,
  where,
} from 'firebase/firestore';
import { motion } from 'framer-motion';
import { SendHorizonal, User2 } from 'lucide-react';

const ManagerChat = () => {
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);
  const [recentChats, setRecentChats] = useState([]);
  const [selectedUser, setSelectedUser] = useState('user1');
  const [unreadMessages, setUnreadMessages] = useState({});
  recentChats.sort((a, b) => {
    const aTimestamp = a.lastMessage ? a.lastMessage.timestamp : 0;
    const bTimestamp = b.lastMessage ? b.lastMessage.timestamp : 0;
    return bTimestamp - aTimestamp;
  });
  const users = React.useMemo(() => [
    { id: 'user1', name: 'John Doe' },
    { id: 'user2', name: 'Jane Smith' },
    { id: 'user3', name: 'Alice Johnson' },
    { id: 'user4', name: 'Bob Brown' },
    { id: 'user5', name: 'Charlie Black' },
    { id: 'user6', name: 'David White' },
    { id: 'user7', name: 'Emma Green' },
    { id: 'user8', name: 'Frank Lee' },
    { id: 'user9', name: 'Grace Blue' },
    { id: 'user10', name: 'Harry Gold' },
  ], []);

  const defaultMessages = {
    user1: [
      { sender: 'manager1', message: 'Hello, how can I assist you today?', timestamp: serverTimestamp() },
      { sender: 'user1', message: 'I need help with the menu.', timestamp: serverTimestamp() },
      { sender: 'manager1', message: 'Sure! Do you want to know about our specials?', timestamp: serverTimestamp() },
    ],
  };

  useEffect(() => {
    if (!selectedUser) return;
    const q = query(
      collection(db, 'chats', selectedUser, 'messages'),
      orderBy('timestamp')
    );
    const unsubscribe = onSnapshot(q, (snapshot) => {
      setMessages(snapshot.docs.map((doc) => doc.data()));
    });
    return () => unsubscribe();
  }, [selectedUser]);

  useEffect(() => {
    const recentChatsList = users.map((user) => {
      const q = query(
        collection(db, 'chats', user.id, 'messages'),
        orderBy('timestamp'),
        where('receiver', '==', 'manager1')
      );
      const unsubscribe = onSnapshot(q, (snapshot) => {
        const lastMessage = snapshot.docs.length > 0 ? snapshot.docs[snapshot.docs.length - 1].data() : null;
        setRecentChats((prev) => [...prev, { user, lastMessage }]);
      });
      return unsubscribe;
    });
    return () => recentChatsList.forEach((unsubscribe) => unsubscribe());
  }, [users]);

  const handleSend = async () => {
    if (message.trim() === '' || !selectedUser) return;
    const newMsg = {
      sender: 'manager1',
      receiver: selectedUser,
      message,
      timestamp: serverTimestamp(),
      read: false,
    };
    await addDoc(collection(db, 'chats', selectedUser, 'messages'), newMsg);
    await addDoc(collection(db, 'chats', 'manager1', 'messages'), newMsg);
    setMessage('');
  };

  const handleSelectUser = (userId) => {
    setSelectedUser(userId);
    setUnreadMessages((prev) => ({ ...prev, [userId]: 0 }));
  };

  return (
    <div
      className="min-h-screen bg-cover bg-center bg-no-repeat font-serif text-white"
      style={{
        backgroundImage: `url('https://images.unsplash.com/photo-1600891964599-f61ba0e24092?ixlib=rb-4.0.3&auto=format&fit=crop&w=1950&q=80')`
      }}
    >
      <div className="min-h-screen bg-black/70 px-4">
        <nav className="p-4">
          <div className="max-w-7xl mx-auto flex justify-between items-center">
            <div className="text-red-500 font-bold text-3xl tracking-wider">Let's Eat</div>
            <div className="space-x-6 text-md flex items-center text-white">
              <a href="/" className="hover:text-red-400 transition flex items-center gap-1">Home</a>
              <a href="/restaurants" className="hover:text-red-400 transition flex items-center gap-1">Restaurants</a>
              <a href="/bookings" className="hover:text-red-400 transition flex items-center gap-1">Bookings</a>
              <a href="/messages" className="hover:text-red-400 transition flex items-center gap-1">Messages</a>
            </div>
          </div>
        </nav>

        <div className="max-w-7xl mx-auto p-6 mt-4 grid grid-cols-1 md:grid-cols-3 gap-6">
          <motion.div
            className="col-span-1 bg-black/50 backdrop-blur-md p-5 rounded-2xl shadow-2xl"
            initial={{ x: -50, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ duration: 0.6 }}
          >
            <h2 className="text-2xl font-bold text-center text-red-400 mb-4">Recent Chats</h2>
            <ul className="space-y-3">
              {users.map(({ id, name }) => (
                <li
                  key={id}
                  className={`p-3 rounded-xl cursor-pointer transition-all ${
                    selectedUser === id
                      ? 'bg-red-600 text-white font-bold'
                      : 'bg-white/10 hover:bg-red-800/30'
                  }`}
                  onClick={() => handleSelectUser(id)}
                >
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <User2 className="w-4 h-4 text-white" />
                      <span>{name}</span>
                    </div>
                    {unreadMessages[id] > 0 && (
                      <span className="bg-red-600 text-white text-xs px-2 py-1 rounded-full">
                        {unreadMessages[id]}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-gray-300 mt-1 truncate">
                    {defaultMessages[id]?.slice(-1)[0]?.message || 'No messages yet'}
                  </p>
                </li>
              ))}
            </ul>
          </motion.div>

          <motion.div
            className="col-span-2 bg-black/40 backdrop-blur-md p-6 rounded-2xl shadow-2xl flex flex-col justify-between h-[80vh]"
            initial={{ x: 50, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ duration: 0.6 }}
          >
            {selectedUser ? (
              <>
                <h2 className="text-xl font-bold text-center text-white mb-4">Chat with {selectedUser}</h2>
                <div className="overflow-y-auto pr-2 h-full scrollbar-thin scrollbar-thumb-red-600">
                  {(defaultMessages[selectedUser] || []).map((msg, index) => (
                    <div
                      key={`default-${index}`}
                      className={`p-3 my-2 rounded-xl max-w-xs ${
                        msg.sender === 'manager1'
                          ? 'bg-red-600 ml-auto text-right'
                          : 'bg-white/10 mr-auto text-left'
                      }`}
                    >
                      {msg.message}
                    </div>
                  ))}
                  {messages.map((msg, index) => (
                    <div
                      key={`msg-${index}`}
                      className={`p-3 my-2 rounded-xl max-w-xs ${
                        msg.sender === 'manager1'
                          ? 'bg-red-500 ml-auto text-right'
                          : 'bg-white/10 mr-auto text-left'
                      }`}
                    >
                      {msg.message}
                    </div>
                  ))}
                </div>
                <div className="mt-4 flex">
                  <input
                    className="border border-red-500 bg-white/20 text-white rounded-l-xl px-4 py-3 w-full focus:outline-none placeholder:text-gray-200"
                    placeholder="Type a message..."
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                  />
                  <button
                    onClick={handleSend}
                    className="bg-red-600 hover:bg-red-700 text-white px-5 py-3 rounded-r-xl font-semibold transition flex items-center gap-1"
                  >
                    Send <SendHorizonal className="w-4 h-4" />
                  </button>
                </div>
              </>
            ) : (
              <div className="text-center text-gray-300 font-medium">Select a user to start chatting</div>
            )}
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default ManagerChat;
