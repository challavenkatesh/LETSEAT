import React, { useState } from 'react';
import { Phone, MessageSquare, PlusCircle } from 'lucide-react';

const FloatingAddButton = () => {
  const [menuOpen, setMenuOpen] = useState(false);

  // Toggle function to show or hide chat and phone icons
  const toggleMenu = () => setMenuOpen(!menuOpen);

  return (
    <div className="fixed bottom-10 right-10 flex items-center justify-center z-50 space-x-6">
      {/* Show Chat and Phone buttons when menu is open */}
      {menuOpen && (
        <div className="flex flex-col space-y-4 mr-10">
          {/* Chat Button */}
          <button
            title="Chat"
            onClick={() => alert('Chat Clicked')}
            className="group cursor-pointer p-4 bg-gradient-to-r from-blue-500 to-teal-500 rounded-full shadow-lg transform transition-all hover:scale-110 duration-300"
          >
            <MessageSquare className="text-white group-hover:text-gray-100 text-2xl" />
          </button>

          {/* Phone Button */}
          <button
            title="Phone"
            onClick={() => alert('Phone Clicked')}
            className="group cursor-pointer p-4 bg-gradient-to-r from-green-500 to-teal-600 rounded-full shadow-lg transform transition-all hover:scale-110 duration-300"
          >
            <Phone className="text-white group-hover:text-gray-100 text-2xl" />
          </button>
        </div>
      )}

      {/* Add Button with PlusCircle icon */}
      <button
        onClick={toggleMenu}
        title="Add New"
        className="group cursor-pointer outline-none hover:rotate-90 duration-300 p-4 bg-gradient-to-r from-purple-500 to-indigo-500 rounded-full shadow-lg transform transition-transform hover:scale-110"
      >
        <PlusCircle className="text-white group-hover:text-gray-200 text-3xl" />
      </button>
    </div>
  );
};

export default FloatingAddButton;
