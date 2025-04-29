import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

const EventDetails = () => {
  const [event, setEvent] = useState(null);
  const navigate = useNavigate();

  // Sample upcoming events
  const upcomingEvents = [
    {
      id: 1,
      name: "Live Jazz Night",
      date: "April 25, 2025",
      imageUrl: "https://images.pexels.com/photos/10881631/pexels-photo-10881631.jpeg?auto=compress&cs=tinysrgb&w=600",
    },
    {
      id: 2,
      name: "Vegan Food Festival",
      date: "May 12, 2025",
      imageUrl: "https://images.pexels.com/photos/5965653/pexels-photo-5965653.jpeg?auto=compress&cs=tinysrgb&w=600",
    },
    {
      id: 3,
      name: "Wine & Dine Evening",
      date: "May 5, 2025",
      imageUrl: "https://images.pexels.com/photos/941864/pexels-photo-941864.jpeg?auto=compress&cs=tinysrgb&w=600",
    },
  ];

  useEffect(() => {
    const eventData = sessionStorage.getItem("selectedEvent");
    if (eventData) {
      setEvent(JSON.parse(eventData));
    }
  }, []);

  const handleJoinEvent = () => {
    navigate("/event-form");
  };

  if (!event) return <p className="p-4 text-center text-gray-600 font-serif">No event data available.</p>;

  return (
    <div className="min-h-screen bg-white py-10 px-6 font-serif">
      <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left: Luxurious Event Details */}
        <div className="lg:col-span-2 bg-white shadow-2xl rounded-2xl p-8 border border-black/10">
          <img
            src={event.imageUrl}
            alt={event.name}
            className="w-full h-80 object-cover rounded-xl mb-6 border-4 border-black"
          />
          <h2 className="text-4xl font-bold text-red-600 mb-2">{event.name}</h2>
          <p className="text-gray-700 text-base mb-6 italic tracking-wide">{event.description}</p>

          <div className="grid grid-cols-2 gap-4 text-sm text-gray-700">
            <div className="flex items-center gap-2">
              <span className="text-xl">📍</span>
              <span><strong className="text-black">Location:</strong> {event.location}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xl">📅</span>
              <span><strong className="text-black">Date:</strong> {event.date}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xl">⏰</span>
              <span><strong className="text-black">Time:</strong> {event.time}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xl">👥</span>
              <span><strong className="text-black">Max Attendees:</strong> {event.maxAttendees}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xl">🏷️</span>
              <span><strong className="text-black">Category:</strong> {event.category}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xl">🆔</span>
              <span><strong className="text-black">Restaurant ID:</strong> {event.restaurantId}</span>
            </div>
          </div>

          <div className="mt-6 text-2xl font-extrabold text-red-600">
            💰 ₹{event.price}
          </div>

          <button
            onClick={handleJoinEvent}
            className="mt-8 bg-red-600 hover:bg-black text-white py-3 px-8 rounded-xl text-lg shadow-lg transition duration-300 ease-in-out"
          >
            Join Event
          </button>
        </div>

        {/* Right: Upcoming Events */}
        <div className="bg-gray-50 p-6 rounded-2xl shadow-lg">
          <h3 className="text-xl font-bold text-black mb-4 border-b border-red-600 pb-2">
            🔔 Upcoming Events
          </h3>
          <div className="space-y-4">
            {upcomingEvents.map((upEvent) => (
              <div
                key={upEvent.id}
                className="bg-white rounded-xl shadow hover:shadow-md transition overflow-hidden"
              >
                <img
                  src={upEvent.imageUrl}
                  alt={upEvent.name}
                  className="w-full h-32 object-cover"
                />
                <div className="p-3">
                  <h4 className="font-semibold text-black">{upEvent.name}</h4>
                  <p className="text-sm text-gray-600">📅 {upEvent.date}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default EventDetails;
