import React, { useState, useEffect } from "react";
import axios from "axios";
import { motion } from "framer-motion";

const Events = () => {
  const [formData, setFormData] = useState({
    name: "",
    maxAttendees: "",
    date: "",
    time: "",
    description: "",
    restaurantId: "",
    imageUrl: "",
    location: "",
    category: "",
    price: "",
  });

  const [events, setEvents] = useState([]);

  useEffect(() => {
    fetchEvents();
  }, []);

  const fetchEvents = async () => {
    try {
      const res = await axios.get("http://localhost:5000/api/events");
      setEvents(res.data);
    } catch (err) {
      console.error("Error fetching events:", err);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post("http://localhost:5000/api/events", formData);
      setFormData({
        name: "",
        maxAttendees: "",
        date: "",
        time: "",
        description: "",
        restaurantId: "",
        imageUrl: "",
        location: "",
        category: "",
        price: "",
      });
      fetchEvents();
    } catch (err) {
      console.error("Error creating event:", err);
    }
  };

  return (
    <div className="min-h-screen bg-white">
      <nav className="bg-black text-white py-4 px-4 md:px-8 flex flex-col sm:flex-row justify-between items-center gap-4 sm:gap-0 shadow-md">
        <div className="text-2xl font-bold text-red-500">Let's Eat</div>
        <div className="flex flex-wrap gap-4 text-sm sm:text-base justify-center">
          <button onClick={() => (window.location.href = "/restaurantpage")} className="hover:text-red-500 transition">
            Home
          </button>
          <button className="hover:text-red-500 transition">Restaurants</button>
          <button className="hover:text-red-500 transition">Booking</button>
          <button className="hover:text-red-500 transition">Events</button>
        </div>
      </nav>

      <div className="p-4 sm:p-6 max-w-6xl mx-auto">
        <h2 className="text-3xl font-extrabold text-center text-red-600 mb-6">Create Event</h2>
        <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-10">
          <input name="name" placeholder="Event Name" value={formData.name} onChange={handleChange} className="p-2 border rounded focus:outline-red-600" required />
          <input name="maxAttendees" placeholder="Max Attendees" value={formData.maxAttendees} onChange={handleChange} className="p-2 border rounded focus:outline-red-600" required />
          <input type="date" name="date" value={formData.date} onChange={handleChange} className="p-2 border rounded focus:outline-red-600" required />
          <input type="time" name="time" value={formData.time} onChange={handleChange} className="p-2 border rounded focus:outline-red-600" required />
          <input name="restaurantId" placeholder="Restaurant ID" value={formData.restaurantId} onChange={handleChange} className="p-2 border rounded focus:outline-red-600" required />
          <input name="location" placeholder="Location" value={formData.location} onChange={handleChange} className="p-2 border rounded focus:outline-red-600" required />
          <input name="category" placeholder="Category (e.g., Music, Food)" value={formData.category} onChange={handleChange} className="p-2 border rounded focus:outline-red-600" required />
          <input name="imageUrl" placeholder="Image URL" value={formData.imageUrl} onChange={handleChange} className="p-2 border rounded focus:outline-red-600" required />
          <input type="number" name="price" placeholder="Price (₹)" value={formData.price} onChange={handleChange} className="p-2 border rounded focus:outline-red-600" required />
          <textarea name="description" placeholder="Description" value={formData.description} onChange={handleChange} className="p-2 border rounded md:col-span-2 focus:outline-red-600" required />
          <button type="submit" className="bg-red-600 text-white py-2 px-4 rounded md:col-span-2 hover:bg-black transition font-bold">
            Create Event
          </button>
        </form>

        <h3 className="text-2xl font-semibold mb-4 text-black text-center md:text-left">Upcoming Events</h3>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {events.map((event) => (
            <motion.div
              key={event.id || event._id}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
              className="border border-red-600 rounded-lg p-4 shadow hover:shadow-xl transition bg-white"
            >
              <img src={event.imageUrl} alt={event.name} className="w-full h-40 object-cover rounded mb-3" />
              <h4 className="text-lg font-bold text-red-600">{event.name}</h4>
              <p className="text-sm text-gray-700 mb-1">{event.description}</p>
              <p className="text-sm">📍 {event.location}</p>
              <p className="text-sm">📅 {event.date} ⏰ {event.time}</p>
              <p className="text-sm">👥 Max: {event.maxAttendees}</p>
              <p className="text-sm">🏷️ Restaurant ID: {event.restaurantId}</p>
              <p className="text-sm">🎉 Category: {event.category}</p>
              <p className="text-sm">💰 Price: ₹{event.price}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Events;