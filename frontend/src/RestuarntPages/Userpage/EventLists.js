import React, { useEffect, useState } from "react";
import axios from "axios";
import { Home, Filter } from "lucide-react";
import { useNavigate } from "react-router-dom";

const EventList = () => {
  const [events, setEvents] = useState([]);
  const [filteredEvents, setFilteredEvents] = useState([]);
  const [showFilter, setShowFilter] = useState(false);
  const [categories, setCategories] = useState([]);
  const [locations, setLocations] = useState([]);
  const [filterData, setFilterData] = useState({
    category: "",
    location: "",
    price: "",
  });

  const navigate = useNavigate();

  useEffect(() => {
    axios.get("http://localhost:5000/api/events").then((res) => {
      setEvents(res.data);
      setFilteredEvents(res.data);
      const uniqueCategories = [...new Set(res.data.map((e) => e.category))];
      const uniqueLocations = [...new Set(res.data.map((e) => e.location))];
      setCategories(uniqueCategories);
      setLocations(uniqueLocations);
    });
  }, []);

  const handleFilter = () => {
    const filtered = events.filter((e) => {
      const matchCategory = filterData.category ? e.category === filterData.category : true;
      const matchLocation = filterData.location ? e.location === filterData.location : true;
      const matchPrice = filterData.price ? parseInt(e.price) <= parseInt(filterData.price) : true;
      return matchCategory && matchLocation && matchPrice;
    });
    setFilteredEvents(filtered);
    setShowFilter(false);
  };

  const handleReset = () => {
    setFilterData({ category: "", location: "", price: "" });
    setFilteredEvents(events);
    setShowFilter(false);
  };

  return (
    <div className="p-4">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <button
          onClick={() => (window.location.href = "/userpage")}
          className="flex items-center gap-2 text-red-600 hover:text-black font-semibold"
        >
          <Home className="w-5 h-5" />
          Home
        </button>

        <button
          onClick={() => setShowFilter(true)}
          className="flex items-center gap-2 bg-red-600 text-white px-4 py-2 rounded hover:bg-black transition"
        >
          <Filter className="w-4 h-4" /> Filter
        </button>
      </div>

      {/* Filter Popover */}
      {showFilter && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center z-50">
          <div className="bg-white w-[90%] max-w-md rounded-lg shadow-lg p-6 relative">
            <h2 className="text-xl font-bold text-red-600 mb-4 text-center">Filter Events</h2>

            <div className="space-y-4">
              <div>
                <label className="block font-medium mb-1">Category</label>
                <select
                  value={filterData.category}
                  onChange={(e) => setFilterData({ ...filterData, category: e.target.value })}
                  className="w-full border px-3 py-2 rounded"
                >
                  <option value="">All</option>
                  {categories.map((cat, i) => (
                    <option key={i} value={cat}>{cat}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block font-medium mb-1">Location</label>
                <select
                  value={filterData.location}
                  onChange={(e) => setFilterData({ ...filterData, location: e.target.value })}
                  className="w-full border px-3 py-2 rounded"
                >
                  <option value="">All</option>
                  {locations.map((loc, i) => (
                    <option key={i} value={loc}>{loc}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block font-medium mb-1">Max Price</label>
                <input
                  type="number"
                  placeholder="Enter max price"
                  value={filterData.price}
                  onChange={(e) => setFilterData({ ...filterData, price: e.target.value })}
                  className="w-full border px-3 py-2 rounded"
                />
              </div>
            </div>

            <div className="flex justify-between mt-6">
              <button
                onClick={handleReset}
                className="px-4 py-2 bg-gray-200 rounded hover:bg-gray-300"
              >
                Reset
              </button>
              <button
                onClick={handleFilter}
                className="px-6 py-2 bg-red-600 text-white rounded hover:bg-black transition"
              >
                Apply
              </button>
            </div>

            <button
              onClick={() => setShowFilter(false)}
              className="absolute top-2 right-3 text-gray-500 hover:text-red-600 text-xl"
            >
              &times;
            </button>
          </div>
        </div>
      )}

      {/* Event Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredEvents.length === 0 ? (
          <p className="text-center col-span-full text-gray-600">No events found.</p>
        ) : (
          filteredEvents.map((event) => (
            <div
              key={event.id}
              onClick={() => {
                sessionStorage.setItem("selectedEvent", JSON.stringify(event));
                navigate("/event-details");
              }}
              className="border p-4 rounded-xl shadow hover:shadow-lg transition bg-white cursor-pointer"
            >
              <img
                src={event.imageUrl}
                alt={event.name}
                className="w-full h-40 object-cover rounded mb-2"
              />
              <h4 className="font-bold text-lg text-red-600">{event.name}</h4>
              <p className="text-sm text-gray-700 mb-1">{event.description}</p>
              <p className="text-sm">📍 {event.location}</p>
              <p className="text-sm">📅 {event.date} ⏰ {event.time}</p>
              <p className="text-sm">👥 Max: {event.maxAttendees}</p>
              <p className="text-sm">🏷️ Restaurant ID: {event.restaurantId}</p>
              <p className="text-sm">🎉 Category: {event.category}</p>
              <p className="text-sm">💰 Price: ₹{event.price || "N/A"}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default EventList;
