import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import axios from "axios";

const RestaurantDetail = () => {
  const [restaurant, setRestaurant] = useState(null);
  const [showMenu, setShowMenu] = useState(false);
  const [menuItems, setMenuItems] = useState([]);
  const [bestRestaurants, setBestRestaurants] = useState([]);
  const navigate = useNavigate();
  const [hover, setHover] = useState(false);
  useEffect(() => {
    const storedRestaurant = sessionStorage.getItem("selectedRestaurant");
    if (storedRestaurant) {
      const parsed = JSON.parse(storedRestaurant);
      setRestaurant(parsed);

      // Fetch menu items for that restaurant from backend
      axios
        .get(`http://localhost:5000/api/menu/${parsed.id}`)
        .then((res) => setMenuItems(res.data))
        .catch((err) => console.error("Error loading menu:", err));
    }

    setBestRestaurants([
      {
        id: 1,
        name: "The Spice Route",
        cuisine: "Indian",
        rating: 4.9,
        image_url:
          "https://images.pexels.com/photos/2474661/pexels-photo-2474661.jpeg?auto=compress&cs=tinysrgb&w=600",
      },
      {
        id: 2,
        name: "Dragon's Delight",
        cuisine: "Chinese",
        rating: 4.7,
        image_url:
          "https://images.pexels.com/photos/31485852/pexels-photo-31485852/free-photo-of-sugary-passion-fruit-candies-in-glass-bowl.jpeg?auto=compress&cs=tinysrgb&w=600",
      },
      {
        id: 3,
        name: "Trattoria Bella",
        cuisine: "Italian",
        rating: 4.8,
        image_url:
          "https://images.pexels.com/photos/31450849/pexels-photo-31450849/free-photo-of-freshly-baked-margherita-pizza-on-wooden-table.jpeg?auto=compress&cs=tinysrgb&w=600",
      },
    ]);
  }, []);

  const handleBookNowClick = () => {
    navigate("/booking-form", {
      state: {
        name: restaurant.name,
        location: restaurant.location,
        id: restaurant.id,
        price: restaurant.price,
      },
    });
  };

  if (!restaurant) {
    return (
      <p className="text-center text-xl text-gray-700 bg-white min-h-screen flex items-center justify-center">
        Loading...
      </p>
    );
  }

  return (
    <div className="bg-white min-h-screen p-6 font-serif relative">
     {showMenu && (
  <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center backdrop-blur-sm">
    <div className="animate-fade-in-up bg-white w-[95%] md:w-[650px] rounded-3xl shadow-2xl p-6 relative border border-red-200 transition-all duration-300 ease-in-out scale-95 hover:scale-100">
      
      {/* Title */}
      <h2 className="text-3xl font-extrabold mb-6 text-center text-red-700 tracking-wide underline underline-offset-8">
        Restaurant Menu
      </h2>

      {/* Table */}
      <div className="overflow-x-auto max-h-80 overflow-y-auto rounded-xl border border-gray-200 shadow-inner">
        <table className="min-w-full table-auto text-sm text-gray-800">
          <thead className="bg-gradient-to-r from-red-200 to-red-100 sticky top-0 z-10 shadow-sm">
            <tr className="text-left text-red-800 font-semibold tracking-wide">
              <th className="px-6 py-3">Image</th>
              <th className="px-6 py-3">Item Name</th>
              <th className="px-6 py-3">Price (₹)</th>
            </tr>
          </thead>
          <tbody>
            {menuItems.length === 0 ? (
              <tr>
                <td colSpan="3" className="text-center py-6 text-gray-500 font-medium">
                  No menu items found.
                </td>
              </tr>
            ) : (
              menuItems.map((item, index) => (
                <tr
                  key={index}
                  className="transition-all duration-200 hover:bg-red-50 hover:shadow-sm border-b"
                >
                  <td className="px-6 py-3">
                    {item.image_url ? (
                      <img
                        src={item.image_url}
                        alt={item.name}
                        className="w-14 h-14 rounded-lg object-cover border border-gray-300 shadow"
                      />
                    ) : (
                      <span className="text-gray-400 italic">No image</span>
                    )}
                  </td>
                  <td className="px-6 py-3 font-medium capitalize">{item.name}</td>
                  <td className="px-6 py-3 font-semibold text-red-600">₹{item.price}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Close Button */}
      <button
        className="absolute top-4 right-5 text-3xl text-gray-500 hover:text-red-600 transition-transform hover:rotate-90"
        onClick={() => setShowMenu(false)}
      >
        &times;
      </button>
    </div>
  </div>
)}


      {/* Main Content */}
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row gap-8">
        {/* Left Column */}
        <motion.div
          whileHover={{ scale: 1.01 }}
          transition={{ duration: 0.4 }}
          className="flex-[2] bg-white p-6 rounded-xl shadow-md border border-gray-200"
        >
          <motion.img
            src={restaurant.image_url}
            alt={restaurant.name}
            className="w-full h-80 object-cover rounded-xl"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 1 }}
          />

          <div className="mt-6 space-y-4 text-black">
            <h2 className="text-4xl font-extrabold text-red-700">{restaurant.name}</h2>
            <div className="text-lg text-gray-700">{restaurant.location}</div>

            <div className="flex gap-3 mt-2">
              <span className="bg-red-100 text-red-700 px-3 py-1 rounded-full text-sm font-semibold">
                {restaurant.cuisine}
              </span>
              <span className="bg-black text-white px-3 py-1 rounded-full text-sm font-semibold">
                ₹{restaurant.price}
              </span>
            </div>

            <div className="flex items-center gap-2 mt-2">
              <span className="text-yellow-500 text-lg">⭐</span>
              <p className="text-gray-800">{restaurant.rating} / 5</p>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm text-gray-700 mt-4">
              <div className="flex items-center gap-2">
                <span className="text-red-600">🪑</span>
                Seats: {restaurant.seats_available}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-red-600">⏰</span>
                Hours: {restaurant.opening_hours}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-red-600">📍</span>
                {restaurant.location}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-red-600">🍽️</span>
                {restaurant.cuisine}
              </div>
            </div>

            {/* Buttons */}
            <div className="flex flex-col sm:flex-row gap-4 mt-6">
            <button
      onClick={handleBookNowClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      className="relative overflow-hidden outline-none cursor-pointer rounded-full bg-red-600 border-4 border-black text-white text-sm font-semibold uppercase flex items-center gap-3 px-4 py-2 transition-all duration-300"
    >
      {/* Default Button */}
      <div
        className={`default-btn flex items-center gap-3 px-4 py-2 bg-red-600 rounded-full transition-all duration-300 ${
          hover ? "translate-y-[-100%]" : ""
        }`}
      >
        <svg
          className="text-white"
          strokeLineJoin="round"
          strokeLineCap="round"
          fill="none"
          strokeWidth="2"
          stroke="#FFF"
          height="16"
          width="16"
          viewBox="0 0 24 24"
        >
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
          <circle r="3" cy="12" cx="12"></circle>
        </svg>
        <span>Quick View</span>
      </div>

      {/* Hover Button */}
      <div
        className={`hover-btn absolute inset-0 bg-black transform ${
          hover ? "translate-y-0" : "translate-y-full"
        } flex items-center gap-3 px-4 py-2 rounded-full transition-all duration-300`}
      >
        <svg
          className="text-red-600"
          strokeLineJoin="round"
          strokeLineCap="round"
          fill="none"
          strokeWidth="2"
          stroke="#f44336"
          height="16"
          width="16"
          viewBox="0 0 24 24"
        >
          <circle r="1" cy="21" cx="9"></circle>
          <circle r="1" cy="21" cx="20"></circle>
          <path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"></path>
        </svg>
        <span>Book Now</span>
      </div>
    </button>
    <button onClick={() => setShowMenu(true)}
      className="relative py-4 px-10 rounded-full cursor-pointer bg-white shadow-[rgb(0_0_0_/5%)_0_0_8px] text-sm uppercase tracking-wider transition-all duration-500 ease-in-out
        hover:tracking-widest hover:bg-red-600 hover:text-white hover:shadow-[rgb(255_0_0)_0px_7px_29px_0px]
        active:tracking-widest active:bg-red-700 active:text-white active:shadow-none active:translate-y-[10px] active:transition-[100ms]"
    >
      View Menu
    </button>
            </div>
          </div>
        </motion.div>

        {/* Right Column */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8 }}
          className="md:w-1/3 bg-white p-6 rounded-xl shadow-md border border-gray-200"
        >
          <h3 className="text-2xl font-bold text-black mb-6 text-center border-b pb-2">
            Best Restaurants
          </h3>
          <div className="space-y-6">
            {bestRestaurants.map((r) => (
              <motion.div
                key={r.id}
                whileHover={{ scale: 1.05 }}
                className="bg-white border border-gray-200 p-4 rounded-xl shadow-sm hover:shadow-xl transition duration-300 cursor-pointer"
              >
                <div className="flex items-center space-x-4">
                  <img
                    src={r.image_url}
                    alt={r.name}
                    className="w-16 h-16 object-cover rounded-lg border-2 border-red-600"
                  />
                  <div>
                    <h4 className="text-lg font-bold text-black">{r.name}</h4>
                    <p className="text-sm text-gray-600">{r.cuisine}</p>
                    <p className="text-sm text-red-600">Rating: {r.rating}⭐</p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default RestaurantDetail;
