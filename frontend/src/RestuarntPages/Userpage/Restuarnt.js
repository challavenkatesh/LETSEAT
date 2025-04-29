import React, { useEffect, useState } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import {
  FaMapMarkerAlt,
  FaUtensils,
  FaDollarSign,
  FaStar,
  FaClock,
  FaSearch,
  FaFilter,
  FaTimes,
  FaBars
} from "react-icons/fa";

const RestaurantDisplay = () => {
  const [restaurants, setRestaurants] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const [selectedLocation, setSelectedLocation] = useState("");
  const [selectedPrice, setSelectedPrice] = useState("");
  const [selectedRating, setSelectedRating] = useState("");
  const [selectedCuisine, setSelectedCuisine] = useState("");

  // Fetch all restaurants from the backend
  const fetchRestaurants = async () => {
    try {
      const response = await axios.get("http://localhost:5000/api/restaurants");
      setRestaurants(response.data);
    } catch (error) {
      console.error("Error fetching restaurants", error);
    }
  };

  useEffect(() => {
    fetchRestaurants();
  }, []);

  const handleRestaurantClick = (restaurant) => {
    sessionStorage.setItem("selectedRestaurant", JSON.stringify(restaurant));
  };

  // Filter logic
  const filteredRestaurants = restaurants.filter((restaurant) => {
    const query = searchQuery.trim().toLowerCase();

    const matchesSearch =
      restaurant.name?.toLowerCase().includes(query) ||
      restaurant.location?.toLowerCase().includes(query) ||
      restaurant.cuisine?.toLowerCase().includes(query);

    const matchesLocation = selectedLocation ? restaurant.location === selectedLocation : true;
    const matchesPrice = selectedPrice ? restaurant.price === selectedPrice : true;
    const matchesRating = selectedRating ? restaurant.rating >= parseFloat(selectedRating) : true;
    const matchesCuisine = selectedCuisine ? restaurant.cuisine === selectedCuisine : true;

    return matchesSearch && matchesLocation && matchesPrice && matchesRating && matchesCuisine;
  });

  return (
    <div
      className="min-h-screen bg-black text-white font-serif relative"
      style={{
        backgroundImage: "url('https://images.pexels.com/photos/311458/pexels-photo-311458.jpeg?auto=compress&cs=tinysrgb&w=600')",
        backgroundSize: "cover",
        backgroundPosition: "center",
        backgroundRepeat: "no-repeat"
      }}
    >
      {/* Navbar */}
      <nav className="flex justify-between items-center bg-white p-4 h-16 shadow-lg">
        <h1 className="text-2xl font-bold text-black flex items-center">
          <img src="logo-1.png" alt="Logo" className="h-16 w-auto" />
        </h1>

        <div className="hidden md:flex items-center space-x-4">
          <div className="flex space-x-10 mr-64">
            <Link to="/userpage" className="text-black hover:text-red-600 transition">Home</Link>
            <Link to="/restaurants" className="text-black hover:text-red-600 transition">Restaurants</Link>
            <Link to="/bookings" className="text-black hover:text-red-600 transition">Bookings</Link>
          </div>

          <div className="relative flex items-center bg-black px-3 py-1 rounded-lg border border-white">
            <FaSearch className="text-red-400" />
            <input
              type="text"
              placeholder="Search..."
              className="ml-2 bg-transparent outline-none text-white placeholder-gray-300"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <button
            className="flex items-center bg-black text-white px-4 py-2 rounded-lg border border-white hover:bg-red-500 transition"
            onClick={() => setIsFilterOpen(true)}
          >
            <FaFilter className="mr-2" /> Filter
          </button>
        </div>

        <button className="md:hidden text-black text-2xl" onClick={() => setIsMenuOpen(true)}>
          <FaBars />
        </button>
      </nav>

      {/* Mobile Menu */}
      {isMenuOpen && (
        <>
          <div className="fixed inset-0 bg-black opacity-50 z-40" onClick={() => setIsMenuOpen(false)}></div>
          <div className="fixed left-0 top-0 w-64 h-full bg-red-600 p-6 shadow-lg z-50">
            <button className="absolute top-4 right-4 text-white text-xl" onClick={() => setIsMenuOpen(false)}>
              <FaTimes />
            </button>
            <h2 className="text-2xl font-bold text-white mb-4">Menu</h2>
            <div className="relative flex items-center bg-black px-3 py-2 rounded-lg border border-white">
              <FaSearch className="text-red-400" />
              <input
                type="text"
                placeholder="Search..."
                className="ml-2 bg-transparent outline-none text-white placeholder-gray-300"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <button
              className="flex items-center bg-black text-white px-4 py-2 rounded-lg border border-white hover:bg-red-500 transition w-full mt-4"
              onClick={() => {
                setIsMenuOpen(false);
                setIsFilterOpen(true);
              }}
            >
              <FaFilter className="mr-2" /> Filter
            </button>
          </div>
        </>
      )}

      {/* Filter Sidebar */}
      {isFilterOpen && (
        <>
          <div className="fixed inset-0 bg-black opacity-50 z-40" onClick={() => setIsFilterOpen(false)}></div>
          <div className="fixed right-0 top-0 w-64 h-full bg-red-600 p-6 shadow-lg z-50">
            <button className="absolute top-4 right-4 text-white text-xl" onClick={() => setIsFilterOpen(false)}>
              <FaTimes />
            </button>
            <h2 className="text-2xl font-bold text-white mb-4">Filter Options</h2>

            <label className="block text-white mb-2">Location:</label>
            <input
              className="w-full p-2 bg-black text-white border border-white rounded-lg"
              onChange={(e) => setSelectedLocation(e.target.value)}
            />

            <label className="block text-white mt-2">Price:</label>
            <input
              className="w-full p-2 bg-black text-white border border-white rounded-lg"
              onChange={(e) => setSelectedPrice(e.target.value)}
            />

            <label className="block text-white mt-2">Rating:</label>
            <select
              className="w-full p-2 bg-black text-white border border-white rounded-lg"
              onChange={(e) => setSelectedRating(e.target.value)}
            >
              <option value="">All</option>
              <option value="4">4+ Stars</option>
              <option value="3">3+ Stars</option>
            </select>

            <label className="block text-white mt-2">Cuisine:</label>
            <input
              className="w-full p-2 bg-black text-white border border-white rounded-lg"
              onChange={(e) => setSelectedCuisine(e.target.value)}
            />
          </div>
        </>
      )}

      {/* Restaurant Cards */}
      <div className="max-w-7xl mx-auto p-6 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-3 gap-10">
        {filteredRestaurants.length > 0 ? (
          filteredRestaurants.map((restaurant) => (
            <div
              key={restaurant.id}
              className="bg-white p-6 rounded-xl shadow-xl hover:shadow-2xl transition-shadow duration-300 text-black w-full"
            >
              <div className="mb-4">
                <img
                  className="w-full h-48 object-cover rounded-lg"
                  src={restaurant.image_url || "https://via.placeholder.com/400x300?text=Restaurant"}
                  alt={restaurant.name}
                />
              </div>

              <Link
                to={`/restaurant/${restaurant.id}`}
                onClick={() => handleRestaurantClick(restaurant)}
                className="block"
              >
                <h3 className="text-xl font-bold text-red-600 mb-1">{restaurant.name}</h3>
                <p className="flex items-center text-gray-700"><FaMapMarkerAlt className="mr-2 text-red-600" />{restaurant.location}</p>
                <p className="flex items-center text-gray-700"><FaUtensils className="mr-2 text-red-600" />{restaurant.cuisine}</p>
                <p className="flex items-center text-gray-700"><FaDollarSign className="mr-2 text-red-600" />{restaurant.price}</p>
                <p className="flex items-center text-gray-700"><FaStar className="mr-2 text-yellow-400" />{restaurant.rating}</p>
                <p className="flex items-center text-gray-700"><FaClock className="mr-2 text-red-600" />{restaurant.opening_hours}</p>
                <p className="text-gray-700">Seats Available: {restaurant.seats_available}</p>
              </Link>
            </div>
          ))
        ) : (
          <p className="col-span-full text-center text-gray-400">No restaurants found.</p>
        )}
      </div>
    </div>
  );
};

export default RestaurantDisplay;
