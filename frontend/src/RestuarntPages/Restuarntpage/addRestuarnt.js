import React, { useEffect, useState } from "react";
import axios from "axios";
import { Link } from "react-router-dom";

const RestaurantForm = () => {
  const [restaurantData, setRestaurantData] = useState({
    name: "",
    location: "",
    owner_id: "",
    cuisine: "",
    description: "",
    image_url: "",
    price: "",
    rating: "",
    seats_available: "",
    opening_hours: "",
  });

  const [restaurants, setRestaurants] = useState([]);
  const [editId, setEditId] = useState(null); // Track if we're editing an existing restaurant
  const [menuOpen, setMenuOpen] = useState(false);

  // Handle form input changes
  const handleChange = (e) => {
    const { name, value } = e.target;
    setRestaurantData((prevState) => ({
      ...prevState,
      [name]: value,
    }));
  };

  // Handle form submission to add or edit restaurant data
  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      if (editId) {
        // Update existing restaurant
        const response = await axios.put(
          `http://localhost:5000/api/restaurants/${editId}`,
          restaurantData
        );
        if (response.status === 200) {
          alert("Restaurant updated successfully!");
          setEditId(null); // Reset edit state
        }
      } else {
        // Add new restaurant
        const response = await axios.post("http://localhost:5000/api/restaurants", restaurantData);
        if (response.status === 200) {
          alert("Restaurant added successfully!");
        }
      }
      // Fetch updated list and clear the form
      fetchRestaurants();
      setRestaurantData({
        name: "",
        location: "",
        owner_id: "",
        cuisine: "",
        description: "",
        image_url: "",
        price: "",
        rating: "",
        seats_available: "",
        opening_hours: "",
      });
    } catch (error) {
      console.error("Error submitting restaurant data", error);
    }
  };

  // Fetch all restaurants from the backend
  const fetchRestaurants = async () => {
    try {
      const response = await axios.get("http://localhost:5000/api/restaurants");
      setRestaurants(response.data);
    } catch (error) {
      console.error("Error fetching restaurants", error);
    }
  };

  const handleEdit = (restaurantId) => {
    const restaurant = restaurants.find((item) => item.id === restaurantId);
    setRestaurantData(restaurant);
    setEditId(restaurantId); // Set the ID for the restaurant being edited
  };

  const handleDelete = async (restaurantId) => {
    try {
      const response = await axios.delete(`http://localhost:5000/api/restaurants/${restaurantId}`);
      if (response.status === 200) {
        alert("Restaurant deleted successfully!");
        fetchRestaurants();
      }
    } catch (error) {
      console.error("Error deleting restaurant", error);
    }
  };

  useEffect(() => {
    fetchRestaurants();
  }, []);

  return (
    <>
    <nav className="bg-black text-white px-4 py-3 shadow-md fixed w-full top-0 z-50">
    <div className="flex justify-between items-center max-w-7xl mx-auto">
      <h1 className="text-lg font-semibold tracking-wide">Restaurant Admin</h1>

      {/* Desktop Menu */}
      <div className="hidden md:flex space-x-6 text-sm">
        <Link to="/restaurantpage" className="hover:text-red-400 transition duration-300">
          Home
        </Link>
        <Link to="/addbookings" className="hover:text-red-400 transition duration-300">
          Bookings
        </Link>
        <Link to="/addrestuarnt" className="hover:text-red-400 transition duration-300">
          Restaurants
        </Link>
      </div>

      {/* Mobile Hamburger Icon */}
      <div className="md:hidden">
        <button
          onClick={() => setMenuOpen(!menuOpen)}
          className="focus:outline-none"
          aria-label="Toggle Menu"
        >
          <svg
            className="w-6 h-6"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            viewBox="0 0 24 24"
          >
            {menuOpen ? (
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            ) : (
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            )}
          </svg>
        </button>
      </div>
    </div>

    {/* Mobile Menu Dropdown */}
    {menuOpen && (
      <div className="md:hidden mt-2 space-y-2 text-sm px-2">
        <Link
          to="/restaurantpage"
          onClick={() => setMenuOpen(false)}
          className="block py-2 px-4 rounded hover:bg-red-500 transition"
        >
          Home
        </Link>
        <Link
          to="/addbookings"
          onClick={() => setMenuOpen(false)}
          className="block py-2 px-4 rounded hover:bg-red-500 transition"
        >
          Bookings
        </Link>
        <Link
          to="/addrestuarnt"
          onClick={() => setMenuOpen(false)}
          className="block py-2 px-4 rounded hover:bg-red-500 transition"
        >
          Restaurants
        </Link>
      </div>
    )}
  </nav>
    <div
      className="bg-[url('https://images.pexels.com/photos/349609/pexels-photo-349609.jpeg')] bg-cover bg-center min-h-screen w-full flex items-center justify-center text-black"
    >
      <div
        className="max-w-4xl mx-auto p-6 bg-cover bg-center text-white rounded-lg shadow-xl"
      >
        <h2 className="text-3xl font-bold mb-4 mt-16 text-center font-serif text-red-500">{editId ? "Edit Restaurant" : "Add a Restaurant"}</h2>
        <form onSubmit={handleSubmit} className="grid grid-cols-2 gap-4 mb-6 font-serif">
  <input
    type="text"
    name="name"
    placeholder="Restaurant Name"
    value={restaurantData.name}
    onChange={handleChange}
    className="p-3 border border-gray-300 text-black rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
  />
  <input
    type="text"
    name="location"
    placeholder="Location"
    value={restaurantData.location}
    onChange={handleChange}
    className="p-3 border border-gray-300 text-black rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
  />
  <input
    type="text"
    name="owner_id"
    placeholder="Owner ID"
    value={restaurantData.owner_id}
    onChange={handleChange}
    className="p-3 border border-gray-300 text-black rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
  />
  <input
    type="text"
    name="cuisine"
    placeholder="Cuisine"
    value={restaurantData.cuisine}
    onChange={handleChange}
    className="p-3 border border-gray-300 text-black rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
  />
  <textarea
    name="description"
    placeholder="Description"
    value={restaurantData.description}
    onChange={handleChange}
    className="p-3 border border-gray-300 text-black rounded-lg col-span-2 focus:outline-none focus:ring-2 focus:ring-red-500"
  />
  <input
    type="text"
    name="image_url"
    placeholder="Image URL"
    value={restaurantData.image_url}
    onChange={handleChange}
    className="p-3 border border-gray-300 text-black rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
  />
  <input
    type="number"
    name="price"
    placeholder="Price"
    value={restaurantData.price}
    onChange={handleChange}
    className="p-3 border border-gray-300 rounded-lg text-black focus:outline-none focus:ring-2 focus:ring-red-500"
  />
  <input
    type="number"
    name="rating"
    placeholder="Rating"
    value={restaurantData.rating}
    onChange={handleChange}
    className="p-3 border border-gray-300 rounded-lg text-black focus:outline-none focus:ring-2 focus:ring-red-500"
  />
  <input
    type="number"
    name="seats_available"
    placeholder="Seats Available"
    value={restaurantData.seats_available}
    onChange={handleChange}
    className="p-3 border border-gray-300 text-black rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
  />
  <input
    type="text"
    name="opening_hours"
    placeholder="Opening Hours"
    value={restaurantData.opening_hours}
    onChange={handleChange}
    className="p-3 border border-gray-300 text-black rounded-lg col-span-2 focus:outline-none focus:ring-2 focus:ring-red-500"
  />
  <button
    type="submit"
    className="bg-red-500 text-white p-3 rounded-lg hover:bg-red-600 col-span-2 transition-transform duration-300 ease-in-out transform hover:scale-105"
  >
    {editId ? "Update Restaurant" : "Submit"}
  </button>
</form>


        <h2 className="text-2xl font-bold mb-4 text-center font-serif text-red-500">Restaurants List</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {restaurants.length > 0 ? (
            restaurants.map((restaurant) => (
              <div key={restaurant.id} className="bg-white text-black p-6 border border-gray-300 rounded-lg shadow-lg transform transition-all duration-500 ease-in-out hover:scale-105 hover:shadow-2xl">
              <img
                src={restaurant.image_url}
                alt={restaurant.name}
                className="w-full h-48 object-cover rounded-lg mb-4"
              />
              <h3 className="text-2xl font-serif font-semibold text-gray-800 mt-2">{restaurant.name}</h3>
              <p className="text-lg text-gray-700">{restaurant.location}</p>
              <p className="text-sm text-gray-600">{restaurant.cuisine}</p>
              <p className="mt-2 text-xl font-serif font-semibold text-red-600">Price: ${restaurant.price}</p>
              <p className="mt-2 text-lg text-red-500">Rating: {restaurant.rating}⭐</p>
              <p className="mt-2 text-md text-gray-500">Seats Available: {restaurant.seats_available}</p>
              <p className="mt-2 text-md text-gray-500">Opening Hours: {restaurant.opening_hours}</p>
            
              <div className="mt-6 flex space-x-4 justify-center md:justify-start">
                <button
                  onClick={() => handleEdit(restaurant.id)}
                  className="bg-yellow-500 text-white px-6 py-3 rounded-lg hover:bg-yellow-600 transition-all duration-300 ease-in-out"
                >
                  Edit
                </button>
                <button
                  onClick={() => handleDelete(restaurant.id)}
                  className="bg-red-600 text-white px-6 py-3 rounded-lg hover:bg-red-700 transition-all duration-300 ease-in-out"
                >
                  Delete
                </button>
              </div>
            </div>
            
      
            ))
          ) : (
            <p className="text-white">No restaurants available</p>
          )}
        </div>
      </div>
    </div>
    </>
  );
};

export default RestaurantForm;
