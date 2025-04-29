import React, { useState } from 'react';
import { v4 as uuidv4 } from 'uuid'; // To generate unique owner IDs

const RestaurantDetails = () => {
  const [restaurantManagers, setRestaurantManagers] = useState([]);
  const [newRestaurant, setNewRestaurant] = useState({
    name: '',
    location: '',
    ownerName: '',
  });

  const [successMessage, setSuccessMessage] = useState('');
  const [generatedCredentials, setGeneratedCredentials] = useState({
    email: '',
    password: '',
  });

  const [editingRestaurant, setEditingRestaurant] = useState(null); // For Edit functionality

  // Handle form change
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setNewRestaurant((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  // Generate random email and password
  const generateOwnerEmail = (ownerName) => `${ownerName.replace(/\s+/g, '').toLowerCase()}@letseat.com`;
  const generateOwnerPassword = () => Math.random().toString(36).slice(-8); // Generates a random password

  // Handle form submission for adding or editing a restaurant
  const handleFormSubmit = (e) => {
    e.preventDefault();
    if (newRestaurant.name && newRestaurant.location && newRestaurant.ownerName) {
      const email = generateOwnerEmail(newRestaurant.ownerName);
      const password = generateOwnerPassword();

      if (editingRestaurant) {
        // Update existing restaurant
        setRestaurantManagers((prev) =>
          prev.map((restaurant) =>
            restaurant.id === editingRestaurant.id
              ? { ...restaurant, ...newRestaurant, ownerEmail: email, ownerPassword: password }
              : restaurant
          )
        );
        setSuccessMessage(`Restaurant "${newRestaurant.name}" has been successfully updated!`);
        setEditingRestaurant(null);
      } else {
        // Add new restaurant
        const newRestaurantData = {
          id: uuidv4(),
          name: newRestaurant.name,
          location: newRestaurant.location,
          ownerName: newRestaurant.ownerName,
          ownerId: uuidv4(), // Generate unique owner ID
          ownerEmail: email,
          ownerPassword: password,
        };

        setRestaurantManagers((prev) => [...prev, newRestaurantData]);
        setSuccessMessage(`Restaurant "${newRestaurant.name}" has been successfully registered!`);
      }

      // Set generated credentials
      setGeneratedCredentials({ email, password });
      // Clear form
      setNewRestaurant({ name: '', location: '', ownerName: '' });
    } else {
      setSuccessMessage('Please fill out all fields.');
    }
  };

  // Handle edit button click
  const handleEdit = (restaurant) => {
    setNewRestaurant({
      name: restaurant.name,
      location: restaurant.location,
      ownerName: restaurant.ownerName,
    });
    setEditingRestaurant(restaurant);
  };

  // Handle delete button click
  const handleDelete = (id) => {
    setRestaurantManagers((prev) => prev.filter((restaurant) => restaurant.id !== id));
    setSuccessMessage('Restaurant has been successfully deleted!');
  };

  return (
    <div className="p-6 font-serif">
      <h2 className="text-3xl font-bold text-red-600 mb-6">Restaurant Details</h2>

      {/* Success Message */}
      {successMessage && (
        <div className="mb-4 p-4 text-green-700 bg-green-200 border border-green-500 rounded-lg">
          {successMessage}
        </div>
      )}

      {/* Restaurant Managers List */}
      <div className="mb-6">
        <h3 className="text-2xl font-semibold text-gray-800 mb-4">List of Restaurant Managers</h3>
        <table className="min-w-full text-sm text-left bg-white border border-gray-200 rounded-2xl overflow-hidden">
          <thead className="bg-black text-white text-xs uppercase">
            <tr>
              <th className="py-3 px-6">Name</th>
              <th className="py-3 px-6">Restaurant Name</th>
              <th className="py-3 px-6">Email</th>
              <th className="py-3 px-6">Actions</th>
            </tr>
          </thead>
          <tbody className="text-gray-800">
            {restaurantManagers.map((manager) => (
              <tr key={manager.id} className="border-b transition-all duration-300 hover:bg-red-50">
                <td className="py-3 px-6">{manager.ownerName}</td>
                <td className="py-3 px-6">{manager.name}</td>
                <td className="py-3 px-6">{manager.ownerEmail}</td>
                <td className="py-3 px-6">
                  <button
                    onClick={() => handleEdit(manager)}
                    className="bg-blue-600 text-white py-1 px-3 rounded-lg hover:bg-blue-700 transition duration-300 mr-2"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(manager.id)}
                    className="bg-red-600 text-white py-1 px-3 rounded-lg hover:bg-red-700 transition duration-300"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Add or Edit Restaurant Form */}
      <div>
        <h3 className="text-2xl font-semibold text-gray-800 mb-4">
          {editingRestaurant ? 'Edit Restaurant' : 'Add New Restaurant'}
        </h3>
        <form onSubmit={handleFormSubmit}>
          <div className="mb-4">
            <label className="block text-lg font-medium text-gray-700" htmlFor="name">
              Restaurant Name
            </label>
            <input
              type="text"
              id="name"
              name="name"
              value={newRestaurant.name}
              onChange={handleInputChange}
              className="w-full p-2 border border-gray-300 rounded-lg"
              placeholder="Enter Restaurant Name"
            />
          </div>

          <div className="mb-4">
            <label className="block text-lg font-medium text-gray-700" htmlFor="location">
              Location
            </label>
            <input
              type="text"
              id="location"
              name="location"
              value={newRestaurant.location}
              onChange={handleInputChange}
              className="w-full p-2 border border-gray-300 rounded-lg"
              placeholder="Enter Location"
            />
          </div>

          <div className="mb-4">
            <label className="block text-lg font-medium text-gray-700" htmlFor="ownerName">
              Owner Name
            </label>
            <input
              type="text"
              id="ownerName"
              name="ownerName"
              value={newRestaurant.ownerName}
              onChange={handleInputChange}
              className="w-full p-2 border border-gray-300 rounded-lg"
              placeholder="Enter Owner Name"
            />
          </div>

          <button
            type="submit"
            className="bg-red-600 text-white py-2 px-4 rounded-lg hover:bg-red-700 transition duration-300"
          >
            {editingRestaurant ? 'Update Restaurant' : 'Register Restaurant'}
          </button>
        </form>
      </div>

      {/* Display Generated Email and Password */}
      {generatedCredentials.email && generatedCredentials.password && (
        <div className="mt-6 p-4 text-blue-700 bg-blue-200 border border-blue-500 rounded-lg">
          <h4 className="text-xl font-semibold">Generated Credentials:</h4>
          <p>Email: {generatedCredentials.email}</p>
          <p>Password: {generatedCredentials.password}</p>
        </div>
      )}
    </div>
  );
};

export default RestaurantDetails;
