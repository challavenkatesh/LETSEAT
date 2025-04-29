import React, { useState, useEffect } from "react";
import axios from "axios";

const AddMenuForm = () => {
  const [restaurantId, setRestaurantId] = useState("");
  const [itemName, setItemName] = useState("");
  const [price, setPrice] = useState("");
  const [imageUrl, setImageUrl] = useState("");

  const [menuItems, setMenuItems] = useState([]);

  const [editId, setEditId] = useState(null);
  const [editingName, setEditingName] = useState("");
  const [editingPrice, setEditingPrice] = useState("");
  const [editingImage, setEditingImage] = useState("");

  const fetchMenuItems = async () => {
    try {
      const res = await axios.get("http://localhost:5000/api/menu");
      setMenuItems(res.data);
    } catch (err) {
      console.error("Error fetching menu items:", err);
    }
  };

  useEffect(() => {
    fetchMenuItems();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      await axios.post("http://localhost:5000/api/menu", {
        restaurant_id: restaurantId,
        name: itemName,
        price: price,
        image_url: imageUrl,
      });

      alert("Menu item added successfully!");
      setItemName("");
      setPrice("");
      setImageUrl("");
      fetchMenuItems();
    } catch (err) {
      console.error("Error adding menu item:", err);
      alert("Failed to add menu item.");
    }
  };

  const handleDelete = async (id) => {
    try {
      await axios.delete(`http://localhost:5000/api/menu/${id}`);
      fetchMenuItems();
    } catch (err) {
      console.error("Error deleting menu item:", err);
    }
  };

  const handleEdit = (item) => {
    setEditId(item.id);
    setEditingName(item.name);
    setEditingPrice(item.price);
    setEditingImage(item.image_url);
  };

  const handleUpdate = async (id) => {
    try {
      await axios.put(`http://localhost:5000/api/menu/${id}`, {
        name: editingName,
        price: editingPrice,
        image_url: editingImage,
      });
      setEditId(null);
      fetchMenuItems();
    } catch (err) {
      console.error("Error updating menu item:", err);
    }
  };

  return (
    <div className="min-h-screen bg-white p-6 flex flex-col items-center font-serif">
      <form
        onSubmit={handleSubmit}
        className="bg-red-50 border border-red-200 p-8 rounded-xl shadow-lg w-full max-w-md mb-10"
      >
        <h2 className="text-2xl font-bold text-red-700 mb-6 text-center">Add Menu Item</h2>

        <div className="mb-4">
          <label className="block text-gray-700 font-semibold mb-1">Restaurant ID</label>
          <input
            type="number"
            value={restaurantId}
            onChange={(e) => setRestaurantId(e.target.value)}
            className="w-full px-4 py-2 border rounded-md"
            placeholder="Enter Restaurant ID"
            required
          />
        </div>

        <div className="mb-4">
          <label className="block text-gray-700 font-semibold mb-1">Item Name</label>
          <input
            type="text"
            value={itemName}
            onChange={(e) => setItemName(e.target.value)}
            className="w-full px-4 py-2 border rounded-md"
            placeholder="Enter Menu Item Name"
            required
          />
        </div>

        <div className="mb-4">
          <label className="block text-gray-700 font-semibold mb-1">Price</label>
          <input
            type="number"
            value={price}
            onChange={(e) => setPrice(e.target.value)}
            className="w-full px-4 py-2 border rounded-md"
            placeholder="Enter Price"
            required
          />
        </div>

        <div className="mb-6">
          <label className="block text-gray-700 font-semibold mb-1">Image URL</label>
          <input
            type="text"
            value={imageUrl}
            onChange={(e) => setImageUrl(e.target.value)}
            className="w-full px-4 py-2 border rounded-md"
            placeholder="Paste image URL"
            required
          />
        </div>

        <button
          type="submit"
          className="w-full bg-red-600 text-white py-2 rounded-md font-semibold hover:bg-black transition duration-300"
        >
          Add Menu Item
        </button>
      </form>

      {/* Menu Items List */}
      <div className="w-full max-w-3xl">
        <h3 className="text-xl font-bold text-center mb-4 text-gray-700">Menu Items</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {menuItems.map((item) => (
            <div key={item.id} className="border p-4 rounded-md bg-red-50 shadow">
              {editId === item.id ? (
                <>
                  <input
                    type="text"
                    value={editingName}
                    onChange={(e) => setEditingName(e.target.value)}
                    className="w-full mb-2 border px-2 py-1 rounded"
                  />
                  <input
                    type="number"
                    value={editingPrice}
                    onChange={(e) => setEditingPrice(e.target.value)}
                    className="w-full mb-2 border px-2 py-1 rounded"
                  />
                  <input
                    type="text"
                    value={editingImage}
                    onChange={(e) => setEditingImage(e.target.value)}
                    className="w-full mb-2 border px-2 py-1 rounded"
                  />
                  <button
                    onClick={() => handleUpdate(item.id)}
                    className="bg-green-500 text-white px-3 py-1 rounded mr-2"
                  >
                    Save
                  </button>
                  <button
                    onClick={() => setEditId(null)}
                    className="bg-gray-400 text-white px-3 py-1 rounded"
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <>
                  {item.image_url && (
                    <img
                      src={item.image_url}
                      alt={item.name}
                      className="w-full h-40 object-cover rounded mb-2"
                    />
                  )}
                  <h4 className="font-bold text-lg">{item.name}</h4>
                  <p className="text-gray-700">Price: ₹{item.price}</p>
                  <div className="mt-2">
                    <button
                      onClick={() => handleEdit(item)}
                      className="bg-blue-500 text-white px-3 py-1 rounded mr-2"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(item.id)}
                      className="bg-red-600 text-white px-3 py-1 rounded"
                    >
                      Delete
                    </button>
                  </div>
                </>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default AddMenuForm;
