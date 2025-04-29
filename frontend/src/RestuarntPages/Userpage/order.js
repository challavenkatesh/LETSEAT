import React, { useState, useEffect } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { FaHome } from "react-icons/fa";

const TakeawayOrder = () => {
  const [restaurants, setRestaurants] = useState([]);
  const [selectedRestaurant, setSelectedRestaurant] = useState(null);
  const [menus, setMenus] = useState([]);
  const [selectedItems, setSelectedItems] = useState([]); // Updated to support multiple selections
  const [orderQty, setOrderQty] = useState(1);
  const [orderType, setOrderType] = useState("Takeaway");
  const [pickupTime, setPickupTime] = useState("");
  const [distance, setDistance] = useState("");
  const [extraCharge, setExtraCharge] = useState(0);
  const [totalPrice, setTotalPrice] = useState(0);
  const [showModal, setShowModal] = useState(false);
  const [paymentMethod, setPaymentMethod] = useState("");
  const [cardDetails, setCardDetails] = useState("");
  const [upiId, setUpiId] = useState("");
  const [phone, setPhone] = useState("");
  const [email, setEmail] = useState("");
  const navigate = useNavigate();

  const handleOrderPayment = () => {
    if (!phone || !email) {
      return alert("Please enter phone and email.");
    }

    if (paymentMethod === "Card" && !cardDetails) {
      return alert("Enter card details.");
    } else if (paymentMethod === "UPI" && !upiId) {
      return alert("Enter UPI ID.");
    }

    // Save order info to sessionStorage
    sessionStorage.setItem(
      "orderInfo",
      JSON.stringify({
        items: selectedItems.map((item) => item.name),
        type: orderType,
        total: totalPrice,
        phone,
        email,
      })
    );

    // Navigate to confirmation page
    navigate("/menu-form");
  };

  useEffect(() => {
    const fetchRestaurants = async () => {
      try {
        const res = await axios.get("http://localhost:5000/api/restaurants");
        setRestaurants(res.data);
      } catch (err) {
        console.error("Error fetching restaurants:", err);
      }
    };
    fetchRestaurants();
  }, []);

  const handleRestaurantSelect = async (restaurant) => {
    setSelectedRestaurant(restaurant);
    setSelectedItems([]); // Clear selected items when a new restaurant is selected
    setDistance("");
    setPickupTime("");
    setOrderQty(1);
    setExtraCharge(0);

    try {
      const res = await axios.get(`http://localhost:5000/api/menu/${restaurant.id}`);
      setMenus(res.data);
    } catch (err) {
      console.error("Error fetching menu:", err);
    }
  };

  const handleItemClick = (item) => {
    setSelectedItems((prevSelectedItems) => {
      if (prevSelectedItems.some((selected) => selected.id === item.id)) {
        // If item is already selected, remove it
        return prevSelectedItems.filter((selected) => selected.id !== item.id);
      } else {
        // Otherwise, add it to the selection
        return [...prevSelectedItems, item];
      }
    });
  };

  useEffect(() => {
    if (selectedItems.length === 0) {
      setTotalPrice(0);
      return;
    }

    let base = selectedItems.reduce((sum, item) => sum + item.price * orderQty, 0);
    let extra = 0;

    if (orderType === "Dine-in" && distance && distance <= 10) {
      extra = distance * 5;
    }

    setExtraCharge(extra);
    setTotalPrice(base + extra);
  }, [selectedItems, orderQty, orderType, distance]);

  const handleOrderSubmit = (e) => {
    e.preventDefault();

    if (orderType === "Takeaway" && !pickupTime) {
      return alert("⚠️ Please select a pickup time.");
    }

    if (orderType === "Dine-in") {
      if (!distance) return alert("⚠️ Please enter the distance.");
      if (distance > 10) return alert("❌ Not valid for Dine-in beyond 10km.");
    }

    setShowModal(true);
  };

  const handleHomeClick = () => {
    navigate("/userpage");
  };

  return (
    <div className="min-h-screen p-6 bg-white">
      <button
        onClick={handleHomeClick}
        className="absolute top-4 left-4 p-3 bg-red-600 text-white rounded-full shadow-md hover:bg-red-700 transition-all"
      >
        <FaHome size={24} />
      </button>
      <h1 className="text-4xl font-bold mb-6 text-center text-red-800">
        Order Your Meal
      </h1>

      {/* Restaurant Dropdown */}
      <div className="mb-6">
        <label className="block text-lg font-semibold text-red-800 mb-2">
          Choose a Restaurant
        </label>
        <select
          onChange={(e) => {
            const selected = restaurants.find((r) => r.id === parseInt(e.target.value));
            handleRestaurantSelect(selected);
          }}
          value={selectedRestaurant?.id || ""}
          className="w-full p-3 border border-gray-300 rounded-lg bg-white text-red-800 font-semibold shadow-sm focus:outline-none focus:ring-2 focus:ring-red-600"
        >
          <option value="" disabled>
            -- Select Restaurant --
          </option>
          {restaurants.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </select>
      </div>

      {/* Menu Cards */}
      {menus.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          {menus.map((item) => (
            <div
              key={item.id}
              onClick={() => handleItemClick(item)}
              className={`cursor-pointer border rounded-lg p-4 shadow-md hover:shadow-lg transition-transform transform hover:scale-105 ${
                selectedItems.some((selected) => selected.id === item.id)
                  ? "bg-red-100 border-red-500"
                  : "bg-white"
              }`}
            >
              {item.image_url && (
                <img
                  src={item.image_url}
                  alt={item.name}
                  className="w-full h-40 object-cover mb-2 rounded-lg"
                />
              )}
              <h3 className="text-lg font-bold text-red-700">{item.name}</h3>
              <p className="text-gray-700">₹{item.price}</p>
            </div>
          ))}
        </div>
      )}

      {/* Order Form */}
      {selectedItems.length > 0 && (
        <form
          onSubmit={handleOrderSubmit}
          className="mt-6 bg-gray-50 border border-gray-200 p-6 rounded-xl shadow-sm"
        >
          <h3 className="text-xl font-bold mb-4 text-red-600">
            🛒 Order for:
          </h3>
          <ul>
            {selectedItems.map((item) => (
              <li key={item.id} className="mb-2">
                <strong>{item.name}</strong> - ₹{item.price}
              </li>
            ))}
          </ul>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block mb-1 font-medium">Quantity</label>
              <input
                type="number"
                min="1"
                value={orderQty}
                onChange={(e) => setOrderQty(parseInt(e.target.value))}
                className="w-full px-4 py-2 border rounded-lg"
                required
              />
            </div>

            <div>
              <label className="block mb-1 font-medium">Order Type</label>
              <select
                value={orderType}
                onChange={(e) => {
                  setOrderType(e.target.value);
                  setDistance("");
                  setPickupTime("");
                  setExtraCharge(0);
                }}
                className="w-full px-4 py-2 border rounded-lg"
                required
              >
                <option value="Takeaway">Takeaway</option>
                <option value="Dine-in">Dine-in</option>
              </select>
            </div>

            {orderType === "Takeaway" && (
              <div>
                <label className="block mb-1 font-medium">Pickup Time</label>
                <input
                  type="time"
                  value={pickupTime}
                  onChange={(e) => setPickupTime(e.target.value)}
                  className="w-full px-4 py-2 border rounded-lg"
                  required
                />
              </div>
            )}

            {orderType === "Dine-in" && (
              <div>
                <label className="block mb-1 font-medium">Distance (in km)</label>
                <input
                  type="number"
                  value={distance}
                  onChange={(e) => setDistance(parseFloat(e.target.value))}
                  min="1"
                  max="10"
                  className="w-full px-4 py-2 border rounded-lg"
                  required
                />
                {distance > 10 && (
                  <p className="text-red-600 text-sm mt-1">❌ Max distance 10km!</p>
                )}
              </div>
            )}

            <div>
              <label className="block mb-1 font-medium text-green-700">Total Price</label>
              <input
                type="text"
                value={`₹${totalPrice}`}
                disabled
                className="w-full px-4 py-2 border rounded-lg bg-green-100 font-bold text-green-800"
              />
              {extraCharge > 0 && (
                <p className="text-xs text-gray-500">Includes ₹{extraCharge} charge</p>
              )}
            </div>
          </div>

          <div className="mt-6 text-right">
            <button
              type="submit"
              className="bg-red-600 text-white px-6 py-2 rounded-lg hover:bg-red-700 transition"
            >
              ✅ Place Order
            </button>
          </div>
        </form>
      )}

      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-40 flex justify-center items-center z-50">
          <div className="bg-white p-6 rounded-xl shadow-xl w-full max-w-md">
            <h2 className="text-xl font-bold mb-4 text-red-600">💳 Payment</h2>

            {/* ORDER DETAILS DISPLAY */}
            <div className="mb-4 bg-gray-50 p-4 rounded-lg border text-sm">
              <p><strong>🏢 Restaurant:</strong> {selectedRestaurant?.name}</p>
              <p><strong>📍 Location:</strong> {selectedRestaurant?.location}</p>

              <p><strong>🍽️ Order Type:</strong> {orderType}</p>
              <p><strong>🍔 Items:</strong> {selectedItems.map((item) => item.name).join(", ")}</p>
              <p><strong>💰 Total Price:</strong> ₹{totalPrice}</p>
            </div>

            {/* PHONE & EMAIL */}
            <input
              type="text"
              placeholder="Phone Number"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              className="w-full mb-3 px-4 py-2 border rounded-lg"
              required
            />

            <input
              type="email"
              placeholder="Email Address"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full mb-3 px-4 py-2 border rounded-lg"
              required
            />

            {/* PAYMENT OPTIONS */}
            <label className="block font-medium mb-1">Select Payment Method</label>
            <select
              value={paymentMethod}
              onChange={(e) => setPaymentMethod(e.target.value)}
              className="w-full mb-4 px-4 py-2 border rounded-lg"
            >
              <option value="">-- Select --</option>
              <option value="Card">Card</option>
              <option value="UPI">UPI</option>
              <option value="QR">QR Code</option>
            </select>

            {paymentMethod === "Card" && (
              <input
                type="text"
                placeholder="Card Number"
                value={cardDetails}
                onChange={(e) => setCardDetails(e.target.value)}
                className="w-full mb-3 px-4 py-2 border rounded-lg"
              />
            )}

            {paymentMethod === "UPI" && (
              <input
                type="text"
                placeholder="UPI ID"
                value={upiId}
                onChange={(e) => setUpiId(e.target.value)}
                className="w-full mb-3 px-4 py-2 border rounded-lg"
              />
            )}

            {paymentMethod === "QR" && (
              <div className="mb-3 text-center">
                <img
                  src="https://upload.wikimedia.org/wikipedia/commons/8/8c/UPI-QRCode-Paytm.png"
                  alt="QR Code"
                  className="mx-auto w-40"
                />
                <p className="text-sm text-gray-500 mt-2">Scan to Pay</p>
              </div>
            )}

            <button
              onClick={handleOrderPayment}
              className="bg-green-600 text-white px-6 py-2 rounded-lg w-full hover:bg-green-700 mt-3"
            >
              ✅ Pay & Proceed
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default TakeawayOrder;