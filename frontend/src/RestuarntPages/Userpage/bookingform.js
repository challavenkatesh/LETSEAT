import React, { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import ClipLoader from "react-spinners/ClipLoader";

const BookingForm = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    fullName: "",
    email: "",
    phone: "",
    date: "",
    time: "",
    guests: 1,
    specialRequests: "",
  });

  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false); // Spinner state
  const [userId, setUserId] = useState(null); // State to hold userId
  const [restaurantId, setRestaurantId] = useState(null); // State to hold restaurantId

  useEffect(() => {
    // Only set the IDs if they aren't already set (to ensure they remain fixed)
    const lastUserId = parseInt(localStorage.getItem("lastUserId")) || 0;
    const user = lastUserId + 1;
    localStorage.setItem("lastUserId", user);

    const lastRestaurantId = parseInt(localStorage.getItem("lastRestaurantId")) || 0;
    const restaurant = lastRestaurantId + 1;
    localStorage.setItem("lastRestaurantId", restaurant);

    setUserId(user); // Set userId once
    setRestaurantId(restaurant); // Set restaurantId once
  }, []); // Empty dependency array ensures this runs only once when the component mounts

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const { name, location: restaurantLocation, price } = location.state || {};

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true); // Show spinner when submitting

    const payload = {
      user_id: userId,
      restaurant_id: restaurantId,
      restaurant_name: name,
      restaurant_location: restaurantLocation,
      booking_datetime: `${formData.date} ${formData.time}`,
      guests: formData.guests,
      specialRequests: formData.specialRequests,
      price: price,
    };

    try {
      const res = await fetch("http://localhost:5000/api/bookings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const bookingId = await res.json();
        setMessage("✅ Booking request sent!");
        await checkBookingStatus(bookingId.bookingId);
      } else {
        setMessage("❌ Something went wrong.");
      }
    } catch (err) {
      console.error(err);
      setMessage("🚫 Error connecting to server.");
    }
  };

  const checkBookingStatus = async (bookingId) => {
    let isAccepted = false;

    while (!isAccepted) {
      try {
        const statusResponse = await fetch(
          `http://localhost:5000/api/bookings/status/${bookingId}`
        );
        const statusData = await statusResponse.json();

        if (statusData.status === "Accepted") {
          isAccepted = true;
          setLoading(false);
          navigate("/restaurant-payment", {
            state: {
              name,
              fullName: formData.fullName,
              dateTime: `${formData.date} ${formData.time}`,
              guests: formData.guests,
              price: price,
            },
          });
        } else if (statusData.status === "Declined") {
          isAccepted = true;
          setLoading(false);
          setMessage("🚫 Sorry to inform you, your booking was declined.");
        } else {
          // Wait 5 seconds before checking again
          await new Promise((resolve) => setTimeout(resolve, 5000));
        }
      } catch (err) {
        console.error("❌ Error checking booking status:", err);
        setMessage("🚫 Error checking booking status.");
        setLoading(false); // Hide spinner after error
        break;
      }
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-6">
      <div className="w-full max-w-xl bg-white p-8 rounded-2xl shadow-md">
        <h2 className="text-3xl font-bold text-red-600 mb-6 text-center">Book a Table</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Restaurant Info */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Restaurant Name</label>
            <input type="text" value={name} readOnly className="w-full px-4 py-2 border rounded-lg bg-gray-100" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Location</label>
            <input type="text" value={restaurantLocation} readOnly className="w-full px-4 py-2 border rounded-lg bg-gray-100" />
          </div>

          {/* User Input Fields */}
          <input type="text" name="fullName" placeholder="Full Name" className="w-full px-4 py-2 border rounded-lg" onChange={handleChange} required />
          <input type="email" name="email" placeholder="Email" className="w-full px-4 py-2 border rounded-lg" onChange={handleChange} required />
          <input type="tel" name="phone" placeholder="Phone Number" className="w-full px-4 py-2 border rounded-lg" onChange={handleChange} required />
          <div className="flex flex-col md:flex-row md:space-x-4">
            <input type="date" name="date" className="flex-1 px-4 py-2 border rounded-lg" onChange={handleChange} required />
            <input type="time" name="time" className="flex-1 px-4 py-2 border rounded-lg" onChange={handleChange} required />
          </div>
          <input type="number" name="guests" placeholder="Guests" min="1" className="w-full px-4 py-2 border rounded-lg" onChange={handleChange} required />
          <textarea name="specialRequests" rows="3" placeholder="Special Requests" className="w-full px-4 py-2 border rounded-lg" onChange={handleChange} />

          <div className="text-center">
            <button type="submit" className="bg-red-600 text-white px-6 py-2 rounded-xl hover:bg-red-700 transition-all duration-300">
              Confirm Booking
            </button>
          </div>
        </form>

        {message && <p className="mt-4 text-center text-lg">{message}</p>}

        {/* LOADING SPINNER POPUP */}
        {loading && (
          <div className="fixed inset-0 flex items-center justify-center bg-gray-900 bg-opacity-50">
            <div className="bg-white p-6 rounded-lg shadow-lg flex flex-col items-center">
              <ClipLoader size={50} color="#ff0000" />
              <p className="mt-4 text-lg font-semibold">Waiting for restaurant to accept...</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default BookingForm;
