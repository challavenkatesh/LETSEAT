import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  FaTrashAlt,
  FaRupeeSign,
  FaUtensils,
  FaUserFriends,
  FaCalendarAlt,
  FaClock,
  FaHome,
} from "react-icons/fa";
import {
  CalendarDays,
  User,
  UsersRound,
  Landmark,
  IndianRupee,
} from "lucide-react";
import { useNavigate } from "react-router-dom";

const UserPanel = () => {
  const [payments, setPayments] = useState([]);
  const [bookings, setBookings] = useState([]);
  const navigate = useNavigate();

  const handleDeleteBooking = (index) => {
    const updatedBookings = [...bookings];
    updatedBookings.splice(index, 1);
    setBookings(updatedBookings);
    localStorage.setItem("userPanelData", JSON.stringify(updatedBookings));
  };

  useEffect(() => {
    // Load payments
    const storedPayments = JSON.parse(localStorage.getItem("payments")) || [];
    const enrichedPayments = storedPayments.map((payment) => ({
      id: payment.id,
      amount: payment.amount || 0,
      method: payment.method || "Unknown",
      date: payment.date || new Date().toLocaleDateString(),
      restaurant: payment.restaurantName || "Restaurant ABC",
      guests: payment.guests || "N/A",
      time: payment.bookingDateTime || "N/A",
      bookingId: payment.bookingId || `BK${payment.id}`,
    }));
    setPayments(enrichedPayments);

    // Load event bookings
    const eventData = JSON.parse(localStorage.getItem("userPanelData")) || [];
    setBookings(eventData);
  }, []);

  const handleDelete = (paymentId) => {
    const updatedPayments = payments.filter((payment) => payment.id !== paymentId);
    setPayments(updatedPayments);
    localStorage.setItem("payments", JSON.stringify(updatedPayments));
  };

  const getAmountBadgeClass = (amount) => {
    if (amount < 500) return "bg-green-100 text-green-700";
    if (amount >= 500 && amount < 1000) return "bg-yellow-100 text-yellow-700";
    return "bg-red-100 text-red-700";
  };

  return (
    <div className="min-h-screen bg-white text-black px-4 sm:px-6 lg:px-12 py-8 font-sans relative overflow-x-hidden">
      <button
        className="fixed top-4 left-4 z-50 bg-red-500 text-white p-3 rounded-full hover:bg-black transition"
        onClick={() => navigate("/userpage")}
        title="Back to Home"
      >
        <FaHome size={20} />
      </button>

      <div className="max-w-7xl mx-auto">
        {/* Payments Section */}
        <h2 className="text-3xl font-extrabold text-center text-red-600 mb-10 uppercase border-b-2 border-red-500 pb-4">
          Your Bookings & Payments
        </h2>

        {payments.length === 0 ? (
          <p className="text-center text-gray-600">No payments found.</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {payments.map((payment) => (
              <motion.div
                key={payment.id}
                whileHover={{ scale: 1.02 }}
                transition={{ duration: 0.3 }}
                className="bg-white border border-gray-200 rounded-2xl shadow-sm hover:shadow-red-300 p-5"
              >
                <div className="space-y-3 text-sm sm:text-base">
                  <p className="flex items-center gap-2">
                    <FaRupeeSign className="text-red-500" />
                    <span className={`inline-block px-3 py-1 rounded-full font-semibold ${getAmountBadgeClass(payment.amount)}`}>
                      ₹{payment.amount}
                    </span>
                  </p>
                  <p className="flex items-center gap-2"><FaUtensils className="text-red-500" /> Restaurant: {payment.restaurant}</p>
                  <p className="flex items-center gap-2"><FaUserFriends className="text-red-500" /> Guests: {payment.guests}</p>
                  <p className="flex items-center gap-2"><FaCalendarAlt className="text-red-500" /> Date & Time: {payment.time}</p>
                  <p className="flex items-center gap-2"><FaClock className="text-red-500" /> Paid On: {payment.date}</p>
                  <p className="flex items-center gap-2">💳 Method: {payment.method}</p>
                  <p className="flex items-center gap-2">🆔 Booking ID: {payment.bookingId}</p>
                </div>
                <button
                  onClick={() => handleDelete(payment.id)}
                  className="mt-5 w-full bg-red-500 hover:bg-black text-white py-2 rounded-lg flex items-center justify-center gap-2"
                >
                  <FaTrashAlt /> Delete
                </button>
              </motion.div>
            ))}
          </div>
        )}

        {/* Joined Events Section */}
        <h2 className="text-3xl font-extrabold text-center text-red-600 mt-16 mb-10 uppercase border-b-2 border-red-500 pb-4">
          Your Joined Events
        </h2>

        {bookings.length === 0 ? (
          <p className="text-center text-gray-600">No bookings found.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {bookings.map((booking, index) => (
              <div key={index} className="bg-white p-4 shadow rounded-2xl border relative">
                <p className="flex items-center gap-2 text-gray-700 mb-1">
                  <User size={20} className="text-red-500" />
                  <strong>Name:</strong> {booking.fullName}
                </p>
                <p className="flex items-center gap-2 text-gray-700 mb-1">
                  <UsersRound size={20} className="text-red-500" />
                  <strong>Persons:</strong> {booking.numberOfPersons}
                </p>
                <p className="flex items-center gap-2 text-gray-700 mb-1">
                  <CalendarDays size={20} className="text-red-500" />
                  <strong>Date:</strong> {booking.date}
                </p>
                <p className="flex items-center gap-2 text-gray-700 mb-1">
                  <Landmark size={20} className="text-red-500" />
                  <strong>Location:</strong> {booking.location}
                </p>
                <p className="flex items-center gap-2 text-gray-700 mb-1">
                  🎉 <strong>Event:</strong> {booking.eventName}
                </p>
                <p className="flex items-center gap-2 text-gray-700 mb-1">
                  🆔 <strong>Event ID:</strong> {booking.eventId || "EVT0000"}
                </p>
                <p className="flex items-center gap-2 text-gray-700 mt-2 font-semibold">
                  <IndianRupee size={20} className="text-green-500" />
                  <strong>Total:</strong> ₹{booking.totalPrice}
                </p>
                <button
                  onClick={() => handleDeleteBooking(index)}
                  className="mt-4 w-full bg-red-500 hover:bg-black text-white py-2 rounded-lg flex items-center justify-center gap-2"
                >
                  <FaTrashAlt /> Delete
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default UserPanel;
