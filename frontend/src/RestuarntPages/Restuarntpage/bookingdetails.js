import React, { useEffect, useState } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import { User, Home, MapPin, Calendar, CheckCircle } from 'lucide-react';

const BookingsList = () => {
  const [bookings, setBookings] = useState([]);

  useEffect(() => {
    const fetchBookings = async () => {
      try {
        const response = await axios.get("http://localhost:5000/api/bookings");
        setBookings(response.data);
      } catch (error) {
        console.error("Error fetching bookings:", error);
      }
    };
    fetchBookings();
  }, []);

  const handleStatusChange = async (id, newStatus) => {
    try {
      const response = await axios.put(
        `http://localhost:5000/api/bookings/status/${id}`,
        { status: newStatus }
      );
      console.log('Booking status updated:', response.data);

      setBookings((prevBookings) =>
        prevBookings.map((booking) =>
          booking.id === id ? { ...booking, status: newStatus } : booking
        )
      );
    } catch (error) {
      console.error('Error updating booking status:', error);
    }
  };

  return (
    <div className="bg-white text-black min-h-screen">
      <nav className="bg-black text-white p-4 shadow-md">
        <div className="container mx-auto flex justify-between items-center">
          <h1 className="text-xl font-semibold">Restaurant Management</h1>
          <div className="hidden lg:flex space-x-6">
            <Link to="/restaurantpage" className="text-sm hover:text-red-500 transition-colors">Home</Link>
            <Link to="/restaurants" className="text-sm hover:text-red-500 transition-colors">Restaurants</Link>
            <Link to="/bookings" className="text-sm hover:text-red-500 transition-colors">Bookings</Link>
          </div>
        </div>
      </nav>

      <div className="container mx-auto p-6">
        <h2 className="text-3xl font-bold text-center text-red-600 mb-8">Bookings</h2>

        <div className="overflow-hidden rounded-lg border-t border-black">
          <table className="min-w-full table-auto text-sm text-black">
            <thead className="bg-black text-white">
              <tr>
                <th className="py-3 px-6 text-left font-medium">
                  <User className="inline w-5 h-5 mr-2" /> User ID
                </th>
                <th className="py-3 px-6 text-left font-medium">
                  <Home className="inline w-5 h-5 mr-2" /> Restaurant ID
                </th>
                <th className="py-3 px-6 text-left font-medium">
                  <Home className="inline w-5 h-5 mr-2" /> Restaurant Name
                </th>
                <th className="py-3 px-6 text-left font-medium">
                  <MapPin className="inline w-5 h-5 mr-2" /> Location
                </th>
                <th className="py-3 px-6 text-left font-medium">
                  <Calendar className="inline w-5 h-5 mr-2" /> Booking Date/Time
                </th>
                <th className="py-3 px-6 text-left font-medium">
                  <CheckCircle className="inline w-5 h-5 mr-2" /> Status
                </th>
                <th className="py-3 px-6 text-left font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {bookings.map((booking, index) => (
                <tr
                  key={booking.id}
                  className={`transition-all duration-300 ${index % 2 === 0 ? 'bg-white' : 'bg-gray-50'} hover:bg-gray-200`}
                >
                  <td className="py-4 px-6 border-b">{booking.user_id}</td>
                  <td className="py-4 px-6 border-b">{booking.restaurant_id}</td>
                  <td className="py-4 px-6 border-b font-semibold">{booking.restaurant_name}</td>
                  <td className="py-4 px-6 border-b">{booking.restaurant_location}</td>
                  <td className="py-4 px-6 border-b">{booking.booking_datetime}</td>
                  <td className="py-4 px-6 border-b">
                    <span
                      className={`px-3 py-1 rounded-full text-sm font-semibold ${
                        booking.status === "Accepted"
                          ? "bg-green-500 text-white"
                          : booking.status === "Declined"
                          ? "bg-red-600 text-white"
                          : "bg-black text-white"
                      }`}
                    >
                      {booking.status}
                    </span>
                  </td>
                  <td className="py-4 px-6 border-b">
                    {booking.status === "Pending" && (
                      <div className="flex space-x-4">
                        <button
                          className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-all focus:outline-none focus:ring-2 focus:ring-green-500"
                          onClick={() => handleStatusChange(booking.id, "Accepted")}
                        >
                          Accept
                        </button>
                        <button
                          className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-all focus:outline-none focus:ring-2 focus:ring-red-500"
                          onClick={() => handleStatusChange(booking.id, "Declined")}
                        >
                          Decline
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default BookingsList;
