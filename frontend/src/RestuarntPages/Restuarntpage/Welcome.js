import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  FaCalendarCheck,
  FaStar,
  FaUtensils,
  FaChartBar,
  FaUsers,
  FaHome,
  FaPlus,
  FaCalendarAlt,
  FaConciergeBell,
  FaEnvelope,
  FaUserCircle,
  FaBars,
  FaTimes,
  FaSearch,
  FaBell,
} from "react-icons/fa";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { Link } from "react-router-dom";

const DashboardStats = () => {
  const [stats, setStats] = useState({ totalUsers: 0, totalBookings: 0, totalEvents: 0 });
  const [bookingsByMonth, setBookingsByMonth] = useState([]);
  const [popularEvents, setPopularEvents] = useState([]);
  const [darkMode, ] = useState(false);
  const [popularRestaurants, setPopularRestaurants] = useState([]);
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    fetch("http://localhost:5000/api/bookings/popular")
      .then((response) => {
        if (!response.ok) throw new Error("Network response was not ok");
        return response.json();
      })
      .then((data) => {
        setPopularRestaurants(data);
      })
      .catch((error) => {
        console.error("Error fetching popular restaurants:", error);
      });
  }, []);

  useEffect(() => {
    fetch("http://localhost:5000/api/users")
      .then((res) => res.json())
      .then((data) => {
        const customers = data.filter((user) => user.role === "customer");
        setStats((prev) => ({ ...prev, totalUsers: customers.length }));
      });
      fetch('/api/popular-restaurants')
      .then((response) => response.json())
      .then((data) => setPopularRestaurants(data));

    fetch('/api/popular-events')
      .then((response) => response.json())
      .then((data) => setPopularEvents(data));

    fetch("http://localhost:5000/api/bookings")
      .then((res) => res.json())
      .then((data) => {
        setStats((prev) => ({ ...prev, totalBookings: data.length }));
      });

    fetch("http://localhost:5000/api/events")
      .then((res) => res.json())
      .then((data) => {
        setStats((prev) => ({ ...prev, totalEvents: data.length }));
      });

      fetch("http://localhost:5000/api/popular-events")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Failed to fetch popular events");
        }
        return response.json();
      })
      .then((data) => {
        setPopularEvents(data);
      })
      .catch((error) => {
        console.error("Error:", error);
      });

    fetch("http://localhost:5000/api/analytics/monthly")
      .then((res) => res.json())
      .then((data) => {
        setBookingsByMonth(data.bookingsByMonth || []);
      });
  }, []);

  const monthMap = [
    { month: 1, name: "Jan" },
    { month: 2, name: "Feb" },
    { month: 3, name: "Mar" },
    { month: 4, name: "Apr" },
    { month: 5, name: "May" },
    { month: 6, name: "Jun" },
    { month: 7, name: "Jul" },
    { month: 8, name: "Aug" },
    { month: 9, name: "Sep" },
    { month: 10, name: "Oct" },
    { month: 11, name: "Nov" },
    { month: 12, name: "Dec" },
  ];
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.clear();
    navigate("/");
  };
  const chartData = monthMap.map(({ month, name }) => {
    const booking = bookingsByMonth.find((b) => b.month === month);
    return { name, Bookings: booking?.count || 0 };
  });

  return (
    <div className={darkMode ? "dark bg-gray-900 text-white min-h-screen flex" : "bg-gray-50 text-gray-900 min-h-screen flex"}>
<aside className={`bg-black dark:bg-gray-800 w-64 space-y-6 p-6 fixed inset-y-0 left-0 transform ${mobileMenuOpen ? "translate-x-0" : "-translate-x-full"} md:translate-x-0 transition duration-200 ease-in-out z-50`}>
  <h1 className="text-2xl font-bold text-red-600 dark:text-green-500 text-center">
    <Link to="/">Lets Eat</Link>
  </h1>
  <nav className="flex flex-col gap-4 text-white dark:text-gray-300">
    <Link to="/restaurantpage" onClick={() => setMobileMenuOpen(false)} className="flex items-center gap-2 hover:text-red-600">
      <FaHome /> Dashboard
    </Link>
    <Link to="/addrestuarnt" onClick={() => setMobileMenuOpen(false)} className="flex items-center gap-2 hover:text-red-600">
      <FaPlus /> Add Restaurant
    </Link>
    <Link to="/addbookings" onClick={() => setMobileMenuOpen(false)} className="flex items-center gap-2 hover:text-red-600">
      <FaCalendarAlt /> Bookings
    </Link>
    <Link to="/user-events" onClick={() => setMobileMenuOpen(false)} className="flex items-center gap-2 hover:text-red-600">
      <FaConciergeBell /> Events
    </Link>
    <Link to="/restuarntorder" onClick={() => setMobileMenuOpen(false)} className="flex items-center gap-2 hover:text-red-600">
      <FaUtensils /> Add Menu
    </Link>
    <Link to="/manager-chat" onClick={() => setMobileMenuOpen(false)} className="flex items-center gap-2 hover:text-red-600">
      <FaEnvelope /> Messages
    </Link>
  </nav>
</aside>
    <div className="flex-1 md:ml-64 w-full">
      <header className="bg-black dark:bg-gray-900 shadow-lg sticky top-0 z-10 px-6 py-4 flex justify-between items-center">
  <div className="flex items-center gap-4">
    <button
      className="text-white text-2xl md:hidden"
      onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
    >
      {mobileMenuOpen ? <FaTimes /> : <FaBars />}
    </button>
    <div className="hidden md:block w-96 relative">
  <span className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500 dark:text-gray-300 text-sm">
    <FaSearch />
  </span>
  <input
    type="text"
    placeholder="Search..."
    className="w-full pl-10 pr-3 py-1 rounded-md text-sm bg-gray-100 dark:bg-gray-700 text-black dark:text-white focus:outline-none focus:ring-2 focus:ring-red-500"
  />
</div>
  </div>
  <div className="flex items-center gap-4 ml-auto">
    <button
      className="text-white text-xl hover:text-green-500 transition relative"
      title="Notifications"
    >
      <FaBell />
      <span className="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full"></span>
    </button>
    <div className="relative">
      <button
        onClick={() => setShowProfileMenu(!showProfileMenu)}
        className="text-white text-2xl hover:text-green-500 transition"
        title="Restaurant Panel"
      >
        <FaUserCircle />
      </button>
      {showProfileMenu && (
        <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 shadow-lg rounded-lg z-50">
          <ul className="py-2 text-sm text-gray-700 dark:text-gray-200">
            <li>
              <Link to="/profile" className="block px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700">
                Profile
              </Link>
            </li>
            <li>
              <button
                onClick={handleLogout}
                className="w-full text-left block px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                Logout
              </button>
            </li>
          </ul>
        </div>
      )}
    </div>
  </div>
</header>
          <main className="max-w-7xl mx-auto p-6 space-y-12">
<div className="grid grid-cols-1 md:grid-cols-3 gap-6">
  <StatCard
    title="Total Users"
    value={stats.totalUsers}
    icon={<FaUsers className="text-indigo-500 text-3xl" />}
    border="border-indigo-500"
  />
  <StatCard
    title="Total Bookings"
    value={stats.totalBookings}
    icon={<FaCalendarCheck className="text-emerald-500 text-3xl" />}
    border="border-emerald-500"
  />
  <StatCard
    title="Total Events"
    value={stats.totalEvents}
    icon={<FaStar className="text-yellow-500 text-3xl" />}
    border="border-yellow-500"
  />
</div>
<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
  <div className="lg:col-span-2">
    <SectionCard title="Monthly Bookings" icon={<FaChartBar className="text-indigo-600" />}>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" />
          <YAxis allowDecimals={false} />
          <Tooltip />
          <Legend />
          <Bar dataKey="Bookings" fill="#6366F1" />
        </BarChart>
      </ResponsiveContainer>
    </SectionCard>
  </div>
  <div className="space-y-6">
    <SectionCard title="Top Booked Restaurants" icon={<FaUtensils className="text-emerald-600" />}>
      <ul className="space-y-3">
        {popularRestaurants.map((item, idx) => (
          <li
            key={idx}
            className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm flex justify-between items-center"
          >
            <div>
              <p className="font-semibold text-indigo-800 dark:text-indigo-300">{item.restaurant_name}</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">{item.location}</p>
            </div>
            <span className="text-emerald-600 font-semibold">{item.total_bookings} bookings</span>
          </li>
        ))}
      </ul>
    </SectionCard>
    <SectionCard title="Top Booked Events" icon={<FaCalendarAlt className="text-pink-600" />}>
      {popularEvents.length === 0 ? (
        <p className="text-center text-gray-500">No popular events found.</p>
      ) : (
        <ul className="space-y-3">
          {popularEvents.map((item, idx) => (
            <li
              key={idx}
              className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm flex justify-between items-center"
            >
              <p className="font-semibold text-purple-800 dark:text-purple-300">
                {item.eventName}
              </p>
              <span className="text-pink-600 font-semibold">
                {item.total_bookings} bookings
              </span>
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  </div>
</div>
          </main>
        </div>
      </div>
    );
    };
    const StatCard = ({ title, value, icon, border }) => (
      <div className={`bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 border-l-4 ${border}`}>
        <div className="flex items-center space-x-4">
          {icon}
          <div>
            <h3 className="text-gray-600 dark:text-gray-300 font-semibold">{title}</h3>
            <p className="text-2xl font-bold text-gray-800 dark:text-white">{value}</p>
          </div>
        </div>
      </div>
    );
    const SectionCard = ({ title, icon, children }) => (
      <div className="bg-white dark:bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-200 dark:border-gray-600">
        <h2 className="text-lg font-semibold text-gray-800 dark:text-white mb-4 flex items-center gap-2">
          {icon} {title}
        </h2>
        {children}
      </div>
    );
export default DashboardStats;
/*Hello*/