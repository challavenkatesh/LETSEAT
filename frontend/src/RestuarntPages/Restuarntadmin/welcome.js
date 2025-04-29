import React, { useState ,useEffect} from "react";
import { format } from "date-fns";
import { useNavigate } from "react-router-dom";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

import {
  BarChart3,
  Users,
  Building2,
  AlertCircle,
  CalendarDays,
  FileBarChart2,
  Menu,
  Sun,
  Moon,
  UserCircle2,
  MessageCircleWarning,
  Mail,
  DollarSign,
  BarChart2,
  TrendingUp,
  CalendarCheck,
  User,
  X,
  Utensils,
  LogOut,
  Star,

} from "lucide-react";

import "react-calendar/dist/Calendar.css";
import "./CustomCalendar.css"; 
import { motion } from "framer-motion";
import Calendar from "react-calendar";
const events = [
  {
    id: 1,
    name: "Food Festival 2025",
    date: "2025-06-25",
    location: "Los Angeles, CA",
    status: "Scheduled",
    contact: "event1@example.com",
    attendees: 500,
    joining: 200,
    restaurantName: "The Gourmet Hub",
    restaurantLocation: "Los Angeles, CA",
  },
  {
    id: 2,
    name: "Gourmet Night",
    date: "2025-07-10",
    location: "New York, NY",
    status: "In Progress",
    contact: "event2@example.com",
    attendees: 300,
    joining: 150,
    restaurantName: "Delicious Bites",
    restaurantLocation: "New York, NY",
  },
  {
    id: 3,
    name: "Grand Opening",
    date: "2025-08-15",
    location: "San Francisco, CA",
    status: "Completed",
    contact: "event3@example.com",
    attendees: 700,
    joining: 350,
    restaurantName: "Opening Feast",
    restaurantLocation: "San Francisco, CA",
  },
];


const restaurantRatings = [
  { name: "The Royal Feast", rating: 85 },
  { name: "Sushi World", rating: 90 },
  { name: "Green Garden", rating: 75 },
  { name: "BBQ Nation", rating: 95 },
];



const getStatuColor = (status) => {
  switch (status) {
    case "Scheduled":
      return "bg-blue-100 text-blue-600";
    case "In Progress":
      return "bg-yellow-100 text-yellow-600";
    case "Completed":
      return "bg-green-100 text-green-600";
    default:
      return "bg-gray-100 text-gray-600";
  }
};
const restaurantData = [
  {
    name: "The Royal Feast",
    location: "Hyderabad",
    cuisine: "Indian",
    ownerName: "Raj Kumar",
    ownerId: "OWN123",
    ownerEmail: "rajkumar@example.com",
  },
  {
    name: "Sushi World",
    location: "Bangalore",
    cuisine: "Japanese",
    ownerName: "Aiko Tanaka",
    ownerId: "OWN456",
    ownerEmail: "aiko@example.com",
  },
  {
    name: "Green Garden",
    location: "Delhi",
    cuisine: "Vegan",
    ownerName: "Priya Mehra",
    ownerId: "OWN789",
    ownerEmail: "priyamehra@example.com",
  },
  {
    name: "BBQ Nation",
    location: "Mumbai",
    cuisine: "BBQ",
    ownerName: "Aarav Singh",
    ownerId: "OWN999",
    ownerEmail: "aarav@example.com",
  },
];
const bookingData = [
  { month: "Jan", bookings: 30 },
  { month: "Feb", bookings: 45 },
  { month: "Mar", bookings: 60 },
  { month: "Apr", bookings: 40 },
  { month: "May", bookings: 80 },
  { month: "Jun", bookings: 50 },
];

const issues = [
  {
    id: 1,
    title: "Unable to login",
    description: "The user is experiencing login issues despite entering correct credentials.",
    status: "Open",
    contact: "user1@example.com",
  },
  {
    id: 2,
    title: "Payment not processed",
    description: "Customer made the payment but the booking wasn't confirmed.",
    status: "In Progress",
    contact: "user2@example.com",
  },
  {
    id: 3,
    title: "Restaurant not showing",
    description: "A registered restaurant is not visible on the explore page.",
    status: "Resolved",
    contact: "user3@example.com",
  },
];

const getStatusColor = (status) => {
  switch (status) {
    case "Open":
      return "bg-red-100 text-red-600";
    case "In Progress":
      return "bg-yellow-100 text-yellow-700";
    case "Resolved":
      return "bg-green-100 text-green-600";
    default:
      return "bg-gray-100 text-gray-600";
  }
};
const getBookingColor = (type) => {
  switch (type) {
    case "Event":
      return "bg-red-100 text-red-600";
    case "Table":
      return "bg-green-100 text-green-600";
    case "Both":
      return "bg-purple-100 text-purple-600";
    case "Nothing":
      return "bg-gray-100 text-gray-500";
    default:
      return "bg-white";
  }
};

const feedbacks = [
  {
    id: 1,
    name: "Venkatesh",
    email: "venky@example.com",
    rating: 5,
    comment: "Great experience! The food was delicious and the service was excellent.",
  },
  {
    id: 2,
    name: "Sneha",
    email: "sneha@example.com",
    rating: 4,
    comment: "Nice ambience and quick service. Will visit again!",
  },
  // Add more feedbacks as needed
];

const Navbar = () => {
  const navigate = useNavigate(); 

  const handleRowClick = (restoId) => {
    navigate(`/restaurant-manager`);
  };
  

   const handleClick = () => {
     navigate("/user-details");
   };
  const [activePage, setActivePage] = useState("dashboard");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [showProfileDropdown, setShowProfileDropdown] = useState(false);

  const toggleDarkMode = () => setDarkMode(!darkMode);
  const handleLogout = () => {
    localStorage.clear();
    alert("Logged out");
  };
  const reportCards = [
    {
      title: "Total Users",
      value: 1482,
      icon: <Users className="text-white w-5 h-5" />,
      color: "bg-red-600",
    },
    {
      title: "Total Bookings",
      value: 987,
      icon: <CalendarCheck className="text-white w-5 h-5" />,
      color: "bg-green-600",
    },
    {
      title: "Total Revenue",
      value: "₹3,45,600",
      icon: <DollarSign className="text-white w-5 h-5" />,
      color: "bg-black",
    },
    {
      title: "Active Events",
      value: 21,
      icon: <BarChart2 className="text-white w-5 h-5" />,
      color: "bg-red-800",
    },
    {
      title: "Growth Rate",
      value: "12.5%",
      icon: <TrendingUp className="text-white w-5 h-5" />,
      color: "bg-gradient-to-r from-green-700 to-green-500",
    },
  ];

  const commonCardData = [
    { icon: <Users size={32} />, label: "Total Users", value: "152", color: "from-red-400 to-red-600" },
    { icon: <Building2 size={32} />, label: "Restaurants", value: "28", color: "from-black to-gray-700" },
    { icon: <BarChart3 size={32} />, label: "Bookings Today", value: "43", color: "from-green-400 to-green-600" },
    { icon: <AlertCircle size={32} />, label: "Pending Issues", value: "5", color: "from-yellow-400 to-yellow-600" },
    { icon: <CalendarDays size={32} />, label: "Upcoming Events", value: "3", color: "from-blue-400 to-blue-600" },
    { icon: <FileBarChart2 size={32} />, label: "Reports", value: "8", color: "from-purple-400 to-purple-600" },
  ];

  const pages = ["dashboard", "users", "restaurants", "support", "events", "reports", "feedback"];
  const usersData = [
    {
      name: "Alice Johnson",
      email: "alice@example.com",
      gender: "Female",
      location: "New York",
      age: 28,
      booking: "Event",
      paid: true,
    },
    {
      name: "David Smith",
      email: "david@example.com",
      gender: "Male",
      location: "California",
      age: 34,
      booking: "Both",
      paid: true,
    },
    {
      name: "Sofia Lee",
      email: "sofia@example.com",
      gender: "Female",
      location: "Texas",
      age: 22,
      booking: "Table",
      paid: false,
    },
    {
      name: "John Brown",
      email: "john@example.com",
      gender: "Male",
      location: "Florida",
      age: 40,
      booking: "Nothing",
      paid: false,
    },
  ];
  
  const initialIssues = [
    {
      id: 1,
      title: "Unable to login",
      description: "The user is experiencing login issues despite entering correct credentials.",
      status: "Open",
      contact: "user1@example.com",
    },
    {
      id: 2,
      title: "Payment not processed",
      description: "Customer made the payment but the booking wasn't confirmed.",
      status: "In Progress",
      contact: "user2@example.com",
    },
    {
      id: 3,
      title: "Restaurant not showing",
      description: "A registered restaurant is not visible on the explore page.",
      status: "Resolved",
      contact: "user3@example.com",
    },
  ];
  
  const [issues, setIssues] = useState([]);
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [solution, setSolution] = useState("");
  const [formDetails, setFormDetails] = useState({
    assignedTo: "",
    priority: "Medium",
    solvedBy: "",
    resolvedDate: "",
  });

  useEffect(() => {
    const initialIssues = [
      {
        id: 1,
        title: "Unable to login",
        description: "The user is experiencing login issues despite entering correct credentials.",
        status: "Open",
        contact: "user1@example.com",
      },
      {
        id: 2,
        title: "Payment not processed",
        description: "Customer made the payment but the booking wasn't confirmed.",
        status: "In Progress",
        contact: "user2@example.com",
      },
      {
        id: 3,
        title: "Restaurant not showing",
        description: "A registered restaurant is not visible on the explore page.",
        status: "Resolved",
        contact: "user3@example.com",
      },
    ];
    setIssues(initialIssues);
  }, []); // Removed initialIssues from dependency array

  const handleResolve = () => {
    const updated = issues.filter((i) => i.id !== selectedIssue.id);
    setIssues(updated);

    // Auto show next issue if exists
    if (updated.length > 0) {
      setSelectedIssue(updated[0]);
    } else {
      setSelectedIssue(null);
    }

    setSolution("");
    setFormDetails({
      assignedTo: "",
      priority: "Medium",
      solvedBy: "",
      resolvedDate: "",
    });
  };
  const [selectedDate, setSelectedDate] = useState(new Date());
  const todayString = format(selectedDate, "yyyy-MM-dd");

  // Example static data (you can replace with real backend data)
  const allEvents = [
    { name: "Live Music Night", time: "7:00 PM", date: "2025-04-22" },
    { name: "Chef's Special Launch", time: "1:00 PM", date: "2025-04-22" },
    { name: "Sufi Sunday", time: "8:30 PM", date: "2025-04-21" },
    { name: "Wine Tasting", time: "6:00 PM", date: "2025-04-21" },
    { name: "Cooking Class", time: "3:00 PM", date: "2025-04-20" },
    { name: "Food Festival", time: "11:00 AM", date: "2025-04-20" },
    { name: "Charity Dinner", time: "7:30 PM", date: "2025-04-19" },
    { name: "Open Mic Night", time: "9:00 PM", date: "2025-04-19" },



  ];

  const allBookings = [
    { customer: "Rahul Sharma", table: 4, time: "12:30 PM", date: "2025-04-20" },
    { customer: "Priya Patel", table: 2, time: "8:00 PM", date: "2025-04-20" },
    { customer: "Arjun Mehta", table: 1, time: "9:00 PM", date: "2025-04-21" },
  ];

  // Filter for selected date
  const todaysEvents = allEvents.filter(e => e.date === todayString);
  const todaysBookings = allBookings.filter(b => b.date === todayString);

  return (
    <div className={`${darkMode ? "bg-gray-900 text-white" : "bg-white text-black"} min-h-screen font-serif`}>
      {/* Sidebar */}
      <div
        className={`fixed inset-y-0 left-0 bg-black text-white w-64 transform ${
          sidebarOpen || window.innerWidth >= 768 ? "translate-x-0" : "-translate-x-full"
        } transition-transform duration-300 z-50`}
      >
        <div className="p-6">
          <h2 className="text-red-500 font-bold text-xl mb-6">Let's Eat</h2>
          <nav className="space-y-4">
            {pages.map((item) => (
              <button
                key={item}
                onClick={() => {
                  setActivePage(item);
                  setSidebarOpen(false);
                }}
                className={`block w-full text-left capitalize hover:text-red-400 transition-all duration-300 ${
                  activePage === item ? "text-red-500 font-semibold" : ""
                }`}
              >
                {item}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Top Bar */}
      <div className="bg-black text-white px-6 py-4 flex items-center justify-between shadow-md relative z-40">
        <button className="md:hidden" onClick={() => setSidebarOpen(!sidebarOpen)}>
          <Menu />
        </button>
        <div className="hidden md:block text-red-500 font-bold text-xl">Let's Eat</div>
        <div className="flex items-center gap-4">
          <button onClick={toggleDarkMode} className="hover:text-yellow-400 transition-all">
            {darkMode ? <Sun size={20} /> : <Moon size={20} />}
          </button>
          <div className="relative">
            <button onClick={() => setShowProfileDropdown(!showProfileDropdown)} className="hover:text-red-400">
              <UserCircle2 size={24} />
            </button>
            {showProfileDropdown && (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ duration: 0.2 }}
                className="absolute right-0 mt-2 w-40 bg-white text-black rounded-lg shadow-lg z-10"
              >
                <div className="p-3 border-b">
                  <p className="font-semibold">Admin</p>
                  <p className="text-xs text-gray-600">admin@letseat.com</p>
                </div>
                <button
                  onClick={handleLogout}
                  className="flex items-center w-full px-4 py-2 text-sm hover:bg-red-100"
                >
                  <LogOut size={16} className="mr-2" />
                  Logout
                </button>
              </motion.div>
            )}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="ml-0 md:ml-64 p-6 transition-all duration-300">
        <motion.div
          key={activePage}
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          {activePage === "dashboard" && (
            <>
           <h2 className="text-3xl font-bold mb-8 text-center text-red-500 animate-fade-in">
        📊 Admin Dashboard
      </h2>

      {/* Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8 mb-12">
        {commonCardData.map((card, i) => (
          <motion.div
            key={i}
            whileHover={{ scale: 1.05 }}
            className={`bg-gradient-to-br ${card.color} text-white p-6 rounded-2xl shadow-xl flex flex-col items-center justify-center transition-all animate-fade-in-up`}
          >
            <div className="mb-3 animate-bounce">{card.icon}</div>
            <h3 className="text-lg font-semibold">{card.label}</h3>
            <p className="text-3xl font-bold">{card.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Ratings and Calendar Section */}
      <div className="flex flex-col lg:flex-row gap-10 justify-between">
        {/* Ratings Left Side */}
        <div className="flex-1">
          <h3 className="text-2xl font-bold text-red-600 mb-6">🔥 Restaurant Ratings</h3>
          {restaurantRatings.map((restaurant, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, x: -50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.2 * index }}
              className="mb-6"
            >
              <h4 className="text-lg font-semibold text-black mb-2">{restaurant.name}</h4>
              <div className="w-full h-3 bg-gray-200 rounded-lg overflow-hidden">
                <motion.div
                  className="h-full bg-red-500 rounded-lg"
                  initial={{ width: 0 }}
                  animate={{ width: `${restaurant.rating}%` }}
                  transition={{ duration: 1, ease: "easeInOut" }}
                />
              </div>
            </motion.div>
          ))}
        </div>

        {/* Calendar Right Side */}
        <div className="w-full lg:w-[300px]">
          <h3 className="text-2xl font-bold text-red-600 mb-4 text-center">📅 Select Date</h3>
          <div className="bg-black text-white rounded-2xl shadow-xl p-4 border border-red-500">
          <Calendar
  onChange={setSelectedDate}
  value={selectedDate}
  className="styled-calendar"
/>

          </div>
        </div>
      </div>
      <div className="mt-12 grid grid-cols-1 md:grid-cols-2 gap-10">
  {/* Today's Events */}
  <motion.div
    initial={{ opacity: 0, y: 50 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.5 }}
    className="bg-white border-l-8 border-red-500 p-6 rounded-xl shadow-lg"
  >
    <h3 className="text-2xl font-bold text-red-600 mb-4 font-serif">🎉 Today's Events</h3>
    {todaysEvents.length ? (
      todaysEvents.map((event, i) => (
        <div key={i} className="mb-3 p-3 bg-gray-100 rounded-lg">
          <h4 className="font-semibold text-black">{event.name}</h4>
          <p className="text-sm text-gray-700">Time: {event.time}</p>
        </div>
      ))
    ) : (
      <p className="text-gray-500 italic">No events today</p>
    )}
  </motion.div>

  {/* Today's Bookings */}
  <motion.div
    initial={{ opacity: 0, y: 50 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.5, delay: 0.2 }}
    className="bg-white border-l-8 border-black p-6 rounded-xl shadow-lg"
  >
    <h3 className="text-2xl font-bold text-black mb-4 font-serif">📖 Today's Bookings</h3>
    {todaysBookings.length ? (
      todaysBookings.map((booking, i) => (
        <div key={i} className="mb-3 p-3 bg-gray-100 rounded-lg">
          <h4 className="font-semibold text-black">Customer: {booking.customer}</h4>
          <p className="text-sm text-gray-700">
            Table: {booking.table} | Time: {booking.time}
          </p>
        </div>
      ))
    ) : (
      <p className="text-gray-500 italic">No bookings today</p>
    )}
  </motion.div>
</div>

  
            </>
          )}

          {activePage === "users" && <h2 className="text-2xl font-semibold text-center animate-fade-in">
          <motion.div
      className="p-6 font-serif"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
    >
      <h2 className="text-3xl font-bold text-red-600 mb-6 flex items-center gap-2">
        <Users className="text-green-600" />
        User Management
      </h2>

      <div className="overflow-x-auto shadow-2xl rounded-2xl">
        <table className="min-w-full text-sm text-left bg-white border border-gray-200 rounded-2xl overflow-hidden">
          <thead className="bg-black text-white text-xs uppercase">
            <tr>
              <th className="py-3 px-6">Name</th>
              <th className="py-3 px-6">Email</th>
              <th className="py-3 px-6">Gender</th>
              <th className="py-3 px-6">Location</th>
              <th className="py-3 px-6">Age</th>
              <th className="py-3 px-6">Booking</th>
              <th className="py-3 px-6">Paid</th>
            </tr>
          </thead>
          <tbody className="text-gray-800">
  {usersData.map((user, index) => (
  <motion.tr
  key={index}
  whileHover={{ scale: 1.01 }}
  onClick={handleClick}
  className="border-b transition-all duration-300 hover:bg-red-50 cursor-pointer"
>
      <td className="py-3 px-6 font-medium">{user.name}</td>
      <td className="py-3 px-6">{user.email}</td>
      <td className="py-3 px-6">{user.gender}</td>
      <td className="py-3 px-6">{user.location}</td>
      <td className="py-3 px-6">{user.age}</td>
      <td className="py-3 px-6">
        <span
          className={`px-3 py-1 rounded-full text-xs font-semibold ${getBookingColor(
            user.booking
          )}`}
        >
          {user.booking}
        </span>
      </td>
      <td className="py-3 px-6">
        <span
          className={`px-3 py-1 rounded-full text-xs font-bold ${
            user.paid ? "bg-green-100 text-green-600" : "bg-red-100 text-red-600"
          }`}
        >
          {user.paid ? "Yes" : "No"}
        </span>
      </td>
    </motion.tr>
  ))}
</tbody>
        </table>
      </div>
    </motion.div>
            </h2>}
          {activePage === "restaurants" && <h2 className="text-2xl font-semibold text-center animate-fade-in">
            <motion.div
      className="p-6 font-serif"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
    >
      <h2 className="text-3xl font-bold text-red-600 mb-6 flex items-center gap-2">
        <Utensils className="text-green-600" />
        Restaurant Management
      </h2>

      <div className="overflow-x-auto shadow-2xl rounded-2xl">
        <table className="min-w-full text-sm text-left bg-white border border-gray-200 rounded-2xl overflow-hidden">
          <thead className="bg-black text-white text-xs uppercase">
            <tr>
              <th className="py-3 px-6">Name</th>
              <th className="py-3 px-6">Location</th>
              <th className="py-3 px-6">Cuisine</th>
              <th className="py-3 px-6">Owner Name</th>
              <th className="py-3 px-6">Owner ID</th>
              <th className="py-3 px-6">Owner Email</th>
            </tr>
          </thead>
          <tbody className="text-gray-800">
            {restaurantData.map((resto) => (
              <motion.tr
                key={resto.id} // Use unique id for key
                whileHover={{ scale: 1.01 }}
                className="border-b transition-all duration-300 hover:bg-red-50 cursor-pointer"
                onClick={() => handleRowClick(resto.id)} // Add onClick handler
              >
                <td className="py-3 px-6 font-medium">{resto.name}</td>
                <td className="py-3 px-6">{resto.location}</td>
                <td className="py-3 px-6">{resto.cuisine}</td>
                <td className="py-3 px-6">{resto.ownerName}</td>
                <td className="py-3 px-6">{resto.ownerId}</td>
                <td className="py-3 px-6">{resto.ownerEmail}</td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.div>
            </h2>}
          {activePage === "support" && <h2 className="text-2xl font-semibold text-center animate-fade-in">
            <motion.div
      className="p-6 font-serif"
      initial={{ opacity: 0, y: 30 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
    >
      <h2 className="text-3xl font-bold text-red-600 mb-6 flex items-center gap-2">
        <MessageCircleWarning className="text-green-600" />
        Support & Issues
      </h2>

      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {issues.map((issue) => (
          <motion.div
            key={issue.id}
            className="bg-white border border-gray-200 shadow-xl rounded-2xl p-5 transition-all hover:shadow-2xl hover:scale-[1.01] cursor-pointer"
            whileHover={{ y: -5 }}
            onClick={() => {
              setSelectedIssue(issue);
              setSolution("");
            }}
          >
            <h3 className="text-xl font-semibold text-black mb-2 flex items-center gap-2">
              <AlertCircle className="text-red-500" />
              {issue.title}
            </h3>
            <p className="text-gray-700  text-sm mb-3">{issue.description}</p>
            <div className="flex justify-between items-center">
              <span
                className={`text-xs font-bold px-3 py-1 rounded-full ${getStatusColor(
                  issue.status
                )}`}
              >
                {issue.status}
              </span>
              <span className="text-sm text-blue-600 flex items-center gap-1">
                <Mail className="w-4 h-4" />
                {issue.contact}
              </span>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Modal Popup */}
      {selectedIssue && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-white rounded-2xl p-6 w-full max-w-2xl shadow-2xl relative"
          >
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 text-gray-400 hover:text-red-600"
              onClick={() => {
                setSelectedIssue(null);
                setSolution("");
              }}
            >
              <X />
            </button>

            {/* Issue Form */}
            <h3 className="text-2xl font-bold text-red-600 mb-4">
              Solve Issue
            </h3>
            <h3 className="text-xl font-semibold text-gray-800 mb-4">Resolve Issue</h3>

<form
  onSubmit={(e) => {
    e.preventDefault();
    handleResolve();
  }}
  className="grid grid-cols-1 md:grid-cols-2 gap-5 bg-white p-6 rounded-lg shadow-md"
>
  {/* Issue Title */}
  <div>
    <label className="text-sm text-gray-600 mb-1 block">Issue Title</label>
    <input
      type="text"
      value={selectedIssue.title}
      disabled
      className="w-full border rounded-md px-3 py-2 bg-gray-100 text-sm"
    />
  </div>

  {/* Issue ID */}
  <div>
    <label className="text-sm text-gray-600 mb-1 block">Issue ID</label>
    <input
      type="text"
      value={selectedIssue.id}
      disabled
      className="w-full border rounded-md px-3 py-2 bg-gray-100 text-sm"
    />
  </div>

  {/* Assigned To */}
  <div>
    <label className="text-sm text-gray-700 mb-1 block">Assigned To</label>
    <input
      type="text"
      value={formDetails.assignedTo}
      onChange={(e) =>
        setFormDetails({ ...formDetails, assignedTo: e.target.value })
      }
      required
      className="w-full border rounded-md px-3 py-2 text-sm"
    />
  </div>

  {/* Priority */}
  <div>
    <label className="text-sm text-gray-700 mb-1 block">Priority</label>
    <select
      value={formDetails.priority}
      onChange={(e) =>
        setFormDetails({ ...formDetails, priority: e.target.value })
      }
      className="w-full border rounded-md px-3 py-2 text-sm"
    >
      <option>Low</option>
      <option>Medium</option>
      <option>High</option>
    </select>
  </div>

  {/* Solved By */}
  <div>
    <label className="text-sm text-gray-700 mb-1 block">Solved By</label>
    <input
      type="text"
      value={formDetails.solvedBy}
      onChange={(e) =>
        setFormDetails({ ...formDetails, solvedBy: e.target.value })
      }
      required
      className="w-full border rounded-md px-3 py-2 text-sm"
    />
  </div>

  {/* Date Resolved */}
  <div>
    <label className="text-sm text-gray-700 mb-1 block">Date Resolved</label>
    <input
      type="date"
      value={formDetails.resolvedDate}
      onChange={(e) =>
        setFormDetails({ ...formDetails, resolvedDate: e.target.value })
      }
      required
      className="w-full border rounded-md px-3 py-2 text-sm"
    />
  </div>

  {/* Solution */}
  <div className="md:col-span-2">
  
    <textarea
      value={solution}
      onChange={(e) => setSolution(e.target.value)}
      rows="4"
      placeholder="Describe how the issue was resolved..."
      required
      className="w-full border rounded-md px-3 py-2 text-sm resize-none"
    />
  </div>

  {/* Submit */}
  <div className="md:col-span-2 text-right">
    <button
      type="submit"
      className="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-md text-sm"
    >
      Submit & Resolve
    </button>
  </div>
</form>

          </motion.div>
        </div>
      )}
    </motion.div>
    
            </h2>}
          {activePage === "events" && <h2 className="text-2xl font-semibold text-center animate-fade-in">
            <motion.div
  className="p-6 font-serif bg-gradient-to-br from-white to-red-50 rounded-3xl shadow-lg"
  initial={{ opacity: 0, y: 30 }}
  animate={{ opacity: 1, y: 0 }}
  transition={{ duration: 0.6 }}
>
  <h2 className="text-2xl font-bold text-red-700 mb-5 flex items-center gap-3">
    <img
      src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSjZeBcuCj5lQ8UfeqWewLBFPyNvPV4PucQ_g&s"
      alt="Event Icon"
      className="w-7 h-7 rounded-full object-cover border border-red-300 shadow"
    />
    Events Monitoring
  </h2>

  <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
    {events.map((event) => (
      <motion.div
        key={event.id}
        className="bg-white border border-red-100 text-gray-800 shadow-md rounded-2xl p-4 transition-all hover:shadow-xl hover:scale-[1.015] hover:-translate-y-[2px]"
        whileHover={{ scale: 1.02 }}
      >
        <h3 className=" text-sm font-semibold text-red-600 mb-2">{event.name}</h3>
        <div className="text-left">
        <p className="text-sm text-gray-600 mb-1 ">📅 <strong>Date:</strong> {event.date}</p>
        <p className="text-sm text-gray-600 mb-1">📍 <strong>Location:</strong> {event.location}</p>
        <p className="text-sm text-gray-600 mb-1">👨‍🍳 <strong>Conducted by:</strong> {event.restaurantName}</p>
        <p className="text-sm text-gray-600 mb-3">🏠 <strong>Restaurant Location:</strong> {event.restaurantLocation}</p>
        </div>
        <div className="flex justify-between items-center mt-3">
          <span
            className={`text-xs font-medium px-3 py-1 rounded-full shadow-sm ${getStatuColor(event.status)}`}
          >
            {event.status}
          </span>
          <span className="text-xs text-green-700 flex items-center gap-1">
            <User className="w-3.5 h-3.5" />
            {event.contact}
          </span>
        </div>

        <div className="mt-3 flex justify-between text-xs text-gray-500">
          <div className="flex items-center gap-1">
            👥 <span className="font-medium">Attendees:</span> {event.attendees}
          </div>
          <div className="flex items-center gap-1">
            ✅ <span className="font-medium">Joining:</span> {event.joining}
          </div>
        </div>
      </motion.div>
    ))}
  </div>
</motion.div>

            </h2>}
          {activePage === "reports" && <h2 className="text-2xl font-semibold text-center animate-fade-in">
            <motion.div
      className="p-6 font-serif"
      initial={{ opacity: 0, y: 30 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
    >
      <h2 className="text-3xl font-bold text-red-600 mb-6 flex items-center gap-2">
        <BarChart2 className="text-green-600" />
        Reports & Analytics
      </h2>

      {/* Cards Section */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-10">
        {reportCards.map((card, idx) => (
          <motion.div
            key={idx}
            whileHover={{ scale: 1.03 }}
            className={`rounded-2xl shadow-xl text-white p-6 flex justify-between items-center ${card.color}`}
          >
            <div>
              <p className="text-sm uppercase tracking-wide text-white/70">{card.title}</p>
              <h3 className="text-2xl font-bold mt-1">{card.value}</h3>
            </div>
            <div className="p-2 rounded-full bg-white/10">
              {card.icon}
            </div>
          </motion.div>
        ))}
      </div>

      {/* Chart Placeholder */}
      <div  className="bg-white rounded-2xl shadow-2xl p-6">
  <h3 className="text-xl font-semibold text-red-600 mb-4">
    Booking Trends Overview
  </h3>

  <div className="w-full h-60">
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={bookingData}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="month" />
        <YAxis />
        <Tooltip />
        <Line type="monotone" dataKey="bookings" stroke="#ef4444" strokeWidth={2} />
      </LineChart>
    </ResponsiveContainer>
  </div>

      </div>
    </motion.div>
            </h2>}
        </motion.div>
        {activePage === "feedback" && <h2 className="text-2xl font-semibold text-center animate-fade-in">
          <motion.div>
          <motion.div
      className="p-6 bg-white rounded-3xl shadow-md font-sans"
      initial={{ opacity: 0, y: 40 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
    >
      <h2 className="text-2xl font-bold text-red-700 mb-6 flex items-center gap-3">
        <img
          src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSjZeBcuCj5lQ8UfeqWewLBFPyNvPV4PucQ_g&s"
          alt="Feedback Icon"
          className="w-8 h-8 rounded-full object-cover border border-gold-500"
        />
        User Feedback
      </h2>

      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {feedbacks.map((feedback) => (
          <div
            key={feedback.id}
            className="bg-gradient-to-br from-green-50 to-white border border-gold-300 rounded-xl p-5 shadow hover:shadow-lg transition duration-300"
          >
            <div className="flex items-center gap-3 mb-2">
              <User className="w-5 h-5 text-red-600" />
              <div>
                <h3 className="text-lg font-semibold text-green-800">{feedback.name}</h3>
                <p className="text-sm text-gray-500">{feedback.email}</p>
              </div>
            </div>

            <p className="text-gray-700 italic mb-3">"{feedback.comment}"</p>

            <div className="flex gap-1 text-gold-500">
              {[...Array(5)].map((_, i) => (
                <Star
                  key={i}
                  fill={i < feedback.rating ? "#FFD700" : "none"}
                  stroke="#FFD700"
                  className="w-4 h-4"
                />
              ))}
            </div>
          </div>
        ))}
      </div>
    </motion.div>
          </motion.div>
        </h2>}
      </div>
    </div>
  );
};

export default Navbar;
