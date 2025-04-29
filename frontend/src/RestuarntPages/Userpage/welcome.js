import React, { useState ,useEffect} from "react";
import { Link } from "react-router-dom";
import { Menu, X, Settings,Star,User,Tag,Percent, KeyRound, LogOut,Sun,Moon ,CheckCircle} from "lucide-react";
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem } from "@radix-ui/react-dropdown-menu";
import { motion } from "framer-motion";
import { FaFacebookF, FaInstagram, FaTwitter, FaLinkedinIn,FaMapMarkerAlt  } from "react-icons/fa";
import { MessageSquare, Phone, Utensils } from "lucide-react";
import { useNavigate } from "react-router-dom";
import logo from "./logo-1.png";
import "./welcome.css"
import UserChat from "./UserChat";
function Welcome() {
  const [showModal, setShowModal] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);

  const handleClick = () => {
    setShowModal(true);
    setIsConnecting(false);
  };

  const startCall = () => {
    setIsConnecting(true);
    setTimeout(() => {
      setIsConnecting(false);
    }, 5000); // Simulate a 2-second loading delay
  };
  const [menuOpen, setMenuOpen] = useState(false);
  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
  };
  const [chatOpen, setChatOpen] = useState(false);
  const toggleChat = () => {
    setChatOpen(!chatOpen);
  };

  const navigate = useNavigate(); // ✅ Hook inside the component

  const orderNow = () => {
    navigate("/order"); // ✅ Use navigate here
  };
  const [darkMode, setDarkMode] = useState(false);

  // Toggle theme
  const toggleTheme = () => {
    setDarkMode(!darkMode);
    document.documentElement.classList.toggle("dark", !darkMode);
    localStorage.setItem("theme", !darkMode ? "dark" : "light");
  };

  // Load saved theme
  useEffect(() => {
    const savedTheme = localStorage.getItem("theme");
    if (savedTheme === "dark") {
      setDarkMode(true);
      document.documentElement.classList.add("dark");
    }
  }, []);
  const restaurants = [
    {
      id: 1,
      name: "Spice Heaven",
      image: "https://images.pexels.com/photos/31336108/pexels-photo-31336108/free-photo-of-indonesian-cuisine-platter-with-herbal-tea.jpeg?auto=compress&cs=tinysrgb&w=600",
      rating: 4.5,
    },
    {
      id: 2,
      name: "The Royal Dine",
      image: "https://images.pexels.com/photos/27570262/pexels-photo-27570262/free-photo-of-a-room-with-gold-walls-and-furniture.jpeg?auto=compress&cs=tinysrgb&w=600",
      rating: 4.8,
    },
    {
      id: 3,
      name: "Urban Bites",
      image: "https://images.pexels.com/photos/11003499/pexels-photo-11003499.jpeg?auto=compress&cs=tinysrgb&w=600",
      rating: 4.2,
    },
    {
      id: 4,
      name: "Seafood Paradise",
      image: "https://images.pexels.com/photos/28843909/pexels-photo-28843909/free-photo-of-luxurious-underwater-restaurant-in-maldives.jpeg?auto=compress&cs=tinysrgb&w=600",
      rating: 4.7,
    },
  ];
  
const deals = [
  {
    id: 1,
    name: "Spice Heaven",
    image: "https://images.pexels.com/photos/31336108/pexels-photo-31336108/free-photo-of-indonesian-cuisine-platter-with-herbal-tea.jpeg?auto=compress&cs=tinysrgb&w=600",
    discount: "30% OFF",
    deal: "Free Dessert with Dinner",
  },
  {
    id: 2,
    name: "The Royal Dine",
    image: "https://images.pexels.com/photos/27570262/pexels-photo-27570262/free-photo-of-a-room-with-gold-walls-and-furniture.jpeg?auto=compress&cs=tinysrgb&w=600",
    discount: "25% OFF",
    deal: "Special Combo Meals",
  },
  {
    id: 3,
    name: "Urban Bites",
    image: "https://images.pexels.com/photos/11003499/pexels-photo-11003499.jpeg?auto=compress&cs=tinysrgb&w=600",
    discount: "Buy 1 Get 1 Free",
    deal: "On All Beverages",
  },
  {
    id: 4,
    name: "Seafood Paradise",
    image: "https://images.pexels.com/photos/28843909/pexels-photo-28843909/free-photo-of-luxurious-underwater-restaurant-in-maldives.jpeg?auto=compress&cs=tinysrgb&w=600",
    discount: "Flat 20% OFF",
    deal: "Exclusive Weekend Offer",
  },
];
  
  return (
    <div>
      <nav className=" w-full z-50  bg-transparent fixed">
        <div className="container mx-auto flex justify-between items-center">
          {/* Logo */}
          <div className="flex items-center">
            <img src={logo} alt="Logo" className="h-20 w-auto" />
          </div>

          {/* Centered Navigation Links */}
          <div className="hidden md:flex space-x-6 items-center flex-grow justify-center">
            <Link to="/userpage" className="text-black font-serif hover:text-red-600">Home</Link>
            <Link to="/restaurants" className="text-black font-serif hover:text-red-600">Restaurants</Link>
            <Link to="/bookings" className="text-black font-serif hover:text-red-600">Bookings</Link>
            <Link to="/events-list" className="text-black font-serif hover:text-red-600">Events</Link>
            <Link to="/order" className="text-black font-serif hover:text-red-600">Order</Link>
          </div>

          {/* Settings (Right-Aligned) */}
          <div className="hidden md:flex">
          <DropdownMenu>
  <DropdownMenuTrigger className="flex items-center bg-gray-200 dark:bg-gray-700 p-2 rounded-full cursor-pointer hover:bg-gray-300 dark:hover:bg-gray-600">
    <Settings size={20} />
  </DropdownMenuTrigger>
  <DropdownMenuContent className="bg-white dark:bg-gray-800 shadow-lg p-2 rounded-md w-48 mt-2">
    
    {/* Profile */}
    <DropdownMenuItem className="flex items-center p-2 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer">
      <User size={18} className="mr-2" />
      <Link to="/user-profile" className="w-full">Profile</Link>
    </DropdownMenuItem>

    {/* Change Password */}
    <DropdownMenuItem className="flex items-center p-2 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer">
      <KeyRound size={18} className="mr-2" />
      <Link to="/change-password" className="w-full">Change Password</Link>
    </DropdownMenuItem>

    {/* Theme Toggle */}
    <DropdownMenuItem
      onClick={toggleTheme}
      className="flex items-center p-2 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer"
    >
      {darkMode ? <Sun size={18} className="mr-2" /> : <Moon size={18} className="mr-2" />}
      {darkMode ? "Light Mode" : "Dark Mode"}
    </DropdownMenuItem>

    {/* Logout */}
    <DropdownMenuItem className="flex items-center p-2 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer text-red-500">
      <LogOut size={18} className="mr-2" />
      <Link to="/welcome" className="w-full">Logout</Link>
    </DropdownMenuItem>

  </DropdownMenuContent>
</DropdownMenu>

          </div>

          {/* Mobile Menu Toggle */}
          <div className="md:hidden cursor-pointer" onClick={() => setMenuOpen(!menuOpen)}>
            {menuOpen ? <X size={24} /> : <Menu size={24} />}
          </div>
        </div>

        {/* Mobile Menu */}
        {menuOpen && (
          <div className="md:hidden bg-gray-100 p-4 absolute top-20 left-0 w-full shadow-lg flex flex-col items-center">
            <Link to="/" className="block text-gray-700 hover:text-blue-600">Home</Link>
            <Link to="/restaurants" className="block text-gray-700 hover:text-blue-600">Restaurants</Link>
            <Link to="/bookings" className="block text-gray-700 hover:text-blue-600">Bookings</Link>
            <Link to="/events-list" className="block text-gray-700 hover:text-blue-600">Events</Link>

            {/* Mobile Settings Dropdown */}
            <DropdownMenu>
  <DropdownMenuTrigger className="flex items-center bg-gray-200 dark:bg-gray-700 p-2 rounded-full cursor-pointer hover:bg-gray-300 dark:hover:bg-gray-600">
    <Settings size={20} />
  </DropdownMenuTrigger>
  <DropdownMenuContent className="bg-white dark:bg-gray-800 shadow-lg p-2 rounded-md w-48 mt-2">
    
    {/* Profile */}
    <DropdownMenuItem className="flex items-center p-2 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer">
      <User size={18} className="mr-2" />
      <Link to="/user-profile" className="w-full">Profile</Link>
    </DropdownMenuItem>

    {/* Change Password */}
    <DropdownMenuItem className="flex items-center p-2 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer">
      <KeyRound size={18} className="mr-2" />
      <Link to="/change-password" className="w-full">Change Password</Link>
    </DropdownMenuItem>

    {/* Theme Toggle */}
    <DropdownMenuItem
      onClick={toggleTheme}
      className="flex items-center p-2 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer"
    >
      {darkMode ? <Sun size={18} className="mr-2" /> : <Moon size={18} className="mr-2" />}
      {darkMode ? "Light Mode" : "Dark Mode"}
    </DropdownMenuItem>

    {/* Logout */}
    <DropdownMenuItem className="flex items-center p-2 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer text-red-500">
      <LogOut size={18} className="mr-2" />
      <Link to="/welcome" className="w-full">Logout</Link>
    </DropdownMenuItem>

  </DropdownMenuContent>
</DropdownMenu>

          </div>
        )}
      </nav>
      <section
      className="relative bg-cover bg-center h-screen flex items-center justify-center text-center px-6"
      style={{ backgroundImage: `url('https://images.pexels.com/photos/349610/pexels-photo-349610.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=1')` }}
    >
      {/* Overlay */}

      {/* Content */}
      <motion.div
        className="relative z-10 max-w-3xl text-white"
        initial={{ opacity: 0, y: 50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 1, ease: "easeOut" }}
      >
        <motion.h1
          className="text-4xl sm:text-5xl font-extrabold mb-4 text-red-500"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, duration: 1 }}
        >
          Discover & Book Your Favorite Restaurants
        </motion.h1>

        <motion.p
          className="text-base sm:text-lg mb-6 text-black"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6, duration: 1 }}
        >
          Enjoy fine dining experiences with seamless reservations. Your perfect meal is just a click away!
        </motion.p>

        <motion.div
          className="flex flex-col sm:flex-row justify-center space-y-4 sm:space-y-0 sm:space-x-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.9, duration: 1 }}
        >
          <Link
            to="/restaurants"
            className="relative inline-flex items-center justify-center px-6 py-3 text-lg font-semibold text-white transition duration-300 ease-in-out bg-red-600 rounded-lg shadow-md hover:text-red-600 group"
          >
            <span className="absolute inset-0 w-full h-full transition-all duration-300 transform scale-0 bg-white group-hover:scale-100"></span>
            <span className="relative z-10">Explore Restaurants</span>
          </Link>

          <Link
            to="/bookings"
            className="relative inline-flex items-center justify-center px-6 py-3 text-lg font-semibold text-white transition duration-300 ease-in-out bg-black rounded-lg shadow-md hover:text-black group"
          >
            <span className="absolute inset-0 w-full h-full transition-all duration-300 transform scale-0 bg-white group-hover:scale-100"></span>
            <span className="relative z-10">My Bookings</span>
          </Link>
        </motion.div>
      </motion.div>
    </section>
    <section className="py-12 bg-gray-100">
      <div className="max-w-6xl mx-auto px-6 text-center">
        <h2 className="text-4xl font-extrabold text-gray-800 mb-6">
          Top Restaurants
        </h2>
        <p className="text-gray-600 mb-8">
          Discover the best dining experiences curated just for you.
        </p>

        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {restaurants.map((restaurant) => (
            <div
              key={restaurant.id}
              className="bg-white shadow-lg rounded-lg overflow-hidden transform transition duration-300 hover:scale-105"
            >
              <img
                src={restaurant.image}
                alt={restaurant.name}
                className="w-full h-48 object-cover"
              />
              <div className="p-4">
                <h3 className="text-xl font-semibold text-gray-800">
                  {restaurant.name}
                </h3>
                <div className="flex items-center justify-center my-2">
                  {[...Array(5)].map((_, index) => (
                    <Star
                      key={index}
                      size={20}
                      className={`${
                        index < Math.round(restaurant.rating)
                          ? "text-yellow-400"
                          : "text-gray-300"
                      }`}
                    />
                  ))}
                  <span className="ml-2 text-gray-600">
                    {restaurant.rating}
                  </span>
                </div>
                <Link
                  to='/restaurants'
                  className="mt-3 inline-block bg-red-600 text-white px-6 py-2 rounded-lg font-semibold text-lg transition duration-300 hover:bg-red-700"
                >
                  Book Now
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
    <section className="py-12 bg-white">
      <div className="max-w-6xl mx-auto px-6 text-center">
        <h2 className="text-4xl font-extrabold text-black mb-6 flex items-center justify-center gap-2">
          <Tag className="text-red-500" size={32} /> Exclusive Deals & Offers
        </h2>
        <p className="text-black mb-8">
          Grab the hottest restaurant deals before they expire! 
        </p>

        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {deals.map((deal) => (
            <div
              key={deal.id}
              className="bg-gray-900 shadow-xl rounded-lg overflow-hidden transform transition duration-300 hover:scale-105 hover:shadow-red-500/50"
            >
              <img
                src={deal.image}
                alt={deal.name}
                className="w-full h-48 object-cover"
              />
              <div className="p-4 text-white">
                <h3 className="text-xl font-bold">{deal.name}</h3>
                <div className="flex items-center justify-center mt-2 text-red-500 text-lg font-semibold">
                  <Percent size={20} className="mr-2" />
                  {deal.discount}
                </div>
                <p className="text-gray-300 mt-1">{deal.deal}</p>
                <Link
                  to='/restaurants'
                  className="mt-4 inline-block bg-red-600 text-white px-6 py-2 rounded-lg font-semibold text-lg transition duration-300 hover:bg-red-700"
                >
                  Grab Deal
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
         {/* New Section: Order Availability & Features */}
      <section className="py-12 bg-white">
        <div className="max-w-6xl mx-auto px-6 grid md:grid-cols-2 gap-8 items-center">
          {/* Left Side: Image */}
          <div>
            <img
              src="https://img.freepik.com/premium-vector/food-delivery-online-concept-vector_1162942-1594.jpg?semt=ais_hybrid"
              alt="Order Available"
              className="w-full rounded-lg shadow-lg border-4"
            />
          </div>

          {/* Right Side: Information */}
          <div>
            <h2 className="text-3xl font-bold mb-4 text-red-500">
              Order Your Favorite Dishes Online 
            </h2>
            <p className="text-black mb-4">
              Enjoy delicious meals from our restaurant, available for dine-in, takeaway, and delivery.
            </p>
            <ul className="space-y-3">
              <li className="flex items-center gap-2">
                <CheckCircle className="text-red-500" size={20} />
                Quick and Easy Online Ordering
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="text-red-500" size={20} />
                Fast Home Delivery
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="text-red-500" size={20} />
                Fresh and High-Quality Ingredients
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="text-red-500" size={20} />
                Exclusive Deals for Online Orders
              </li>
            </ul>
            <button onClick={orderNow} className="mt-6 bg-red-600 text-white px-6 py-2 rounded-lg font-semibold text-lg transition duration-300 hover:bg-red-700">
              Order Now
            </button>
          </div>
        </div>
      </section>
      
     <footer className="bg-black text-white py-12 mt-10">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
              
              <div>
              <div className="bg-white p-3 rounded-lg shadow-lg inline-block">
      <img src={logo} alt="Let's Eat Logo" className="h-12 object-contain" />
    </div>
                <p className="mt-3 text-white">
                  Experience the best dining with us. Quality food, exceptional service, and a great atmosphere.
                </p>
              </div>
    
              <div>
                <h2 className="text-xl font-semibold text-red-500">Quick Links</h2>
                <ul className="mt-3 space-y-2">
                  <li><a href="/about" className="text-white hover:text-red-500 transition">About Us</a></li>
                  <li><a href="/menu" className="text-white hover:text-red-500 transition">Menu</a></li>
                  <li><a href="/events" className="text-white hover:text-red-500 transition">Events</a></li>
                  <li><a href="/contact" className="text-white hover:text-red-500 transition">Contact</a></li>
                  <li><a href="/careers" className="text-white hover:text-red-500 transition">Careers</a></li>
                </ul>
              </div>
    
              <div>
                <h2 className="text-xl font-semibold text-red-500">Our Branches</h2>
                <ul className="mt-3 space-y-2">
                  <li className="text-white flex items-center">
                    <FaMapMarkerAlt className="text-red-500 mr-2" /> New York - Times Square
                  </li>
                  <li className="text-white flex items-center">
                    <FaMapMarkerAlt className="text-red-500 mr-2" /> Los Angeles - Downtown
                  </li>
                  <li className="text-white flex items-center">
                    <FaMapMarkerAlt className="text-red-500 mr-2" /> Chicago - Millennium Park
                  </li>
                  <li className="text-white flex items-center">
                    <FaMapMarkerAlt className="text-red-500 mr-2" /> Houston - River Oaks
                  </li>
                  <li className="text-white flex items-center">
                    <FaMapMarkerAlt className="text-red-500 mr-2" /> Miami - South Beach
                  </li>
                </ul>
              </div>
    
              <div>
                <h2 className="text-xl font-semibold text-red-500">Contact Us</h2>
                <p className="mt-3 text-white">123 Food Street, Foodville</p>
                <p className="text-white">Phone: (123) 456-7890</p>
                <p className="text-white">Email: contact@letseat.com</p>
                <div className="flex space-x-4 mt-4">
                  <a href="/" className="text-white hover:text-red-500 transition">
                    <FaFacebookF size={20} />
                  </a>
                  <a href="/" className="text-white hover:text-red-500 transition">
                    <FaInstagram size={20} />
                  </a>
                  <a href="/" className="text-white hover:text-red-500 transition">
                    <FaTwitter size={20} />
                  </a>
                  <a href="/" className="text-white hover:text-red-500 transition">
                    <FaLinkedinIn size={20} />
                  </a>
                </div>
              </div>
            </div>
    
            <div className="border-t border-red-500 mt-8 pt-4 text-center text-white">
              © {new Date().getFullYear()} Let's Eat. All Rights Reserved.
            </div>
          </div>
        </footer>
        <section className="fixed bottom-10 right-10 z-50">
      <div className="flex flex-col items-center space-y-4">
        {menuOpen && (
          <div className="flex flex-col items-center space-y-4 mb-4">
            <button
              title="Chat"
              onClick={toggleChat}
              className="group cursor-pointer p-4 bg-red-600 rounded-full shadow-lg transform transition-all hover:scale-110 duration-300"
            >
              <MessageSquare className="text-white group-hover:text-gray-200 text-2xl" />
            </button>
            
    <div>
      <button
        title="Phone"
        onClick={handleClick}
        className="group cursor-pointer p-4 bg-black rounded-full shadow-lg transform transition-all hover:scale-110 duration-300"
      >
        <Phone className="text-white group-hover:text-gray-300 text-2xl" />
      </button>

      {/* Modal */}
      {showModal && (
        <div
          className="fixed inset-0 flex justify-center items-center bg-gray-500 bg-opacity-50 z-50"
          onClick={() => setShowModal(false)}
        >
          <div
            className="bg-white p-8 rounded-lg shadow-xl w-96"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 className="text-xl mb-4 font-semibold text-center">Call Options</h2>

            {isConnecting ? (
              <div className="flex items-center justify-between gap-4">
                {/* Phone Icon */}
                <div className="bg-black p-3 rounded-full shadow-md">
                  <Phone className="text-white text-3xl" />
                </div>

                {/* Animated Loader */}
                <div className="loading">
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                </div>

                {/* Photo */}
                <img
                  src="https://cdn.vectorstock.com/i/500p/51/51/passport-photo-of-young-handsome-man-closeup-vector-20715151.jpg"
                  alt="User"
                  className="w-12 h-12 rounded-full shadow-md object-cover"
                />
              </div>
            ) : (
              <div>
                <p className="text-sm mb-4">Call number: 123-456-7890</p>
                <button
                  onClick={startCall}
                  className="w-full p-2 bg-blue-500 text-white rounded-full hover:bg-blue-600 transition-all duration-300"
                >
                  Start Call
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
          </div>
        )}

        <button
          onClick={toggleMenu}
          title="Dish Menu"
          className="group cursor-pointer outline-none hover:rotate-90 duration-300 p-4 bg-white border-2 border-red-600 rounded-full shadow-lg transform transition-transform hover:scale-110"
        >
          <Utensils className="text-red-600 group-hover:text-red-800 w-5 h-5" />
        </button>

        {chatOpen && (
          <div className="absolute bottom-20 right-0">
            <UserChat toggleChat={toggleChat} />
          </div>
        )}
      </div>
    </section>
    </div>
  );
}

export default Welcome;
/*Welcome*/