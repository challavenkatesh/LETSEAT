import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { Flame, Menu, X ,Phone, MessageSquare, PlusCircle} from "lucide-react";
import { motion } from "framer-motion";
import { FaFacebookF, FaInstagram, FaTwitter, FaLinkedinIn,FaMapMarkerAlt ,FaStar, FaMoneyBillWave } from "react-icons/fa";
import { GiFullPizza, GiHamburger, GiNoodles } from "react-icons/gi"; 
import { useNavigate } from "react-router-dom";
import logo from "./logo-1.png"; // Ensure this path is correct

function Navbar() {
    const navigate = useNavigate();
    const [isOpen, setIsOpen] = useState(false);
    const [openDropdown, setOpenDropdown] = useState(null);
    const [mobileDropdown, setMobileDropdown] = useState(null);
    const [menuOpen, setMenuOpen] = useState(false);
    const [showPopover, setShowPopover] = useState(false);
    useEffect(() => {
        const handleClickOutside = (event) => {
          if (showPopover && !event.target.closest(".popover-content")) {
            setShowPopover(false);
          }
        };
    
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
      }, [showPopover]);

    // Toggle function to show or hide chat and phone icons
    const toggleMenu = () => setMenuOpen(!menuOpen);
   
    // Fix for 'selectedCuisine' error

    const restaurantsRef = useRef(null);
    const menuRef = useRef(null);

    useEffect(() => {
        function handleClickOutside(event) {
            if (
                (restaurantsRef.current && !restaurantsRef.current.contains(event.target)) &&
                (menuRef.current && !menuRef.current.contains(event.target))
            ) {
                setOpenDropdown(null);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, []);

    // Sample restaurant data
    const restaurants = [
        { id: 1, name: "Spicy Delight", cuisine: "Indian Cuisine", rating: "4.8", location: "New Delhi, India", priceRange: "₹₹ - Moderate", image: "https://images.pexels.com/photos/7161739/pexels-photo-7161739.jpeg?auto=compress&cs=tinysrgb&w=600" },
        { id: 2, name: "Sushi Haven", cuisine: "Japanese Cuisine", rating: "4.7", location: "Tokyo, Japan", priceRange: "¥¥¥ - Expensive", image: "https://images.pexels.com/photos/248444/pexels-photo-248444.jpeg?auto=compress&cs=tinysrgb&w=600" },
        { id: 3, name: "Pasta Paradise", cuisine: "Italian Cuisine", rating: "4.6", location: "Rome, Italy", priceRange: "€€ - Moderate", image: "https://images.pexels.com/photos/691114/pexels-photo-691114.jpeg?auto=compress&cs=tinysrgb&w=600" },
        { id: 4, name: "Burger Bliss", cuisine: "American Cuisine", rating: "4.5", location: "New York, USA", priceRange: "$$ - Moderate", image: "https://images.pexels.com/photos/1199960/pexels-photo-1199960.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=1" },
        { id: 5, name: "Taco Fiesta", cuisine: "Mexican Cuisine", rating: "4.7", location: "Mexico City, Mexico", priceRange: "$ - Affordable", image: "https://images.pexels.com/photos/8920125/pexels-photo-8920125.jpeg?auto=compress&cs=tinysrgb&w=600" },
        { id: 6, name: "Vegan Bites", cuisine: "Vegan Cuisine", rating: "4.9", location: "Los Angeles, USA", priceRange: "$$ - Moderate", image: "https://images.pexels.com/photos/3026811/pexels-photo-3026811.jpeg?auto=compress&cs=tinysrgb&w=600" }
    ];

 
  

    return (
        <div>
        <nav className="fixed w-full z-50 bg-white">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex justify-between items-center h-16">
                    {/* Logo */}
                    <div className="flex items-center space-x-2">
                        <img src={logo} alt="Logo" className="h-20 w-auto rounded-md" />
                    </div>

                    {/* Desktop Menu */}
                    <div className="hidden md:flex space-x-6">
                        <Link to="/welcome" className="relative font-serif text-black hover:text-red-500 group">
                            Welcome
                            <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-red-500 transition-all duration-300 group-hover:w-full"></span>
                        </Link>

                        {/* Restaurants Dropdown */}
                        <div className="relative group" ref={restaurantsRef}>
                            <button
                                onClick={() => setOpenDropdown(prev => prev === "restaurants" ? null : "restaurants")}
                                className="relative font-serif text-black hover:text-red-500 group"
                                aria-expanded={openDropdown === "restaurants"}
                            >
                                Restaurants
                                <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-red-500 transition-all duration-300 group-hover:w-full"></span>
                            </button>
                            {openDropdown === "restaurants" && (
                                <div className="absolute left-0 mt-2 w-48 bg-white shadow-lg">
                                    <Link to="/restaurants/italian" className="block px-4 py-2 hover:bg-red-200">Italian</Link>
                                    <Link to="/restaurants/chinese" className="block px-4 py-2 hover:bg-red-200">Chinese</Link>
                                    <Link to="/restaurants/indian" className="block px-4 py-2 hover:bg-red-200">Indian</Link>
                                </div>
                            )}
                        </div>

                        {/* Menu Dropdown */}
                        <div className="relative group" ref={menuRef}>
                            <button
                                onClick={() => setOpenDropdown(prev => prev === "menu" ? null : "menu")}
                                className="relative font-serif text-black hover:text-red-500 group"
                                aria-expanded={openDropdown === "menu"}
                            >
                                Menu
                                <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-red-500 transition-all duration-300 group-hover:w-full"></span>
                            </button>
                            {openDropdown === "menu" && (
                                <div className="absolute left-0 mt-2 w-48 bg-white shadow-lg">
                                    <Link to="/menu/starters" className="block px-4 py-2 hover:bg-red-200">Starters</Link>
                                    <Link to="/menu/main-course" className="block px-4 py-2 hover:bg-red-200">Main Course</Link>
                                    <Link to="/menu/desserts" className="block px-4 py-2 hover:bg-red-200">Desserts</Link>
                                </div>
                            )}
                        </div>

                        <Link to="/events" className="relative font-serif text-black hover:text-red-500 group">
                            Events
                            <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-red-500 transition-all duration-300 group-hover:w-full"></span>
                        </Link>
                        <Link to="/takeaway" className="relative font-serif text-black hover:text-red-500 group">
                            Takeaway
                            <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-red-500 transition-all duration-300 group-hover:w-full"></span>
                        </Link>
                        <div className="relative">
      {/* Main Link */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative font-serif text-black hover:text-red-500 group"
      >
        Register to Dine
        <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-red-500 transition-all duration-300 group-hover:w-full"></span>
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="absolute left-0 mt-2 w-40 bg-white shadow-lg border rounded-lg">
          <Link
            to="/book-event"
            className="block px-4 py-2 text-gray-700 hover:bg-red-500 hover:text-white"
          >
            Book Event
          </Link>
          <Link
            to="/book-table"
            className="block px-4 py-2 text-gray-700 hover:bg-red-500 hover:text-white"
          >
            Book Table
          </Link>
        </div>
      )}
    </div>

                    </div>
                    <div className="relative">
                    <div className="block">
        <button
          onClick={() => setShowPopover(!showPopover)}
          className="flex items-center space-x-2 bg-red-500 text-white px-4 py-2 rounded-lg hover:bg-red-600 transition duration-300 shadow-md"
        >
          <Flame size={20} />
          <span className="text-sm md:text-base">Deals</span>
        </button>
      </div>

      {/* Popover */}
      {showPopover && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 px-4">
          <div className="bg-white shadow-lg p-6 rounded-xl w-full max-w-md text-center relative">
            <h3 className="font-semibold text-lg text-red-600">🔥 Hot Deals Today!</h3>
            <ul className="mt-4 text-sm text-gray-700 space-y-3 text-left">
              <li className="flex items-center gap-3">
                <GiFullPizza className="text-red-500 text-2xl" />
                <span>50% off on all Pizzas</span>
              </li>
              <li className="flex items-center gap-3">
                <GiHamburger className="text-yellow-500 text-2xl" />
                <span>Buy 1 Get 1 Free on Burgers</span>
              </li>
              <li className="flex items-center gap-3">
                <GiNoodles className="text-orange-500 text-2xl" />
                <span>Free Dessert with Pasta</span>
              </li>
            </ul>
            <button
              onClick={() => setShowPopover(false)}
              className="mt-6 px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition duration-300"
            >
              Close
            </button>
          </div>
        </div>
      )}
</div>


                    {/* Mobile Menu Button */}
                    <div className="md:hidden">
                        <button onClick={() => setIsOpen(!isOpen)} className="text-black">
                            {isOpen ? <X size={24} /> : <Menu size={24} />}
                        </button>
                    </div>
                </div>
            </div>

            {/* Mobile Menu */}
            {isOpen && (
                <div className="absolute top-full left-0 w-full bg-white shadow-md z-50 md:hidden">
                    <Link to="/welcome" className="block px-4 py-2 text-black hover:bg-red-600">Welcome</Link>

                    {/* Restaurants Mobile Dropdown */}
                    <div className="px-4 py-2">
                        <button
                            onClick={() => setMobileDropdown(prev => prev === "restaurants" ? null : "restaurants")}
                            className="w-full text-left text-black hover:bg-red-600 py-2"
                        >
                            Restaurants
                        </button>
                        {mobileDropdown === "restaurants" && (
                            <div className="pl-4">
                                <Link to="/restaurants/italian" className="block px-4 py-2 text-black hover:bg-red-200">Italian</Link>
                                <Link to="/restaurants/chinese" className="block px-4 py-2 text-black hover:bg-red-200">Chinese</Link>
                                <Link to="/restaurants/indian" className="block px-4 py-2 text-black hover:bg-red-200">Indian</Link>
                            </div>
                        )}
                    </div>

                    <Link to="/menu" className="block px-4 py-2 text-black hover:bg-red-600">Menu</Link>
                    <Link to="/events" className="block px-4 py-2 text-black hover:bg-red-600">Events</Link>
                    <Link to="/takeaway" className="block px-4 py-2 text-black hover:bg-red-600">Takeaway</Link>
                    <Link to="/register-to-dine" className="block px-4 py-2 text-black hover:bg-red-600">Register to Dine</Link>

                </div>
            )}
        </nav>
        <div
      className="flex items-center justify-center min-h-screen text-white bg-cover bg-center bg-no-repeat relative"
      style={{ backgroundImage: `url("https://images.pexels.com/photos/460537/pexels-photo-460537.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=1")` }} // Ensure image is inside public folder
    >
      {/* Background Overlay for Better Readability */}
      <div className="absolute inset-0 bg-black/40"></div>

      <section className="relative text-center px-6 md:px-16">
        {/* Motion Animated Heading */}
        <motion.h1
          className="text-5xl md:text-6xl font-extrabold leading-tight"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <span className="text-red-600">Savor Every</span>
          <span className="text-black"> Bite,</span> <br />
          <span className="text-red-600">Delivered</span>
          <span className="text-black"> Right!</span>
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          className="text-lg mt-4 md:w-3/4 mx-auto"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.5 }}
        >
          Enjoy the finest flavors from top restaurants, served fresh at your doorstep.
        </motion.p>

        {/* Call-to-Action Button */}
        <div className="mt-6 flex justify-center">
      <motion.button
        className="relative z-10 flex items-center justify-center gap-2 px-6 py-3 text-lg font-semibold text-black transition-all border-2 border-gray-50 rounded-full shadow-xl bg-white overflow-hidden group hover:scale-105 hover:shadow-2xl"
        type="button"
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        onClick={() => navigate("/register-to-dine")} // Navigate on click
      >
        Grab Your Bite
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 16 19"
          className="w-8 h-8 p-2 transition-transform duration-300 ease-linear rotate-45 bg-gray-50 border border-gray-700 rounded-full group-hover:rotate-90"
        >
          <path
            className="fill-gray-800"
            d="M7 18C7 18.5523 7.44772 19 8 19C8.55228 19 9 18.5523 9 18H7ZM8.70711 0.292893C8.31658 -0.0976311 7.68342 -0.0976311 7.29289 0.292893L0.928932 6.65685C0.538408 7.04738 0.538408 7.68054 0.928932 8.07107C1.31946 8.46159 1.95262 8.46159 2.34315 8.07107L8 2.41421L13.6569 8.07107C14.0474 8.46159 14.6805 8.46159 15.0711 8.07107C15.4616 7.68054 15.4616 7.04738 15.0711 6.65685L8.70711 0.292893ZM9 18L9 1H7L7 18H9Z"
          ></path>
        </svg>

        <span className="absolute inset-0 w-full transition-all duration-700 bg-red-600 rounded-full -left-full group-hover:left-0 group-hover:scale-200 -z-10"></span>
      </motion.button>
    </div>
      </section>
    </div>
    <section className="bg-white py-12 px-6 text-black">
      <h2 className="text-3xl font-bold text-center mb-8 text-red-500">
        Explore Top Restaurants
      </h2>

      <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
        {restaurants.map((restaurant) => (
          <motion.div
            key={restaurant.id}
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            whileHover={{ scale: 1.05 }}
            className="bg-gray-100 rounded-2xl overflow-hidden shadow-lg"
          >
            <img
              src={restaurant.image}
              alt={restaurant.name}
              className="w-full h-48 object-cover transition-transform duration-300 hover:scale-110"
            />
            <div className="p-5">
              <h3 className="text-xl font-bold text-black">{restaurant.name}</h3>
              <p className="text-red-400">{restaurant.cuisine}</p>
              <p className="text-yellow-500 font-semibold flex items-center gap-1">
                <FaStar /> {restaurant.rating}
              </p>
              <p className="text-gray-600 flex items-center gap-1">
                <FaMapMarkerAlt /> {restaurant.location}
              </p>
              <p className="text-green-600 font-medium flex items-center gap-1">
                <FaMoneyBillWave /> {restaurant.priceRange}
              </p>
              <motion.button
                whileTap={{ scale: 0.9 }}
                className="mt-4 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg w-full transition"
                onClick={() => navigate("/register-to-dine")}
              >
                Book Now
              </motion.button>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="text-center mt-8">
        <motion.button
          whileTap={{ scale: 0.9 }}
          className="bg-red-600 hover:bg-red-700 text-white px-6 py-3 rounded-lg text-lg font-bold transition"
          onClick={() => navigate("/register-to-dine")}
        >
          View More
        </motion.button>
      </div>
    </section>
    <section className="w-full bg-gray-100 py-12">
      <div className="max-w-6xl mx-auto px-4">
        <h2 className="text-4xl font-bold text-center mb-8 text-red-600">
          Upcoming Events
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Event 1 */}
          <div className="bg-white shadow-lg rounded-lg overflow-hidden">
            <img
              src="https://images.pexels.com/photos/1763075/pexels-photo-1763075.jpeg?auto=compress&cs=tinysrgb&w=600"
              alt="Jazz Night"
              className="w-full h-56 object-cover"
            />
            <div className="p-6">
              <h3 className="text-2xl font-semibold text-gray-800">
                Live Jazz Night
              </h3>
              <p className="text-gray-600 mt-2">March 25, 2025</p>
              <p className="text-gray-700 mt-4">
                Enjoy live jazz music with a special dinner menu!
              </p>
              <button className="mt-4 w-full bg-red-600 text-white py-2 rounded-lg hover:bg-red-700 transition "  onClick={() => navigate("/register-to-dine")}>
                Book Event
              </button>
            </div>
          </div>

          {/* Event 2 */}
          <div className="bg-white shadow-lg rounded-lg overflow-hidden" >
            <img
              src="https://images.pexels.com/photos/6287555/pexels-photo-6287555.jpeg?auto=compress&cs=tinysrgb&w=600"
              alt="Italian Festival"
              className="w-full h-56 object-cover"
            />
            <div className="p-6">
              <h3 className="text-2xl font-semibold text-gray-800">
                Italian Food Festival
              </h3>
              <p className="text-gray-600 mt-2">April 5, 2025</p>
              <p className="text-gray-700 mt-4">
                Taste authentic Italian dishes with a 20% discount!
              </p>
              <button className="mt-4 w-full bg-red-600 text-white py-2 rounded-lg hover:bg-red-700 transition" onClick={() => navigate("/register-to-dine")}>
                Book Event
              </button>
            </div>
          </div>

          {/* Event 3 */}
          <div className="bg-white shadow-lg rounded-lg overflow-hidden" >
            <img
              src="https://images.pexels.com/photos/7930114/pexels-photo-7930114.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=1"
              alt="Wine Tasting"
              className="w-full h-56 object-cover"
            />
            <div className="p-6">
              <h3 className="text-2xl font-semibold text-gray-800">
                Wine Tasting Evening
              </h3>
              <p className="text-gray-600 mt-2">April 15, 2025</p>
              <p className="text-gray-700 mt-4">
                Explore the best wines with our sommelier.
              </p>
              <button className="mt-4 w-full bg-red-600 text-white py-2 rounded-lg hover:bg-red-700 transition"  onClick={() => navigate("/register-to-dine")}>
                Book Event
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
    <section id="why-choose-us" className="py-16 bg-white">
      <div className="max-w-6xl mx-auto px-6">
        {/* Section Title */}
        <div className="text-center">
          <h2 className="text-4xl font-serif font-bold text-red-600 mb-4">About Us</h2>
          <p className="text-lg text-gray-700 max-w-3xl mx-auto">
            Welcome to <span className="text-red-600 font-semibold">Let's Eat</span>, your go-to platform for discovering the best restaurants and booking tables effortlessly. 
            We aim to provide a seamless dining experience, connecting food lovers with their favorite eateries.
          </p>
        </div>

        {/* Content Section */}
        <div className="grid md:grid-cols-2 gap-12 mt-12 items-center">
          {/* Left Side - Image */}
          <div className="flex justify-center">
            <img
              src="https://images.pexels.com/photos/262978/pexels-photo-262978.jpeg?auto=compress&cs=tinysrgb&w=600"
              alt="Dining Experience"
              className="rounded-lg shadow-lg w-full md:w-3/4"
            />
          </div>

          {/* Right Side - Content */}
          <div>
            <h3 className="text-2xl font-serif font-semibold text-gray-800">Our Mission</h3>
            <p className="text-gray-700 mt-4">
              At <span className="text-red-600 font-semibold">Let's Eat</span>, we believe in bringing people together over delicious food. 
              Whether you're planning a romantic dinner, a family gathering, or a corporate lunch, we make restaurant booking effortless.
            </p>

            {/* Why Choose Us List */}
            <h3 className="text-2xl font-serif font-semibold text-gray-800 mt-6">Why Choose Us?</h3>
            <ul className="mt-4 space-y-3">
              {[
                "Wide selection of top-rated restaurants",
                "Instant table reservations",
                "Exclusive deals & discounts",
                "Verified customer reviews",
              ].map((item, index) => (
                <li key={index} className="flex items-center">
                  <span className="text-red-600 text-lg mr-2">✅</span>
                  <span className="text-gray-700">{item}</span>
                </li>
              ))}
            </ul>
          </div>
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
        {/* Show Chat and Phone buttons when menu is open (VERTICAL STACK) */}
        {menuOpen && (
          <div className="flex flex-col items-center space-y-4 mb-4">
            {/* Chat Button */}
            <button
              title="Chat"
              onClick={() => alert("Please Login")}
              className="group cursor-pointer p-4 bg-red-600 rounded-full shadow-lg transform transition-all hover:scale-110 duration-300"
            >
              <MessageSquare className="text-white group-hover:text-gray-200 text-2xl" />
            </button>

            {/* Phone Button */}
            <button
              title="Phone"
              onClick={() => alert("Please Login")}
              className="group cursor-pointer p-4 bg-black rounded-full shadow-lg transform transition-all hover:scale-110 duration-300"
            >
              <Phone className="text-white group-hover:text-gray-300 text-2xl" />
            </button>
          </div>
        )}

        {/* Add Button with PlusCircle icon */}
        <button
          onClick={toggleMenu}
          title="Add New"
          className="group cursor-pointer outline-none hover:rotate-90 duration-300 p-4 bg-white border-2 border-red-600 rounded-full shadow-lg transform transition-transform hover:scale-110"
        >
          <PlusCircle className="text-red-600 group-hover:text-red-800 w-4 h-4" />
        </button>
      </div>
    </section>
     
        </div>
    );
};

export default Navbar;
