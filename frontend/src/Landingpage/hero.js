import React, { useState } from 'react';
import { Search,X,Users,Heart,Coffee} from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { FaStar } from 'react-icons/fa';

import logo from "./logo-1.png";

function Restaurant() {
    const allRestaurants = [
        { id: 1, name: "The Food Lounge", location: "New York", rating: 4.5, price: "$$", type: "Family", image: "https://images.pexels.com/photos/2612117/pexels-photo-2612117.jpeg?auto=compress&cs=tinysrgb&w=600",table:"2",totalTables:"10" },
        { id: 2, name: "Spice Heaven", location: "Los Angeles", rating: 4.2, price: "$$$", type: "Couple", image: "https://images.pexels.com/photos/31356130/pexels-photo-31356130/free-photo-of-luxurious-outdoor-lounge-area-with-elegant-decor.png?auto=compress&cs=tinysrgb&w=600" ,table:"2",totalTables:"10"},
        { id: 3, name: "Burger Spot", location: "Chicago", rating: 4.7, price: "$", type: "Family", image: "https://images.pexels.com/photos/18408870/pexels-photo-18408870/free-photo-of-tables-with-golden-lamps-next-to-a-green-velvet-sofa-in-a-nightclub.jpeg?auto=compress&cs=tinysrgb&w=600" ,table:"2",totalTables:"10"},
        { id: 4, name: "Sushi Delight", location: "New York", rating: 4.8, price: "$$$$", type: "Couple", image: "https://images.pexels.com/photos/3201921/pexels-photo-3201921.jpeg?auto=compress&cs=tinysrgb&w=600", table:"2",totalTables:"10"},
        { id: 5, name: "Pasta House", location: "Los Angeles", rating: 4.1, price: "$$", type: "Family", image: "https://media.cntraveler.com/photos/6662026d594fb5bb62bcd62d/4:3/w_1596,h_1197,c_limit/Disfrutar-7---@Joan-Valera.jpg", table:"2",totalTables:"11" },
        { id: 6, name: "Taco Fiesta", location: "Chicago", rating: 4.6, price: "$", type: "Family", image: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSlQN5IQ0I7N9We9PTKevXZNxp4dwMvZuubpA&s" , table:"2",totalTables:"10"},
        { id: 7, name: "Pizza Corner", location: "New York", rating: 4.3, price: "$$", type: "Couple", image: "https://images.pexels.com/photos/2079246/pexels-photo-2079246.jpeg?auto=compress&cs=tinysrgb&w=600", table:"2",totalTables:"10" },
        { id: 8, name: "Steak Grill", location: "Los Angeles", rating: 4.9, price: "$$$$", type: "Family", image: "https://api.barbequenation.com/sites/default/files/2025-01/Buf%20gallery%20857x491_3.jpg" , table:"2",totalTables:"10"},
        { id: 9, name: "Vegan Bites", location: "Chicago", rating: 4.5, price: "$$", type: "Couple", image: "https://images.yourstory.com/cs/210/3fb20ae02dc911e9af58c17e6cc3d915/800x400ViratKohlisOne8CommunewithitsglasshousedesignmakesforaverdantescapeinbusyJuhuMumbaiyslifecopy-1669283436495.png?mode=crop&crop=faces&ar=2%3A1&format=auto&w=1920&q=75", table:"2",totalTables:"10" },
        { id: 10, name: "Seafood Paradise", location: "New York", rating: 4.7, price: "$$$", type: "Family", image: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQwfQzo8ghEeXRxdtCrht2TjwZpazk4GaUZJg&s", table:"2",totalTables:"10" },
        { id: 11, name: "BBQ Nation", location: "Los Angeles", rating: 4.4, price: "$$$", type: "Family", image: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxUCrIfzlt6dnjOf7KWdHd6mbIxvAjRnahgg&s", table:"2",totalTables:"10" },
        { id: 12, name: "Healthy Greens", location: "Chicago", rating: 4.2, price: "$$", type: "Couple", image: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQg8VSe___e4sI20umnjSmNg5b-MFsJMhvv7A&s", table:"2",totalTables:"10" },
        { id: 13, name: "Noodle Hub", location: "New York", rating: 4.6, price: "$$", type: "Family", image: "https://images.pexels.com/photos/5836634/pexels-photo-5836634.jpeg?auto=compress&cs=tinysrgb&w=600" , table:"2",totalTables:"10"},
        { id: 14, name: "Deli Delight", location: "Los Angeles", rating: 4.1, price: "$$", type: "Couple", image: "", table:"2",totalTables:"10" },
        { id: 15, name: "Café Bliss", location: "Chicago", rating: 4.3, price: "$$", type: "Family", image: "https://sumesshmenonassociates.com/wp-content/uploads/2020/10/masala-bar-1.jpg" , table:"2",totalTables:"10"},
        { id: 16, name: "Bistro Charm", location: "New York", rating: 4.5, price: "$$", type: "Couple", image: "https://images.pexels.com/photos/15340956/pexels-photo-15340956/free-photo-of-elegant-furniture-in-cafe.jpeg?auto=compress&cs=tinysrgb&w=600", table:"2",totalTables:"10" },
        { id: 17, name: "Fine Dine", location: "Los Angeles", rating: 4.8, price: "$$$$", type: "Family", image: "https://images.pexels.com/photos/8257971/pexels-photo-8257971.jpeg?auto=compress&cs=tinysrgb&w=600" , table:"2",totalTables:"10"},
        { id: 18, name: "Rooftop Bites", location: "Chicago", rating: 4.7, price: "$$$", type: "Couple", image: "https://static.vecteezy.com/system/resources/thumbnails/030/655/121/small_2x/vegetarian-fast-food-restaurant-with-colorful-free-photo.jpg", table:"2",totalTables:"10" }
    ];
    
    const navigate = useNavigate();
    const [showFilter, setShowFilter] = useState(false);
    const [locationFilter, setLocationFilter] = useState("");
    const [filteredRestaurants, setFilteredRestaurants] = useState(allRestaurants);
    const [currentPage, setCurrentPage] = useState(1);

    const restaurantsPerPage = 9;
    const totalPages = Math.ceil(filteredRestaurants.length / restaurantsPerPage);

    const indexOfLastRestaurant = currentPage * restaurantsPerPage;
    const indexOfFirstRestaurant = indexOfLastRestaurant - restaurantsPerPage;
    const currentRestaurants = filteredRestaurants.slice(indexOfFirstRestaurant, indexOfLastRestaurant);

    const applyFilters = () => {
        let filtered = allRestaurants;
        if (locationFilter) {
            filtered = filtered.filter(r => r.location === locationFilter);
        }
        setFilteredRestaurants(filtered);
        setCurrentPage(1);
    };
    const [showLocationOptions, setShowLocationOptions] = useState(false);
    const [selectedLocation, setSelectedLocation] = useState('');


    const toggleLocationDropdown = () => {
        setShowLocationOptions(prevState => !prevState);
    };

    const handleLocationSelect = (location) => {
        setSelectedLocation(location);
        setShowLocationOptions(false);
    };
;

    return (
        <div className="relative">
            {/* Top Navbar */}
            <nav className="bg-black text-white p-2 flex justify-center items-center">
                <ul className="flex space-x-6">
                    <li><Link to="/userpage" className="hover:text-red-600">Home</Link></li>
                    <li><a href="/restaurants" className="hover:text-red-600">Book Table</a></li>
                    <li><a href="#blog" className="hover:text-red-600">Blog</a></li>
                </ul>
            </nav>

            {/* Main Navbar */}
            <nav className="bg-white text-black h-20 p-4 flex justify-between items-center">
                <div className="text-white text-2xl font-bold">
                    <img src={logo} alt="Restaurant Logo" className="w-24" />
                </div>

                {/* Centered Search Bar Section */}
                <div className="flex flex-1 justify-center items-center space-x-4">
                    <div className="relative lg:block hidden">
                        <button
                            onClick={toggleLocationDropdown}
                            className="p-2 bg-red-600 text-white rounded-md hover:bg-red-700"
                        >
                            {selectedLocation ? selectedLocation : 'Location'}
                        </button>
                        {showLocationOptions && (
                            <div className="absolute top-10 left-0 w-40 bg-white text-black border shadow-md">
                                <ul>
                                    {["New York", "Los Angeles", "Chicago"].map((city) => (
                                        <li key={city}
                                            className="p-2 hover:bg-gray-200 cursor-pointer"
                                            onClick={() => handleLocationSelect(city)}
                                        >
                                            {city}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        )}
                    </div>

                    <input
                        type="text"
                        placeholder="Search for dishes..."
                        className="p-2 bg-gray-200 text-black rounded-md w-64 focus:outline-none lg:block hidden"
                    />
                    
                    <button className="bg-red-600 text-white p-2 rounded-md hover:bg-red-700 lg:block hidden">
                        <Search size={20} />
                    </button>
                </div>

                {/* Filter Button */}
                <button 
                    className="bg-red-600 text-white p-2 rounded-md hover:bg-red-700"
                    onClick={() => setShowFilter(true)}
                >
                    Filter
                </button>
            </nav>

       
            {/* Restaurant List */}
            <div className="p-6 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
                {currentRestaurants.map(restaurant => (
                    <div 
                        key={restaurant.id} 
                        className="bg-white p-4 shadow-md rounded-md cursor-pointer hover:shadow-lg transition"
                        onClick={() => navigate(`/restaurant/${restaurant.id}`)}
                    >
                        <img src={restaurant.image} alt={restaurant.name} className="w-full h-40 object-cover rounded-md" />
                        <h3 className="text-lg font-semibold mt-2">{restaurant.name}</h3>
                        <p className="text-black">{restaurant.location}</p>
                        <p className="text-green-500">{restaurant.price}</p>
                        <p className="text-yellow-500 flex items-center">
  <FaStar className="mr-1 text-yellow-500" />
  {restaurant.rating}
</p>
                        {console.log('Total Tables:', restaurant.totalTables, 'Tables booked:', restaurant.table)}
<p>Available Tables: {parseInt(restaurant.totalTables) - parseInt(restaurant.table)}</p>

<p className="text-gray-600 flex items-center">
  {restaurant.type === "Family" && <Users className="mr-2 text-red-600" />} {/* Family Icon */}
  {restaurant.type === "Couple" && <Heart className="mr-2 text-red-600" />} {/* Couple Icon */}
  {restaurant.type === "Cafe" && <Coffee className="mr-2 text-red-600" />} {/* Cafe Icon */}
  {restaurant.type}
</p>                    
                    </div>
                ))}
            </div>

            {/* Pagination */}
            <div className="flex justify-center mt-6">
                {Array.from({ length: totalPages }).map((_, index) => (
                    <button 
                        key={index} 
                        className={`mx-1 px-3 py-2 rounded ${currentPage === index + 1 ? "bg-red-600 text-white" : "bg-gray-200"}`}
                        onClick={() => setCurrentPage(index + 1)}
                    >
                        {index + 1}
                    </button>
                ))}
            </div>

           {/* Filter Button */}

{/* Filter Sidebar */}
{showFilter && (
    <div className="fixed top-0 right-0 w-64 h-full bg-white shadow-lg p-4">
        <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-bold">Filters</h2>
            <button onClick={() => setShowFilter(false)} className="text-gray-500 hover:text-red-600">
                <X size={24} />
            </button>
        </div>
        <select 
            onChange={(e) => setLocationFilter(e.target.value)} 
            className="w-full p-2 border rounded"
        >
            <option value="">All Locations</option>
            <option value="New York">New York</option>
            <option value="Los Angeles">Los Angeles</option>
            <option value="Chicago">Chicago</option>
        </select>
        <button className="bg-red-600 text-white p-2 mt-4 rounded w-full" onClick={applyFilters}>
            Apply
        </button>
    </div>
)}

        
        </div>
    );
}

export default Restaurant;
