{/* Hero Section */}
<section id="welcome"
className="h-screen bg-cover bg-center flex flex-col justify-center items-center text-center"
style={{
    backgroundImage:
        "url('https://images.pexels.com/photos/11654235/pexels-photo-11654235.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=1')",
}}
>
<div className="p-10 rounded-lg">
    <h1 className="text-6xl text-white font-serif">
        Welcome to Let's Eat
    </h1>
    <button className="bg-red-500 hover:bg-red-600 text-white font-serif py-2 px-6 rounded-lg mt-4">
        Book a Table
    </button>
</div>
</section>
<section id="why-choose-us" className="py-16 bg-white">
<div className="max-w-6xl mx-auto px-6">
<div className="text-center">
    <h2 className="text-4xl font-serif font-bold text-red-600 mb-4">About Us</h2>
    <p className="text-lg text-gray-700 max-w-3xl mx-auto">
        Welcome to <span className="text-red-600 font-semibold">Let's Eat</span>, your one-stop destination for discovering the best restaurants and booking tables effortlessly. 
        We aim to provide a seamless dining experience, connecting food lovers with their favorite eateries.
    </p>
</div>

<div className="grid md:grid-cols-2 gap-10 mt-12 items-center">
    {/* Left Side - Image */}
    <div className="flex justify-center">
        <img 
            src="https://images.pexels.com/photos/262978/pexels-photo-262978.jpeg?auto=compress&cs=tinysrgb&w=600" 
            alt="Dining Experience" 
            className="rounded-lg shadow-lg w-full md:w-3/4"
        />
    </div>

    {/* Right Side - Text */}
    <div>
        <h3 className="text-2xl font-serif font-semibold text-gray-800">Our Mission</h3>
        <p className="text-gray-700 mt-4">
            At <span className="text-red-600 font-semibold">Let's Eat</span>, we believe in bringing people together over delicious food. 
            Whether you're looking for a romantic dinner, a family gathering, or a corporate lunch, we make restaurant booking effortless.
        </p>

        <h3 className="text-2xl font-serif font-semibold text-gray-800 mt-6">Why Choose Us?</h3>
        <ul className="mt-4 space-y-3">
            <li className="flex items-center">
                ✅ Wide selection of top-rated restaurants
            </li>
            <li className="flex items-center">
                ✅ Instant table reservations
            </li>
            <li className="flex items-center">
                ✅ Exclusive deals & discounts
            </li>
            <li className="flex items-center">
                ✅ Verified customer reviews
            </li>
        </ul>
    </div>
</div>
</div>
</section>



import { Routes, Route } from "react-router-dom";
import Home from "./bookingwebsite/home";
import Navbar from "./bookingwebsite/website";
import About from "./bookingwebsite/about";

function App() {
  return (
    <>
      <Navbar />
      <Routes>
        <Route path="/welcome" element={<Home />} />
        <Route path="/about" element={<About />} />
      </Routes>
    </>
  );
}

export default App;
