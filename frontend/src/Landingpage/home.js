import React from "react";
import { motion } from "framer-motion";
const Home = () => {
  return (
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
            type="submit"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
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
  );
};

export default Home;
