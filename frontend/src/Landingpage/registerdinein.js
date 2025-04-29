import React, { useState } from "react";
import { Eye, EyeOff } from "lucide-react";
import axios from "axios";
import { Link, useNavigate } from "react-router-dom";

const Login = () => {
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });

  const [errors, setErrors] = useState({});
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();

  const validateForm = () => {
    let newErrors = {};
    if (!formData.email.includes("@")) newErrors.email = "Enter a valid email.";
    if (formData.password.length < 6) newErrors.password = "Password must be at least 6 characters.";
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (validateForm()) {
      try {
        const response = await axios.post("http://localhost:5000/api/auth/login", {
          email: formData.email,
          password: formData.password,
        });

        const token = response.data.token;

        if (process.env.NODE_ENV === "development") {
          console.log("✅ JWT Token: {......}");
        }

        localStorage.setItem("authToken", token);

        const userRole = response.data.user.role;

        if (userRole === "admin") {
          navigate("/adminpage");
        } else if (userRole === "customer") {
          navigate("/userpage");
        } else if (userRole === "restaurant") {
          navigate("/restaurantpage");
        } else {
          setErrors({ api: "Invalid user role" });
        }
      } catch (error) {
        setErrors({ api: error.response?.data?.message || "Invalid credentials" });
      }
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-r from-orange-400 via-red-500 to-yellow-600 px-4 sm:px-6 lg:px-8">
      <h2 className="text-4xl font-bold text-center mb-6">
        <span className="text-red-600 font-serif">Let's</span>
        <span className="text-black font-serif"> Eat</span>
      </h2>

      <div className="w-full max-w-md bg-white shadow-lg rounded-2xl p-6 md:p-10">
        <h2 className="text-2xl font-serif text-center text-red-600 mb-6"> Login</h2>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-gray-700 font-serif">Email</label>
            <input
              type="email"
              className="w-full px-4 py-2 border rounded-xl focus:outline-none focus:ring-2 focus:ring-red-500 transition duration-300"
              placeholder="Enter your email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            />
            {errors.email && <p className="text-red-500 text-sm mt-1">{errors.email}</p>}
          </div>

          <div className="relative">
            <label className="block text-gray-700 font-serif">Password</label>
            <input
              type={showPassword ? "text" : "password"}
              className="w-full px-4 py-2 border rounded-xl focus:outline-none focus:ring-2 focus:ring-red-500 pr-10 transition duration-300"
              placeholder="Enter your password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            />
            <span
              className="absolute top-10 right-3 cursor-pointer"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? <EyeOff className="text-gray-500" /> : <Eye className="text-gray-500" />}
            </span>
            {errors.password && <p className="text-red-500 text-sm mt-1">{errors.password}</p>}
          </div>

          <div className="text-right">
            <Link
              to="/forgot-password"
              className="text-red-600 text-sm font-semibold hover:underline"
            >
              Forgot Password?
            </Link>
          </div>

          <button
            type="submit"
            className="w-full bg-red-600 text-white font-serif py-2 rounded-xl hover:bg-red-700 transition duration-300"
          >
            Login
          </button>

          {errors.api && <p className="text-red-500 text-center text-sm mt-2">{errors.api}</p>}
        </form>

        <p className="text-center text-gray-600 text-sm mt-4">
          Don't have an account?
          <Link to="/restaurant-signup" className="text-red-600 font-semibold hover:underline ml-1">
            Register here
          </Link>
        </p>
      </div>
    </div>
  );
};

export default Login;
