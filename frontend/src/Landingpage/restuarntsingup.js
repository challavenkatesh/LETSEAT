import React, { useState } from "react";
import { Eye, EyeOff, CheckCircle } from "lucide-react";
import axios from "axios";
import * as Dialog from "@radix-ui/react-dialog";
import { Link } from "react-router-dom";

const SignUp = () => {
  const [formData, setFormData] = useState({
    fullName: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  const [errors, setErrors] = useState({});
  const [showPassword, setShowPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState("");
  const [isModalOpen, setIsModalOpen] = useState(false);

  const checkPasswordStrength = (password) => {
    let strength = "";
    if (password.length >= 10 && /[A-Z]/.test(password) && /\d/.test(password) && /[!@#$%^&*]/.test(password)) {
      strength = "Strong";
    } else if (password.length >= 8 && /[A-Z]/.test(password) && /\d/.test(password)) {
      strength = "Medium";
    } else if (password.length >= 6) {
      strength = "Weak";
    } else {
      strength = "Very Weak";
    }
    setPasswordStrength(strength);
  };

  const validateForm = () => {
    let newErrors = {};
    if (!formData.fullName.trim()) newErrors.fullName = "Full name is required.";
    if (!formData.email.includes("@")) newErrors.email = "Enter a valid email.";
    if (passwordStrength === "Very Weak" || passwordStrength === "Weak") newErrors.password = "Use a stronger password.";
    if (formData.password !== formData.confirmPassword) newErrors.confirmPassword = "Passwords do not match.";

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (validateForm()) {
      try {
        const role = formData.email === "admin@letseat.com" ? "admin" : "user";

        await axios.post("http://localhost:5000/api/auth/signup", {
          name: formData.fullName,
          email: formData.email,
          password: formData.password,
          role,
        });

        setFormData({ fullName: "", email: "", password: "", confirmPassword: "" });
        setPasswordStrength("");
        setErrors({});
        setIsModalOpen(true);
      } catch (error) {
        setErrors({ api: error.response?.data?.message || "Something went wrong" });
      }
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-r from-black via-red-900 to-black p-4">
      <div className="flex flex-col md:flex-row w-full max-w-5xl shadow-lg rounded-lg overflow-hidden bg-white">
        <div className="w-full md:w-1/2 flex flex-col items-center bg-red-600 text-white">
          <div className="w-full h-1/2">
            <img
              src="https://images.pexels.com/photos/1449773/pexels-photo-1449773.jpeg?auto=compress&cs=tinysrgb&w=600"
              alt="Join Us"
              className="w-full h-full object-cover"
            />
          </div>
          <div className="w-full flex flex-col justify-center p-8">
            <h2 className="text-3xl font-bold text-center">Join Our Platform</h2>
            <p className="mt-4 text-lg text-center">
              Register now to unlock exclusive features, manage your account easily, and explore our platform.
            </p>
            <ul className="mt-4 space-y-2">
              <li className="flex items-center gap-2">
                <CheckCircle className="text-white" />
                Access exclusive content
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="text-white" />
                Secure login system
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="text-white" />
                24/7 customer support
              </li>
            </ul>
          </div>
        </div>
        <div className="w-full md:w-1/2 flex items-center justify-center p-6">
          <div className="bg-white p-6 rounded-lg shadow-lg w-full max-w-md">
            <h2 className="text-2xl font-serif text-center text-red-600">Register</h2>
            <form onSubmit={handleSubmit} className="mt-4 space-y-4">
              <div>
                <label className="block text-black font-serif">Full Name</label>
                <input
                  type="text"
                  className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
                  placeholder="Enter your full name"
                  value={formData.fullName}
                  onChange={(e) => setFormData({ ...formData, fullName: e.target.value })}
                />
                {errors.fullName && <p className="text-red-500 text-sm mt-1">{errors.fullName}</p>}
              </div>
              <div>
                <label className="block text-black font-serif">Email</label>
                <input
                  type="email"
                  className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
                  placeholder="Enter your email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                />
                {errors.email && <p className="text-red-500 text-sm mt-1">{errors.email}</p>}
              </div>
              <div className="relative">
                <label className="block text-black font-serif">Password</label>
                <input
                  type={showPassword ? "text" : "password"}
                  className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 pr-10"
                  placeholder="Enter your password"
                  value={formData.password}
                  onChange={(e) => {
                    setFormData({ ...formData, password: e.target.value });
                    checkPasswordStrength(e.target.value);
                  }}
                />
                <span className="absolute top-10 right-3 cursor-pointer" onClick={() => setShowPassword(!showPassword)}>
                  {showPassword ? <EyeOff className="text-gray-500" /> : <Eye className="text-gray-500" />}
                </span>
                {errors.password && <p className="text-red-500 text-sm mt-1">{errors.password}</p>}
                {formData.password && (
                  <p
                    className={`mt-1 text-sm ${
                      passwordStrength === "Strong"
                        ? "text-green-500"
                        : passwordStrength === "Medium"
                        ? "text-yellow-500"
                        : "text-red-500"
                    }`}
                  >
                    Strength: {passwordStrength}
                  </p>
                )}
              </div>
              <div>
                <label className="block text-black font-serif">Confirm Password</label>
                <input
                  type="password"
                  className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
                  placeholder="Confirm your password"
                  value={formData.confirmPassword}
                  onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                />
                {errors.confirmPassword && <p className="text-red-500 text-sm mt-1">{errors.confirmPassword}</p>}
              </div>
              <button
                type="submit"
                className="w-full bg-red-600 font-serif text-white py-2 rounded-lg hover:bg-red-700 transition duration-300"
              >
                Register
              </button>
              <p className="text-center text-black font-serif text-sm mt-4">
                Already have an account?
                <Link to="/register-to-dine" className="text-red-600 font-serif hover:underline ml-1">
                  Login
                </Link>
              </p>
            </form>
          </div>
        </div>
      </div>
      <Dialog.Root open={isModalOpen} onOpenChange={setIsModalOpen}>
        <Dialog.Overlay className="fixed inset-0 bg-black bg-opacity-50" />
        <Dialog.Content className="fixed inset-0 flex items-center justify-center">
          <div className="bg-white p-6 rounded-lg shadow-lg text-center">
            <img
              src="https://cdn-icons-png.flaticon.com/512/845/845646.png"
              alt="Success"
              className="w-16 mx-auto mb-4"
            />
            <h2 className="text-lg font-semibold text-green-600">Signup Successful!</h2>
            <button
              className="mt-4 bg-red-600 text-white px-4 py-2 rounded"
              onClick={() => setIsModalOpen(false)}
            >
              Close
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Root>
    </div>
  );
};

export default SignUp;
