import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

const ChangePassword = () => {
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (newPassword !== confirmPassword) {
      setError("New password and confirm password do not match.");
      return;
    }

    try {
      const email = localStorage.getItem("email"); // Ensure email is stored during login/signup

      const res = await axios.post("http://localhost:5000/api/change-password", {
        oldPassword,
        newPassword,
        email,
      });

      if (res.data.success) {
        setSuccess(res.data.message);
        setError("");
        setTimeout(() => {
          navigate("/home");
        }, 2000);
      } else {
        setError(res.data.message);
      }
    } catch (err) {
      console.error(err);
      setError("Server error");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-r from-red-100 to-green-100">
      <div className="bg-white p-6 rounded-lg shadow-lg w-full max-w-md">
        <h2 className="text-2xl font-bold mb-4 text-center text-black">Change Password</h2>
        {error && <p className="text-red-500 mb-2">{error}</p>}
        {success && <p className="text-green-600 mb-2">{success}</p>}
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-black">Old Password</label>
            <input
              type="password"
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
              className="w-full p-2 border rounded text-black"
              required
            />
          </div>
          <div className="mb-4">
            <label className="block text-black">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full p-2 border rounded text-black"
              required
            />
          </div>
          <div className="mb-4">
            <label className="block text-black">Confirm New Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full p-2 border rounded text-black"
              required
            />
          </div>
          <button type="submit" className="bg-red-600 text-white py-2 px-4 rounded hover:bg-red-700 w-full">
            Change Password
          </button>
        </form>
      </div>
    </div>
  );
};

export default ChangePassword;
