import React, { useState } from 'react';
import { Home } from 'react-feather';
import { useNavigate } from 'react-router-dom';

const UserProfile = () => {
  const [profile, setProfile] = useState({
    firstName: 'Ravi',
    lastName: 'Sharma',
    surname: 'Raj',
    age: 32,
    gender: 'Male',
    email: 'ravi.sharma@letseat.com',
    ownerId: 'REST12345',
    image: 'https://i.pravatar.cc/150?img=12',
  });

  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [passwords, setPasswords] = useState({
    oldPassword: '',
    newPassword: '',
    confirmPassword: '',
  });

  const navigate = useNavigate();

  const handleProfileChange = (e) => {
    const { name, value } = e.target;
    setProfile((prev) => ({ ...prev, [name]: value }));
  };

  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    setPasswords((prev) => ({ ...prev, [name]: value }));
  };

  const handleUpdateProfile = () => {
    alert('Profile updated successfully!');
    console.log('Updated Profile:', profile);
  };

  const handleUpdatePassword = () => {
    if (passwords.newPassword !== passwords.confirmPassword) {
      alert('New passwords do not match!');
      return;
    }
    if (!passwords.oldPassword || !passwords.newPassword) {
      alert('Please fill in all password fields.');
      return;
    }

    alert('Password updated successfully!');
    console.log('Password Update:', passwords);
    setPasswords({ oldPassword: '', newPassword: '', confirmPassword: '' });
    setShowPasswordForm(false);
  };

  return (
    <div className="min-h-screen bg-[url('https://images.unsplash.com/photo-1582719478250-c89cae4dc85b')] bg-cover bg-center p-4 md:p-8 font-serif">
      <button
        onClick={() => navigate('/restaurantpage')}
        className="fixed top-4 left-4 bg-white text-black p-2 rounded-full shadow-lg hover:bg-gray-100 transition z-10"
      >
        <Home size={24} />
      </button>

      <div className="max-w-5xl mx-auto bg-black bg-opacity-70 text-white rounded-2xl shadow-2xl p-6 md:p-10 space-y-8">
        <div className="flex flex-col sm:flex-row items-center sm:items-start sm:space-x-6 space-y-4 sm:space-y-0">
          <img
            src={profile.image}
            alt="Profile"
            className="w-28 h-28 sm:w-32 sm:h-32 rounded-full border-4 border-white shadow-lg object-cover"
          />
          <div className="text-center sm:text-left">
            <h2 className="text-2xl sm:text-3xl font-bold text-red-500">Manager Profile</h2>
            <p className="text-gray-300 text-sm sm:text-base">Owner ID: {profile.ownerId}</p>
            <p className="text-gray-300 text-sm sm:text-base">Email: {profile.email}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <input
            type="text"
            name="firstName"
            value={profile.firstName}
            onChange={handleProfileChange}
            className="p-3 rounded-md bg-white/10 border border-white/30 text-white placeholder:text-gray-300"
            placeholder="First Name"
          />
          <input
            type="text"
            name="lastName"
            value={profile.lastName}
            onChange={handleProfileChange}
            className="p-3 rounded-md bg-white/10 border border-white/30 text-white placeholder:text-gray-300"
            placeholder="Last Name"
          />
          <input
            type="text"
            name="surname"
            value={profile.surname}
            onChange={handleProfileChange}
            className="p-3 rounded-md bg-white/10 border border-white/30 text-white placeholder:text-gray-300"
            placeholder="Surname"
          />
          <input
            type="number"
            name="age"
            value={profile.age}
            onChange={handleProfileChange}
            className="p-3 rounded-md bg-white/10 border border-white/30 text-white placeholder:text-gray-300"
            placeholder="Age"
          />
          <select
            name="gender"
            value={profile.gender}
            onChange={handleProfileChange}
            className="bg-white/10 p-3 rounded-md border border-white/30 text-white hover:bg-white/20 focus:bg-white/20 transition duration-200"
          >
            <option value="Male" className="text-black">Male</option>
            <option value="Female" className="text-black">Female</option>
            <option value="Other" className="text-black">Other</option>
          </select>
        </div>

        <button
          onClick={handleUpdateProfile}
          className="w-full sm:w-fit bg-red-600 hover:bg-red-700 text-white font-semibold px-6 py-3 rounded-xl shadow-md transition"
        >
          Update Profile
        </button>

        <div className="pt-6 border-t border-white/20">
          <button
            onClick={() => setShowPasswordForm(!showPasswordForm)}
            className="text-green-400 underline font-semibold"
          >
            {showPasswordForm ? 'Cancel Password Change' : 'Change Password'}
          </button>

          {showPasswordForm && (
            <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
              <input
                type="password"
                name="oldPassword"
                value={passwords.oldPassword}
                onChange={handlePasswordChange}
                className="p-3 rounded-md bg-white/10 border border-white/30 text-white placeholder:text-gray-300"
                placeholder="Old Password"
              />
              <input
                type="password"
                name="newPassword"
                value={passwords.newPassword}
                onChange={handlePasswordChange}
                className="p-3 rounded-md bg-white/10 border border-white/30 text-white placeholder:text-gray-300"
                placeholder="New Password"
              />
              <input
                type="password"
                name="confirmPassword"
                value={passwords.confirmPassword}
                onChange={handlePasswordChange}
                className="p-3 rounded-md bg-white/10 border border-white/30 text-white placeholder:text-gray-300"
                placeholder="Confirm Password"
              />
              <button
                onClick={handleUpdatePassword}
                className="bg-green-600 hover:bg-green-700 text-white font-semibold px-6 py-3 rounded-xl shadow-md md:col-span-3"
              >
                Update Password
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UserProfile;
