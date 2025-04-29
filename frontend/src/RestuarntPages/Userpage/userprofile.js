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
    phone: '+91 1234567890',
    address: '123 Main Street, Delhi, India',
    image: 'https://i.pravatar.cc/150?img=12',
  });

  const navigate = useNavigate();

  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [passwords, setPasswords] = useState({
    oldPassword: '',
    newPassword: '',
    confirmPassword: '',
  });

  const [selectedImage, setSelectedImage] = useState(null);
  const [zoomLevel, setZoomLevel] = useState(160);
  const [showImageModal, setShowImageModal] = useState(false);

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
    <div className="min-h-screen bg-[url('https://images.pexels.com/photos/27865066/pexels-photo-27865066/free-photo-of-divi-beach-aruba.png?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=1')] bg-cover bg-center p-4 sm:p-8 font-serif">
      {/* Home Icon */}
      <button
        onClick={() => {
          setShowImageModal(false);
          navigate('/userpage');
        }}
        className="fixed top-4 left-4 bg-white text-black p-2 rounded-full shadow-lg hover:bg-gray-100 z-50"
      >
        <Home size={24} />
      </button>

      <div className="max-w-4xl mx-auto bg-emerald-100 bg-opacity-10 text-white rounded-2xl shadow-2xl p-4 sm:p-8 space-y-6">
        {/* Profile Header */}
        <div className="flex flex-col sm:flex-row items-center gap-4">
          <img
            src={profile.image}
            alt="Profile"
            className="w-32 h-32 rounded-full border-4 border-white shadow-lg cursor-pointer"
            onClick={() => setShowImageModal(true)}
          />
          <div className="text-center sm:text-left">
            <h2 className="text-2xl sm:text-3xl font-bold text-red-500">User Profile</h2>
            <p className="text-gray-900">Email: {profile.email}</p>
            <p className="text-gray-900">Phone: {profile.phone}</p>
            <p className="text-gray-900">Address: {profile.address}</p>
          </div>
        </div>

        {/* Profile Form */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <input type="text" name="firstName" value={profile.firstName} onChange={handleProfileChange} className="p-3 rounded-md bg-white/10 border border-white/30 text-black" placeholder="First Name" />
          <input type="text" name="lastName" value={profile.lastName} onChange={handleProfileChange} className="p-3 rounded-md bg-white/10 border border-white/30 text-black" placeholder="Last Name" />
          <input type="text" name="surname" value={profile.surname} onChange={handleProfileChange} className="p-3 rounded-md bg-white/10 border border-white/30 text-black" placeholder="Surname" />
          <input type="number" name="age" value={profile.age} onChange={handleProfileChange} className="p-3 rounded-md bg-white/10 border border-white/30 text-black" placeholder="Age" />
          <input type="text" name="phone" value={profile.phone} onChange={handleProfileChange} className="p-3 rounded-md bg-white/10 border border-white/30 text-black" placeholder="Phone" />
          <input type="text" name="address" value={profile.address} onChange={handleProfileChange} className="p-3 rounded-md bg-white/10 border border-white/30 text-black" placeholder="Address" />
          <select name="gender" value={profile.gender} onChange={handleProfileChange} className="bg-white/10 p-3 rounded-md border border-white/30 text-black">
            <option value="Male" className="text-black">Male</option>
            <option value="Female" className="text-black">Female</option>
            <option value="Other" className="text-black">Other</option>
          </select>
        </div>

        <button onClick={handleUpdateProfile} className="bg-red-600 hover:bg-red-700 text-white font-semibold px-6 py-3 rounded-xl shadow-md">
          Update Profile
        </button>

        {/* Password Change */}
        <div className="pt-6 border-t border-white/20">
          <button onClick={() => setShowPasswordForm(!showPasswordForm)} className="text-green-400 underline font-semibold">
            {showPasswordForm ? 'Cancel Password Change' : 'Change Password'}
          </button>

          {showPasswordForm && (
            <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-4">
              <input type="password" name="oldPassword" value={passwords.oldPassword} onChange={handlePasswordChange} className="p-3 rounded-md bg-white/10 border border-white/30 text-white placeholder:text-gray-300" placeholder="Old Password" />
              <input type="password" name="newPassword" value={passwords.newPassword} onChange={handlePasswordChange} className="p-3 rounded-md bg-white/10 border border-white/30 text-white placeholder:text-gray-300" placeholder="New Password" />
              <input type="password" name="confirmPassword" value={passwords.confirmPassword} onChange={handlePasswordChange} className="p-3 rounded-md bg-white/10 border border-white/30 text-white placeholder:text-gray-300" placeholder="Confirm Password" />
              <button onClick={handleUpdatePassword} className="bg-green-600 hover:bg-green-700 text-white font-semibold px-6 py-3 rounded-xl shadow-md sm:col-span-3">
                Update Password
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Image Modal */}
      {showImageModal && (
        <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-lg p-6 w-[90%] max-w-lg text-center relative">
            <button onClick={() => { setShowImageModal(false); setSelectedImage(null); }} className="absolute top-2 right-2 text-black text-xl font-bold">
              ✕
            </button>

            <h3 className="text-2xl font-bold text-red-600 mb-4">Update Profile Image</h3>

            <div className="flex justify-center items-center">
              <img
                src={selectedImage ? URL.createObjectURL(selectedImage) : profile.image}
                alt="Preview"
                className="rounded-full border-4 border-black transition-transform duration-300"
                style={{ width: `${zoomLevel}px`, height: `${zoomLevel}px` }}
              />
            </div>

            <div className="flex items-center justify-center space-x-4 mt-4">
              <span className="text-black text-2xl bg-gray-200 px-3 py-1 rounded-full">–</span>
              <input type="range" min="100" max="300" value={zoomLevel} onChange={(e) => setZoomLevel(Number(e.target.value))} className="w-48" />
              <span className="text-black text-2xl bg-gray-200 px-3 py-1 rounded-full">+</span>
            </div>

            <input type="file" accept="image/*" onChange={(e) => setSelectedImage(e.target.files[0])} className="mt-4 w-full p-2 border rounded-md" />

            <button onClick={() => {
              if (!selectedImage) {
                alert('Please select an image');
                return;
              }
              setProfile((prev) => ({
                ...prev,
                image: URL.createObjectURL(selectedImage),
              }));
              setShowImageModal(false);
              setSelectedImage(null);
              setZoomLevel(160);
            }} className="mt-3 bg-green-600 hover:bg-green-700 text-white font-semibold px-6 py-2 rounded-lg">
              Update
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserProfile;
