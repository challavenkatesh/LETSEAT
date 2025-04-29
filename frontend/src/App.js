import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import Navbar from "./Landingpage/website"; 
import RegisterToDine from "./Landingpage/registerdinein"; 
import RestaurantSignup from "./Landingpage/restuarntsingup";
import UserPage from "./RestuarntPages/Userpage/welcome";
import Restaurant from "./RestuarntPages/Userpage/Restuarnt";
import AdminPage from "./RestuarntPages/Restuarntadmin/welcome";
import WelcomePage from "./RestuarntPages/Restuarntpage/Welcome";
import RestaurantPage from "./RestuarntPages/Restuarntpage/addRestuarnt";
import RestaurantDetails from "./RestuarntPages/Userpage/RestaurantDetails";
import BookingForm from "./RestuarntPages/Userpage/bookingform";
import BookindDetails from "./RestuarntPages/Restuarntpage/bookingdetails";
import RestaurantPayment from "./RestuarntPages/Restuarntpage/restuarntpayment"; 
import BookingsPanel from "./RestuarntPages/Userpage/bookingspanel";
import Events from "./RestuarntPages/Restuarntpage/events";
import EventsList from "./RestuarntPages/Userpage/EventLists";
import EventDetails from "./RestuarntPages/Userpage/eventdetails";
import EventForm from "./RestuarntPages/Userpage/eventform";
import EventPayment from "./RestuarntPages/Userpage/eventpayment";
import OrderNow from "./RestuarntPages/Userpage/order";
import RestuarantOrder from "./RestuarntPages/Restuarntpage/restuarntorder";
import RestaurantMenu from "./RestuarntPages/Userpage/restaurantMenus";
import MenuForm from "./RestuarntPages/Userpage/MenuForm";
import ChangePassword from "./RestuarntPages/Userpage/changepassword";
import RestuanrtManger from "./RestuarntPages/Restuarntadmin/restuarnt_manger"
import UserDetailPage from "./RestuarntPages/Restuarntadmin/Userdetails";
import Profile from "./RestuarntPages/Restuarntpage/profile";
import Userprofile from "./RestuarntPages/Userpage/userprofile";
// Chat Components
import UserChat from './RestuarntPages/Userpage/UserChat';  // Assuming you create this
import ManagerChat from './RestuarntPages/Restuarntpage/Managerchat'; // Assuming you create this
import "./App.css"; // Import your CSS file here
function App() {
  return (
    <>
      <Routes>
        <Route path="/" element={<Navbar />} />
        <Route path="/welcome" element={<Navbar />} />
        <Route path="/register-to-dine" element={<RegisterToDine />} />
        <Route path="/restaurant-signup" element={<RestaurantSignup />} />
        <Route path="/restaurants/italian" element={<Navigate to="/register-to-dine" />} />
        <Route path="/restaurants/chinese" element={<Navigate to="/register-to-dine" />} />
        <Route path="/restaurants/indian" element={<Navigate to="/register-to-dine" />} />
        <Route path="/menu/starters" element={<Navigate to="/register-to-dine" />} />
        <Route path="/menu/main-course" element={<Navigate to="/register-to-dine" />} />
        <Route path="/menu/desserts" element={<Navigate to="/register-to-dine" />} />
        <Route path="/events" element={<Navigate to="/register-to-dine" />} />
        <Route path="/takeaway" element={<Navigate to="/register-to-dine" />} />
        <Route path="/book-event" element={<Navigate to="/register-to-dine" />} />
        <Route path="/book-table" element={<Navigate to="/register-to-dine" />} />
        <Route path="/userpage" element={<UserPage />} />
        <Route path="/restaurant-menu" element={<RestaurantMenu />} />
        <Route path="/adminpage" element={<AdminPage />} />
        <Route path="/restuarntorder" element={<RestuarantOrder />} />
        <Route path="/addrestuarnt" element={<RestaurantPage />} />
        <Route path="/restaurantpage" element={<WelcomePage />} />
        <Route path="/restaurants" element={<Restaurant />} />
        <Route path="/restaurant/:id" element={<RestaurantDetails />} />
        <Route path="/booking-form" element={<BookingForm />} />
        <Route path="/addbookings" element={<BookindDetails />} />
        <Route path="/restaurant-payment" element={<RestaurantPayment />} />
        <Route path="/bookings" element={<BookingsPanel />} />
        <Route path="/user-events" element={<Events />} />
        <Route path="/events-list" element={<EventsList />} /> 
        <Route path="/event-details" element={<EventDetails />} />
        <Route path="/event-form" element={<EventForm />} />
        <Route path="/event-payment" element={<EventPayment />} />
        <Route path="/order" element={<OrderNow />} />
        <Route path="/menu-form" element={<MenuForm />} />
        <Route path="/change-password" element={<ChangePassword />} />
        <Route path="/restaurant-manager" element={<RestuanrtManger />} />
        <Route path="/user-details" element={<UserDetailPage />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/user-profile" element={<Userprofile />} />


       
        
        {/* Chat Routes */}
        <Route path="/user-chat" element={<UserChat />} />
        <Route path="/manager-chat" element={<ManagerChat />} />
      </Routes>
    </>
  );
}

export default App;
