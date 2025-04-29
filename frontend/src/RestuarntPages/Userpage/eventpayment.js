import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

const JoinConfirm = () => {
  const [details, setDetails] = useState(null);
  const [paymentMethod, setPaymentMethod] = useState("");
  const [paymentInfo, setPaymentInfo] = useState({});
  const [isPaymentComplete, setIsPaymentComplete] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const formData = sessionStorage.getItem("joinEventData");
    if (formData) {
      setDetails(JSON.parse(formData));
    }
  }, []);

  useEffect(() => {
    if (paymentMethod) {
      const requiredFields =
        paymentMethod === "card"
          ? ["cardNumber", "cardName", "expiry", "cvv"]
          : paymentMethod === "upi"
          ? ["upiId"]
          : ["transactionId"];

      const filled = requiredFields.every(
        (field) => paymentInfo[field]?.trim() !== ""
      );
      setIsPaymentComplete(filled);
    } else {
      setIsPaymentComplete(false);
    }
  }, [paymentInfo, paymentMethod]);

  const handlePaymentInfoChange = (e) => {
    const { name, value } = e.target;
    setPaymentInfo((prev) => ({
      ...prev,
      [name]: value,
    }));
  };
  const handleDone = async () => {
    const finalData = {
      ...details,
      paymentMethod,
      transactionId:
        paymentMethod === "card"
          ? paymentInfo.cardNumber
          : paymentMethod === "upi"
          ? paymentInfo.upiId
          : paymentInfo.transactionId,
    };
  
    try {
      const res = await fetch("http://localhost:5000/api/join-event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(finalData),
      });
  
      if (!res.ok) throw new Error("Failed to store event");
  
      // Optional local storage
      const joined = JSON.parse(localStorage.getItem("userPanelData")) || [];
      joined.push({ ...finalData, joinedAt: new Date().toISOString() });
      localStorage.setItem("userPanelData", JSON.stringify(joined));
  
      sessionStorage.removeItem("joinEventData");
      navigate("/bookings");
    } catch (err) {
      console.error("Submission error:", err);
      alert("Something went wrong. Please try again.");
    }
  };
  

  if (!details) return <p className="p-4 text-red-600">No joining details found.</p>;

  return (
    <div className="max-w-xl mx-auto p-6 bg-white rounded shadow mt-6">
      <h2 className="text-2xl font-bold text-red-600 mb-4">Confirm & Pay</h2>

      <div className="space-y-2 text-gray-700">
        <p>👤 <strong>Full Name:</strong> {details.fullName}</p>
        <p>💰 <strong>Total Price:</strong> ₹{details.totalPrice}</p>
        <p>📅 <strong>Date:</strong> {details.date}</p>
        <p>👥 <strong>No. of Persons:</strong> {details.numberOfPersons}</p>
        <p>📛 <strong>Event:</strong> {details.eventName}</p>
        <p><strong>Location:</strong>{details.location}</p>
      </div>

      <div className="mt-4">
        <label className="block text-gray-700 font-medium mb-2">Select Payment Method</label>
        <select
          value={paymentMethod}
          onChange={(e) => setPaymentMethod(e.target.value)}
          className="w-full p-2 border rounded"
        >
          <option value="">-- Select --</option>
          <option value="card">Card</option>
          <option value="upi">UPI</option>
          <option value="qr">QR Code</option>
        </select>
      </div>

      {/* Card Payment */}
      {paymentMethod === "card" && (
        <div className="mt-4 space-y-2">
          <input
            type="text"
            name="cardNumber"
            placeholder="Card Number"
            onChange={handlePaymentInfoChange}
            className="w-full p-2 border rounded"
          />
          <input
            type="text"
            name="cardName"
            placeholder="Card Holder Name"
            onChange={handlePaymentInfoChange}
            className="w-full p-2 border rounded"
          />
          <input
            type="text"
            name="expiry"
            placeholder="Expiry Date (MM/YY)"
            onChange={handlePaymentInfoChange}
            className="w-full p-2 border rounded"
          />
          <input
            type="text"
            name="cvv"
            placeholder="CVV"
            onChange={handlePaymentInfoChange}
            className="w-full p-2 border rounded"
          />
        </div>
      )}

      {/* UPI Payment */}
      {paymentMethod === "upi" && (
        <div className="mt-4">
          <input
            type="text"
            name="upiId"
            placeholder="Enter your UPI ID"
            onChange={handlePaymentInfoChange}
            className="w-full p-2 border rounded"
          />
        </div>
      )}

      {/* QR Code Payment */}
      {paymentMethod === "qr" && (
        <div className="mt-4">
          <img
            src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=DemoPayment"
            alt="QR Code"
            className="w-40 h-40 mx-auto"
          />
          <p className="text-center text-gray-600 mt-2">Scan the QR to pay</p>
          <input
            type="text"
            name="transactionId"
            placeholder="Enter Transaction ID"
            onChange={handlePaymentInfoChange}
            className="w-full mt-2 p-2 border rounded"
          />
        </div>
      )}

      {/* Done Button */}
      {paymentMethod && (
        <button
          onClick={handleDone}
          disabled={!isPaymentComplete}
          className={`mt-6 w-full py-2 px-4 rounded text-white ${
            isPaymentComplete ? "bg-red-600 hover:bg-red-700" : "bg-gray-400 cursor-not-allowed"
          }`}
        >
          Done
        </button>
      )}
    </div>
  );
};

export default JoinConfirm;
