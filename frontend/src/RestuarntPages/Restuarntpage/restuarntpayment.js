import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

const PaymentForm = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const bookingData = location.state || {};

  const [method, setMethod] = useState('');
  const [date, setDate] = useState('');
  const [upiId, setUpiId] = useState('');
  const [amount, setAmount] = useState('');

  useEffect(() => {
    if (bookingData.guests) {
      const calculatedAmount = parseInt(bookingData.guests) * 2000;
      setAmount(calculatedAmount.toString());
    }
  }, [bookingData.guests]);

  const handlePaymentSubmit = (e) => {
    e.preventDefault();

    const paymentData = {
      id: Date.now(),
      restaurantName: bookingData.name,
      fullName: bookingData.fullName,
      bookingDateTime: bookingData.dateTime,
      guests: bookingData.guests,
      price: bookingData.price,
      amount,
      method,
      date,
      upiId
    };

    const existingPayments = JSON.parse(localStorage.getItem('payments')) || [];
    existingPayments.push(paymentData);
    localStorage.setItem('payments', JSON.stringify(existingPayments));

    alert("✅ Payment submitted successfully!");
    navigate('/userpage');
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-6">
      <form onSubmit={handlePaymentSubmit} className="bg-white p-8 rounded-lg shadow-lg w-full max-w-xl space-y-4">
        <h2 className="text-2xl font-bold text-center text-red-600">Complete Payment</h2>
        <div className="bg-gray-100 p-4 rounded-lg">
          <p><strong>Restaurant:</strong> {bookingData.name}</p>
          <p><strong>Name:</strong> {bookingData.fullName}</p>
          <p><strong>Date & Time:</strong> {bookingData.dateTime}</p>
          <p><strong>Guests:</strong> {bookingData.guests}</p>
        </div>
        <input
          type="number"
          value={amount}
          readOnly
          className="w-full px-4 py-2 border rounded-lg bg-gray-100 text-gray-700"
        />
        <select
          value={method}
          onChange={(e) => setMethod(e.target.value)}
          className="w-full px-4 py-2 border rounded-lg"
          required
        >
          <option value="">Select Payment Method</option>
          <option value="UPI">UPI</option>
          <option value="Card">Card</option>
          <option value="Wallet">Wallet</option>
        </select>
        {method === 'UPI' && (
          <>
            <input
              type="text"
              placeholder="Enter UPI ID"
              value={upiId}
              onChange={(e) => setUpiId(e.target.value)}
              className="w-full px-4 py-2 border rounded-lg"
              required
            />
            <div className="flex justify-center">
              <img
                src="/assets/qr-code.png"
                alt="Scan to Pay"
                className="w-40 h-40 object-contain"
              />
            </div>
          </>
        )}
        <input
          type="date"
          value={date}
          onChange={(e) => setDate(e.target.value)}
          className="w-full px-4 py-2 border rounded-lg"
          required
        />
        <button
          type="submit"
          className="w-full bg-red-600 text-white py-2 rounded-lg hover:bg-red-700 transition"
        >
          Submit Payment
        </button>
      </form>
    </div>
  );
};

export default PaymentForm;
