import React from "react";

const OrderConfirmation = () => {
  const order = JSON.parse(sessionStorage.getItem("orderInfo"));

  // Custom message based on order type
  let orderMessage = "";
  if (order?.type === "Takeaway") {
    orderMessage = `✅ Your order was placed successfully. Please come and pick it up at your mentioned time.`;
  } else if (order?.type === "Dine-in") {
    orderMessage = `✅ Your order was placed successfully. It will arrive at your table in approximately 10 minutes.`;
  }

  return (
    <div className="min-h-screen flex flex-col justify-center items-center bg-green-50 p-6">
      <div className="bg-white p-6 rounded-xl shadow-lg text-center max-w-lg">
        <h1 className="text-3xl font-bold text-green-700 mb-4">🎉 Order Confirmed!</h1>
        <p className="text-lg">Thank you for your order, {order?.email}!</p>
        <p className="mt-2">📦 Item: <strong>{order?.item}</strong></p>
        <p>📞 Phone: <strong>{order?.phone}</strong></p>
        <p>💰 Total Paid: <strong>₹{order?.total}</strong></p>

        {/* Dynamic order type message */}
        <p className="mt-4 text-base font-medium text-green-700">{orderMessage}</p>

        <p className="mt-4 text-sm text-gray-500">You will receive a confirmation email shortly.</p>
      </div>
    </div>
  );
};

export default OrderConfirmation;
