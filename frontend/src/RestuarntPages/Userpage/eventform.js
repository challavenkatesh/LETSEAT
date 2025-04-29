import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

const JoinEventForm = () => {
  const [event, setEvent] = useState(null);
  const [formData, setFormData] = useState({
    fullName: "",
    age: "",
    gender: "",
    numberOfPersons: 1,
  });
  const [totalPrice, setTotalPrice] = useState(0);
  const navigate = useNavigate();

  useEffect(() => {
    const eventData = sessionStorage.getItem("selectedEvent");
    if (eventData) {
      const parsedEvent = JSON.parse(eventData);
      setEvent(parsedEvent);
      setTotalPrice(parsedEvent.price); // default 1 person
    }
  }, []);

  useEffect(() => {
    if (event) {
      setTotalPrice(event.price * formData.numberOfPersons);
    }
  }, [formData.numberOfPersons, event]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: name === "numberOfPersons" ? parseInt(value) : value,
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const submissionData = {
      ...formData,
      eventName: event.name,
      date: event.date,
      location: event.location,
      pricePerPerson: event.price,
      totalPrice,
    };
    sessionStorage.setItem("joinEventData", JSON.stringify(submissionData));
    navigate("/event-payment");
  };

  if (!event) return <p className="p-4">Loading event details...</p>;

  return (
    <div className="max-w-xl mx-auto p-6 bg-white rounded shadow mt-6 font-serif">
      <h2 className="text-2xl font-bold mb-4 text-red-600">Join Event</h2>
      <form onSubmit={handleSubmit} className="space-y-4 text-sm">
        <div>
          <label className="block font-medium text-gray-700">Event Name</label>
          <input
            type="text"
            value={event.name}
            disabled
            className="w-full p-2 border rounded bg-gray-100"
          />
        </div>
        <div>
          <label className="block font-medium text-gray-700">Date</label>
          <input
            type="text"
            value={event.date}
            disabled
            className="w-full p-2 border rounded bg-gray-100"
          />
        </div>
        <div>
          <label className="block font-medium text-gray-700">Location</label>
          <input
            type="text"
            value={event.location}
            disabled
            className="w-full p-2 border rounded bg-gray-100"
          />
        </div>
        <div>
          <label className="block font-medium text-gray-700">Full Name</label>
          <input
            type="text"
            name="fullName"
            value={formData.fullName}
            onChange={handleChange}
            required
            className="w-full p-2 border rounded"
          />
        </div>
        <div>
          <label className="block font-medium text-gray-700">Age</label>
          <input
            type="number"
            name="age"
            value={formData.age}
            onChange={handleChange}
            required
            className="w-full p-2 border rounded"
          />
        </div>
        <div>
          <label className="block font-medium text-gray-700">Gender</label>
          <select
            name="gender"
            value={formData.gender}
            onChange={handleChange}
            required
            className="w-full p-2 border rounded"
          >
            <option value="">Select Gender</option>
            <option value="Male">Male</option>
            <option value="Female">Female</option>
            <option value="Other">Other</option>
          </select>
        </div>
        <div>
          <label className="block font-medium text-gray-700">No. of Persons</label>
          <input
            type="number"
            name="numberOfPersons"
            value={formData.numberOfPersons}
            min={1}
            onChange={handleChange}
            required
            className="w-full p-2 border rounded"
          />
        </div>
        <div>
          <label className="block font-medium text-gray-700">Price Per Person</label>
          <input
            type="text"
            value={`₹${event.price}`}
            disabled
            className="w-full p-2 border rounded bg-gray-100"
          />
        </div>
        <div>
          <label className="block font-bold text-red-600">Total Price</label>
          <div className="text-lg font-semibold">₹{totalPrice}</div>
        </div>
        <button
          type="submit"
          className="bg-red-600 text-white px-4 py-2 rounded hover:bg-black transition duration-200"
        >
          Join Event
        </button>
      </form>
    </div>
  );
};

export default JoinEventForm;
