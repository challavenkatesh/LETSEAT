import React, { useState } from "react";
import { AlertCircle, Ban, Flag } from "lucide-react";
import { Dialog } from "@headlessui/react";
import { motion } from "framer-motion";

const defaultUsers = [
  {
    name: "Alice Smith",
    email: "alice@example.com",
    gender: "Female",
    location: "New York",
    reported: false,
  },
  {
    name: "Bob Johnson",
    email: "bob@example.com",
    gender: "Male",
    location: "California",
    reported: false,
  },
];

function UserDetails() {
  const [users, setUsers] = useState(defaultUsers);
  const [open, setOpen] = useState(false);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [selectedReason, setSelectedReason] = useState("");

  const reasons = ["Spam", "Abuse", "Inappropriate Content", "Other"];

  const handleReportClick = (email) => {
    setSelectedEmail(email);
    setOpen(true);
  };

  const handleSubmitReport = () => {
    setUsers((prev) =>
      prev.map((user) =>
        user.email === selectedEmail ? { ...user, reported: true } : user
      )
    );
    setOpen(false);
    setSelectedEmail(null);
    setSelectedReason("");
  };

  return (
    <div className="p-6 font-serif">
      <h1 className="text-3xl font-bold text-red-600 mb-6">User Management</h1>

      <div className="overflow-x-auto shadow-xl rounded-xl bg-white">
        <table className="min-w-full text-sm text-left">
          <thead className="bg-black text-white text-xs uppercase">
            <tr>
              <th className="py-3 px-6">Name</th>
              <th className="py-3 px-6">Email</th>
              <th className="py-3 px-6">Gender</th>
              <th className="py-3 px-6">Location</th>
              <th className="py-3 px-6">Actions</th>
            </tr>
          </thead>
          <tbody className="text-gray-800">
            {users.map((user, index) => (
              <tr
                key={index}
                className={`border-b ${user.reported ? "bg-red-50" : ""}`}
              >
                <td className="py-3 px-6 font-semibold flex items-center gap-2">
                  {user.reported && (
                    <AlertCircle className="text-red-600" size={16} />
                  )}
                  {user.name}
                </td>
                <td className="py-3 px-6">{user.email}</td>
                <td className="py-3 px-6">{user.gender}</td>
                <td className="py-3 px-6">{user.location}</td>
                <td className="py-3 px-6 flex gap-3">
                  <button className="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 text-xs flex items-center gap-1">
                    <Ban size={14} />
                    Block
                  </button>
                  <button
                    onClick={() => handleReportClick(user.email)}
                    className="bg-yellow-500 text-white px-3 py-1 rounded hover:bg-yellow-600 text-xs flex items-center gap-1"
                  >
                    <Flag size={14} />
                    Report
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Modal */}
      <Dialog open={open} onClose={() => setOpen(false)} className="relative z-50">
        <div className="fixed inset-0 bg-black/30" aria-hidden="true" />
        <div className="fixed inset-0 flex items-center justify-center">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-white rounded-xl p-6 shadow-2xl w-96"
          >
            <Dialog.Title className="text-xl font-bold mb-4 text-red-600">
              Report User
            </Dialog.Title>
            <div className="space-y-3">
              {reasons.map((reason, idx) => (
                <label key={idx} className="flex items-center gap-2">
                  <input
                    type="radio"
                    value={reason}
                    checked={selectedReason === reason}
                    onChange={(e) => setSelectedReason(e.target.value)}
                    className="accent-red-600"
                  />
                  <span>{reason}</span>
                </label>
              ))}
            </div>

            <div className="flex justify-end mt-6 gap-3">
              <button
                onClick={() => setOpen(false)}
                className="text-gray-500 hover:text-gray-800"
              >
                Cancel
              </button>
              <button
                disabled={!selectedReason}
                onClick={handleSubmitReport}
                className="bg-red-600 text-white px-4 py-1 rounded hover:bg-red-700 disabled:opacity-50"
              >
                Submit
              </button>
            </div>
          </motion.div>
        </div>
      </Dialog>
    </div>
  );
}

export default UserDetails;
