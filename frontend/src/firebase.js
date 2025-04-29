// src/firebase.js
import { initializeApp } from "firebase/app";
import { getFirestore } from "firebase/firestore";

// Your Firebase config
const firebaseConfig = {
  apiKey: "AIzaSyADy7Zl8mr50trquhNzLk6ZfidPwgEb6UQ",
  authDomain: "letseatchat-2071c.firebaseapp.com",
  projectId: "letseatchat-2071c",
  storageBucket: "letseatchat-2071c.firebasestorage.app",
  messagingSenderId: "1015478743759",
  appId: "1:1015478743759:web:d88ca292f519ed2c2afdba",
  measurementId: "G-4TPYF9Q2RG"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize Firestore (you need this for chat)
const db = getFirestore(app);

export { db };
