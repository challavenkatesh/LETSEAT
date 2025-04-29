require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");


const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

// Use Routes

// MySQL Connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Singleforever@2001",
  database: "user_auth",
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
  } else {
    console.log("✅ Connected to MySQL database");
  }
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization");

  if (!token) {
    return res.status(401).json({ message: "Access Denied: No Token Provided" });
  }

  jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid Token" });
    req.user = user;
    next();
  });
};
app.post("/api/auth/signup", (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  let role = "user";
  if (email.includes("admin")) role = "admin";
  else if (email.includes("letseat")) role = "restaurant";
  else if (email.endsWith("@gmail.com")) role = "customer";

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error", error: err });
    if (results.length > 0) return res.status(400).json({ message: "Email already exists" });

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ message: "Error hashing password", error: err });

      db.query(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
        [name, email, hashedPassword, role],
        (err, result) => {
          if (err) return res.status(500).json({ message: "Error storing user", error: err });

          const token = jwt.sign(
            { id: result.insertId, name, email, role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
          );

          res.status(201).json({ message: "User registered successfully", token, role });
        }
      );
    });
  });
});
app.post("/api/change-password", async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  try {
    // Get user by email
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
      if (err) return res.status(500).json({ success: false, message: "DB error" });

      if (results.length === 0) {
        return res.json({ success: false, message: "User not found" });
      }

      const user = results[0];

      // Compare old password
      const isMatch = await bcrypt.compare(oldPassword, user.password);
      if (!isMatch) {
        return res.json({ success: false, message: "Old password is incorrect" });
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update in DB
      db.query(
        "UPDATE users SET password = ? WHERE email = ?",
        [hashedPassword, email],
        (updateErr) => {
          if (updateErr) return res.status(500).json({ success: false, message: "Update failed" });
          return res.json({ success: true, message: "Password updated successfully" });
        }
      );
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Both email and password are required" });
  }

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error", error: err });
    if (results.length === 0) return res.status(401).json({ message: "Invalid email or password" });

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) return res.status(401).json({ message: "Invalid email or password" });

      const token = jwt.sign(
        { id: user.id, email: user.email, name: user.name, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );

      res.status(200).json({
        message: "Login successful",
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    });
  });
});

// PROTECTED ROUTE
app.get("/api/protected", authenticateToken, (req, res) => {
  res.json({ message: "Access granted!", user: req.user });
});
// Admin-Only Route
app.get("/api/admin", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Access denied! Admins only" });
  }
  res.json({ message: "Welcome, Admin!", user: req.user });
});


app.post('/api/restaurants', (req, res) => {
  const {
    name, location, owner_id, cuisine, description, image_url, 
    price, rating, seats_available, opening_hours
  } = req.body;

  const query = `
    INSERT INTO restaurant (name, location, owner_id, cuisine, description, image_url, 
                             price, rating, seats_available, opening_hours)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  const values = [
    name, location, owner_id, cuisine, description, image_url,
    price, rating, seats_available, opening_hours
  ];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error inserting data', err);
      return res.status(500).send('Error saving data');
    }
    res.status(200).send('Restaurant added');
  });
});
app.get('/api/restaurants', (req, res) => {
  db.query('SELECT * FROM restaurant', (err, results) => {
    if (err) {
      console.error('Error fetching restaurants', err);
      return res.status(500).send('Error fetching restaurants');
    }
    res.status(200).json(results);
  });
});
app.put("/api/restaurants/:id", (req, res) => {
  const restaurantId = req.params.id;
  const {
    name, location, owner_id, cuisine, description, image_url, 
    price, rating, seats_available, opening_hours
  } = req.body;

  const query = `
    UPDATE restaurant SET 
      name = ?, location = ?, owner_id = ?, cuisine = ?, description = ?, image_url = ?, 
      price = ?, rating = ?, seats_available = ?, opening_hours = ? 
    WHERE id = ?`;

  const values = [
    name, location, owner_id, cuisine, description, image_url,
    price, rating, seats_available, opening_hours, restaurantId
  ];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error("Error updating restaurant", err);
      return res.status(500).send("Error updating restaurant");
    } 
    res.status(200).send("Restaurant updated successfully");
  });
});
// Delete a restaurant
app.delete("/api/restaurants/:id", (req, res) => {
  const restaurantId = req.params.id;

  const query = `DELETE FROM restaurant WHERE id = ?`;

  db.query(query, [restaurantId], (err, result) => {
    if (err) {
      console.error("Error deleting restaurant", err);
      return res.status(500).send("Error deleting restaurant");
    }
    res.status(200).send("Restaurant deleted successfully");
  });
});
// Assuming you are using express and mysql2
app.post("/api/events", (req, res) => {
  const {
    name,
    maxAttendees,
    date,
    time,
    description,
    restaurantId,
    imageUrl,
    location,
    category,
    price
  } = req.body;

  const sql = `
    INSERT INTO events 
    (name, maxAttendees, date, time, description, restaurantId, imageUrl, location, category, price)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const values = [
    name,
    maxAttendees,
    date,
    time,
    description,
    restaurantId,
    imageUrl,
    location,
    category,
    price
  ];

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error("Error inserting event:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.status(201).json({ message: "Event created successfully" });
  });
});

// Get All Events (GET)
app.get("/api/events", (req, res) => {
  const sql = "SELECT * FROM events";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching events:", err);
      return res.status(500).json({ error: "Error fetching events" });
    }
    res.json(results);
  });
});
app.get("/api/events", (req, res) => {
  const query = "SELECT * FROM events"; // Query to get all events

  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching events" });
    }
    res.json(result);
  });
});
app.get("/api/analytics/monthly", (req, res) => {
  const query = `
    SELECT MONTH(booking_datetime) AS month, COUNT(*) AS count
    FROM bookings
    GROUP BY month
    ORDER BY month ASC
  `; // Query to get the count of bookings per month

  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching monthly bookings" });
    }
    res.json({ bookingsByMonth: result });
  });
});
// Get popular restaurants
app.get("/api/analytics/popular-restaurants", (req, res) => {
  const query = `
    SELECT r.restaurant_name, r.location, COUNT(b.id) AS total_bookings
    FROM restaurants r
    LEFT JOIN bookings b ON r.id = b.restaurant_id
    GROUP BY r.id
    ORDER BY total_bookings DESC
  `; // Query to get the most popular restaurants based on bookings

  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching popular restaurants" });
    }
    res.json(result);
  });
});

// Get popular events
app.get("/api/analytics/popular-events", (req, res) => {
  const query = `
    SELECT e.event_name, COUNT(be.id) AS total_bookings
    FROM events e
    LEFT JOIN bookings_events be ON e.id = be.event_id
    GROUP BY e.id
    ORDER BY total_bookings DESC
    LIMIT 5
  `; // Query to get the top 5 popular events based on bookings

  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching popular events" });
    }
    res.json(result);
  });
});


app.get("/api/users", (req, res) => {
  const query = "SELECT * FROM users"; // Query to get all users

  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching users" });
    }
    res.json(result);
  });
});
app.get("/api/bookings", (req, res) => {
  const query = "SELECT * FROM bookings"; // Query to get all bookings

  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching bookings" });
    }
    res.json(result);
  });
});
// POST endpoint to store booking details
app.post("/api/bookings", (req, res) => {
  const { user_id, restaurant_id, restaurant_name, restaurant_location, booking_datetime, guests, specialRequests, price } = req.body;

  // Ensure that the user_id is provided in the request body
  if (!user_id) {
    return res.status(400).json({ error: "User ID is required" });
  }

  const query = `INSERT INTO bookings (user_id, restaurant_id, restaurant_name, restaurant_location, booking_datetime, status) 
                 VALUES (?, ?, ?, ?, ?, 'Pending')`;

  db.query(query, [user_id, restaurant_id, restaurant_name, restaurant_location, booking_datetime], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send("Error inserting booking");
    }
    const bookingId = result.insertId;
    res.status(200).json({ bookingId });
  });
});


// GET endpoint to fetch all bookings for the user
app.get("/api/bookings", (req, res) => {
  const user_id = req.query.user_id;  // Assuming the user_id is passed as a query parameter

  if (!user_id) {
    return res.status(400).json({ error: "User ID is required" });
  }

  db.query("SELECT * FROM bookings WHERE user_id = ?", [user_id], (err, results) => {
    if (err) {
      return res.status(500).send("Error fetching bookings");
    }
    res.status(200).json(results);
  });
});

// GET endpoint to fetch the status of a booking by bookingId
app.get("/api/bookings/status/:id", (req, res) => {
  const bookingId = req.params.id;

  // Fetch booking by ID
  db.query("SELECT * FROM bookings WHERE id = ?", [bookingId], (err, results) => {
    if (err) return res.status(500).json({ message: "Error fetching booking status" });
    if (results.length === 0) return res.status(404).json({ message: "Booking not found" });

    const booking = results[0];
    res.status(200).json({ status: booking.status });
  });
});

// PUT endpoint to update booking status
app.put('/api/bookings/status/:id', (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  // Update the status in the database
  db.query('UPDATE bookings SET status = ? WHERE id = ?', [status, id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to update status' });
    }
    res.status(200).json({ message: 'Status updated successfully', status });
  });
});


// ✅ POST route
app.post("/api/restaurants", (req, res) => {
  const { name, location, price, menu } = req.body;
  const menuStr = JSON.stringify(menu);
  const sql = "INSERT INTO restaurants (name, location, price, menu) VALUES (?, ?, ?, ?)";

  db.query(sql, [name, location, price, menuStr], (err, result) => {
    if (err) {
      console.error("Insert Error:", err);
      return res.status(500).json({ error: "Failed to add restaurant" });
    }
    res.json({ message: "Restaurant added successfully" });
  });
});

// ✅ GET route (optional to verify)
app.get("/api/restaurants", (req, res) => {
  db.query("SELECT * FROM restaurants", (err, results) => {
    if (err) return res.status(500).json({ error: "Failed to fetch" });
    res.json(results);
  });
});

// ✅ Get menu items by restaurant ID
app.get("/api/menu/:restaurantId", (req, res) => {
  const restaurantId = req.params.restaurantId;
  const query = "SELECT * FROM menu WHERE restaurant_id = ?";
  db.query(query, [restaurantId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching menu:", err);
      return res.status(500).send("Server error");
    }
    res.json(results);
  });
});

// ✅ Add new menu item
app.post('/api/menu', (req, res) => {
  const { restaurant_id, name, price, image_url, category } = req.body;

  const query = `INSERT INTO menu (restaurant_id, name, price, image_url, category) 
                 VALUES (?, ?, ?, ?, ?)`;

  db.query(query, [restaurant_id, name, price, image_url, category], (err, result) => {
    if (err) {
      console.error('Error inserting menu item:', err);
      return res.status(500).json({ error: 'Failed to add menu item' });
    }

    res.status(200).json({ message: 'Menu item added successfully!' });
  });
});

app.get("/api/menu", (req, res) => {
  db.query("SELECT * FROM menu", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});
// 🧾 Update a menu item
app.put("/api/menu/:id", (req, res) => {
  const { id } = req.params;
  const { name, price, image_url } = req.body;
  const sql = "UPDATE menu SET name = ?, price = ?, image_url = ? WHERE id = ?";
  db.query(sql, [name, price, image_url, id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "Menu item updated successfully" });
  });
});


// ❌ Delete a menu item
app.delete("/api/menu/:id", (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM menu WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "Menu item deleted successfully" });
  });
});

// GET: Most Frequently Booked Restaurant Names
app.get("/api/bookings/popular", (req, res) => {
  const query = `
    SELECT 
      restaurant_name,
      restaurant_location AS location,
      COUNT(*) AS total_bookings
    FROM bookings
    GROUP BY restaurant_name, restaurant_location
    HAVING COUNT(*) > 1
    ORDER BY total_bookings DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching popular restaurants:", err);
      return res.status(500).json({ error: "Failed to fetch popular restaurants" });
    }

    res.status(200).json(results);
  });
});

app.post("/api/join-event", (req, res) => {
  const {
    fullName,
    totalPrice,
    date,
    numberOfPersons,
    eventName,
    location,
    paymentMethod,
    transactionId
  } = req.body;

  // Extract just date part (YYYY-MM-DD)
  const dateOnly = new Date(date).toISOString().split("T")[0];

  const query = `
    INSERT INTO event_bookings 
    (fullName, totalPrice, date, numberOfPersons, eventName, location, paymentMethod, transactionId) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [fullName, totalPrice, dateOnly, numberOfPersons, eventName, location, paymentMethod, transactionId],
    (err, result) => {
      if (err) {
        console.error("❌ Error saving event:", err);
        return res.status(500).json({ error: "Database error" });
      }
      res.status(200).json({ message: "✅ Event joined successfully" });
    }
  );
});
app.get("/api/popular-events", (req, res) => {
  const query = `
    SELECT eventName, COUNT(*) AS total_bookings 
    FROM event_bookings 
    GROUP BY eventName 
    ORDER BY total_bookings DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching popular events:", err);
      return res.status(500).json({ error: "Database error" });
    }

    console.log("Popular events:", results); // ✅ Add this line to debug
    res.status(200).json(results);
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
