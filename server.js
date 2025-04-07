// Import dependencies
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const nodemailer = require("nodemailer");
const { RateLimiterMemory } = require('rate-limiter-flexible'); 

// Load environment variables from .env file
dotenv.config();

// Initialize the Express app
const app = express();
app.use(express.json()); // Middleware to parse JSON requests
app.use(cors());

// MongoDB connection (using your Login database and collection)
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.log('MongoDB connection error:', err));


let otpStorage = {};
const OTP_EXPIRATION_TIME = 5 * 60 * 1000; // 5 minutes in milliseconds
const OTP_REQUEST_LIMIT = 3; // Max OTP requests per minute
  
  // Create a rate limiter instance (per user)
const rateLimiter = new RateLimiterMemory({
  points: OTP_REQUEST_LIMIT, // Max 3 requests
  duration: 60, // Per 60 seconds
});

const generateOtp = () => Math.floor(100000 + Math.random() * 900000); 


// Define the User Schema (Email and Password)
const loginSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  signupDate: { type: Date, default: Date.now }, 
});

// Create a model for the Login collection
const Login = mongoose.model("Login", loginSchema,"Logins");

// Signup route
app.post("/signup", async (req, res) => {
  const { email } = req.body;
  try {
    // Check rate limit for the user (email)
 // Use email as the key for rate limiting

    // Generate OTP
    const otp = generateOtp();
    const timestamp = Date.now(); // Store OTP generation timestamp

    // Store OTP and timestamp temporarily (In-memory for simplicity)
    otpStorage[email] = { otp, timestamp };
    // Send OTP to email using nodemailer
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL, // Your email
        pass: process.env.PASS,   // Your email password
      },
    });

    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "OTP for Signup",
      text: `Your Money Tracker OTP is: ${otp}`,
    };

    const existingUser = await Login.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use.' });
    }

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        return res.status(500).json({ success: false, message: "Error sending OTP" });
      }
      res.json({ success: true, message: "OTP sent" });
    });
  } catch (error) {
    return res.status(429).json({
      success: false,
      message: `Too many requests. Please try again later.`,
    });
  }
});

// Verify OTP route
app.post("/verify", async (req, res) => {
  const { email, otp, password } = req.body;

  // Check if OTP exists in storage
  if (otpStorage[email]) {
    const storedOtpData = otpStorage[email];
    const timeElapsed = Date.now() - storedOtpData.timestamp;

    // Check if OTP is expired
    if (timeElapsed > OTP_EXPIRATION_TIME) {
      delete otpStorage[email]; // Remove expired OTP from memory
      return res.status(400).json({ success: false, message: "OTP has expired" });
    }

    // Check if OTP is correct
    if (storedOtpData.otp === parseInt(otp)) {
      try {
        // Hash the password before saving it to the database
        const hashedPassword = await bcrypt.hash(password, 10);
        // Create a new user document with the hashed password
        const newUser = new Login({
          email,
          password: hashedPassword, // Save the hashed password
        });

        // Save the user to the database using `await`
        await newUser.save();

        // Clear OTP from memory after successful signup
        delete otpStorage[email];

        // Send a success response
        res.json({ success: true, message: "Signup successful" });

      } catch (error) { // Log the error for debugging
        return res.status(500).json({ success: false, message: "Error saving user" });
      }
    } else {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }
  } else {
    return res.status(400).json({ success: false, message: "No OTP found for this email" });
  }
});

//Define the payment store Schema
const paymentSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  amount: {
    type: Number,
    required: true,
    min: 1,
  },
  date: {
    type: String,
    required: true,
  },
  payfor: {
    type: String,
    required: true,
  },
});

const Payment = mongoose.model('Payment', paymentSchema);

// Pre-save hook to hash the password before saving it
loginSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  try {
    const salt = await bcrypt.genSalt(10);  // Generate salt
    this.password = await bcrypt.hash(this.password, salt); // Hash the password
    next();
  } catch (error) {
    next(error);
  }
});


app.get("/user-count-per-month", async (req, res) => {
  try {
    // Initialize an array to hold counts for each month
    let monthlyCounts = Array(12).fill(0); // Initialize count for each month (Jan-Dec)

    // Fetch all users' signup dates
    const users = await Login.find({});

    // Loop through users and increment the corresponding month count
    users.forEach(user => {
      const signupMonth = user.signupDate.getMonth(); // Get month index (0 = Jan, 11 = Dec)
      monthlyCounts[signupMonth]++; // Increment the count for that month
    });

    // Return the monthly counts (January to December)
    res.json({
      months: [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
      ],
      userCount: monthlyCounts,
    });
  } catch (error) {
    res.status(500).send("Server Error");
  }
});

app.post('/payment', async (req, res) => {
  const {amount, date, payfor , email} = req.body;

  try {
    // Check if the user exists
    const user = await Login.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }


    // Create a new payment document
    const newPayment = new Payment({
      email,
      amount,
      date,
      payfor,
    });

    // Save the new payment document
    await newPayment.save();

    res.json({ message: 'Expense added successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error in adding expense', error });
  }
});

app.post('/fetchExpenses', async (req, res) => {
  const { email } = req.body;

  try {
    const expenses = await Payment.find({ email });
    res.status(200).json(expenses);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching expenses', error });
  }
});

app.delete('/deletepayment', async (req, res) => {
  const { email, id } = req.body; // Receive email and id from request body

  try {
    // Validate if both email and id are provided
    if (!email || !id) {
      return res.status(400).json({ message: 'Email and ID are required' });
    }

    // Find the payment document by both email and id
    const payment = await Payment.findOneAndDelete({ _id: id, email: email });

    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }

    // Successfully deleted payment
    res.status(200).json({ message: 'Payment deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Login Route (Authenticate user and generate JWT)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user exists
    const user = await Login.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }

    // Compare the entered password with the stored hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }

    // Generate a JWT token for the user
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
	
    res.json({ message: 'Login successful', token});
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error });
  }
});

// Middleware to verify the JWT token (to protect routes)
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', ''); // Extract token from the header

  if (!token) {
    return res.status(401).json({ message: 'No token provided. Authorization denied.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Decode the token using your JWT secret
    req.email = decoded.email; // Attach the decoded email to the request
    next(); // Proceed to the next middleware or route
  } catch (err) {
    res.status(401).json({ message: 'Invalid or expired token.' });
  }
};

// A protected route example (only accessible with a valid token)
app.get('/dashboard', async (req, res) => {
  const { email, password } = req.query;  // Or use req.body if POST request

  try {
    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // If credentials are correct, send the dashboard data
    res.json({ message: 'Welcome to the dashboard!' });

  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Start the server
const port = process.env.PORT;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
