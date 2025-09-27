const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const moment = require('moment');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const dotenv = require('dotenv');
const fs = require('fs');

dotenv.config();

const app = express();
const PORT = 3001;
app.use(express.json());

const JWT_SECRET = 'your_jwt_secret'; // Use a strong, secret key in production

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

// MongoDB connection string
const uri = "mongodb+srv://thomasmethembe43:KSqoTlwvlK45FyVP@cluster0.2vjumfn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const client = new MongoClient(uri);

// Database and collection references
let db;
let usersCollection;

// Connect to MongoDB
async function connectToMongoDB() {
  try {
    await client.connect();
    console.log('Connected to MongoDB');
    db = client.db('nursing-school');
    usersCollection = db.collection('users');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
}

const generateToken = (userId) => {
    const secretKey = 'your-secret-key'; // Replace with your own secret key
    const expiresIn = '1h'; // Token expiration time, e.g., 1 hour
    const payload = { 
        sub: userId,  
        iat: Math.floor(Date.now() / 1000), // Issued at time (current time in seconds)
    };
    return jwt.sign(payload, secretKey, { expiresIn });
};

cloudinary.config({
  cloud_name: "dxxlrzouc",
  api_key: "191187614991536",
  api_secret: "9b75q3SXcar-yJFsWQsfXWFhnM8",
});

async function encryptPassword(password) {
    try {
      // Define the number of salt rounds
      const saltRounds = 10;
  
      // Generate the salt
      const salt = await bcrypt.genSalt(saltRounds);
  
      // Hash the password with the salt
      const hashedPassword = await bcrypt.hash(password, salt);
  
      console.log('Encrypted Password:', hashedPassword);
      return hashedPassword;
    } catch (error) {
      console.error('Error encrypting password:', error);
    }
}

const generateId = () => {
    return crypto.randomBytes(12).toString('hex'); // Generates a 24-character hexadecimal string
};

const registerUser = async (userData) => {
    try {
        // Check if the username exists
        const existingUsername = await usersCollection.findOne({ username: userData.username });
        
        if (existingUsername) {
            return { status: 400, message: 'Username already exists' };
        }

        // Check if the email exists
        const existingEmail = await usersCollection.findOne({ email: userData.email });
        
        if (existingEmail) {
            return { status: 400, message: 'Email already registered' };
        }

        const { hashedPassword, ...rest } = userData;

        // Register the new user
        const result = await usersCollection.insertOne({
            ...rest,
            hashedPassword: hashedPassword,
            signupTimestamp: new Date(),
        });

        const token = generateToken(result.insertedId);

        return { status: 200, token };
    } catch (error) {
        console.error('Error registering user:', error);
        return { status: 500, message: 'Internal server error' };
    }
};

app.post('/get-user', async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        const users = await usersCollection.find({ username: username }).toArray();
        res.json(users);
        console.log(users);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/delete-user', async (req, res) => {
    try {
        const packageData = req.body;
        const { filter, update } = packageData;

        console.log(filter);
        
        if (!filter._id) {
            return res.status(400).json({ error: 'Missing _id for update.' });
        }

        const result = await usersCollection.updateOne(
            { _id: new ObjectId(filter._id) },
            { $set: update }
        );

        res.json(result);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/register', async (req, res) => {
    try {
        const userData = { ...req.body };
        userData.hashedPassword = await encryptPassword(userData.password);
        delete userData.password;
        delete userData.confirmPassword;

        const response = await registerUser(userData);

        if (response.status === 200) {
            res.json({ token: response.token });
        } else {
            res.status(response.status).json({ message: response.message });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Registration failed' });
    }
});

// Login User
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await usersCollection.findOne({ username });

        console.log(user?.hashedPassword);
        
        if (user && bcrypt.compareSync(password, user.hashedPassword)) {
            const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

            // Update user's loggedOn status and loginTimestamp
            const loginTimestamp = new Date().toISOString();
            
            await usersCollection.updateOne(
                { _id: user._id },
                { $set: { isLoggedOn: true, loginTimestamp } }
            );

            res.json({ token });
        } else {
            res.status(401).send('Invalid credentials');
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send('Internal server error');
    }
});

// Multer setup to store files temporarily
const upload = multer({ dest: 'uploads/' });

// Upload route
app.post('/upload', upload.single('image'), async (req, res) => {
    try {
        const filePath = req.file.path;

        // Upload to Cloudinary
        const result = await cloudinary.uploader.upload(filePath, {
            folder: 'chat_avatars', // Optional: target folder in Cloudinary
        });

        // Remove temp file
        fs.unlinkSync(filePath);

        res.json({ success: true, url: result.secure_url });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ success: false, message: 'Image upload failed.' });
    }
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('Shutting down gracefully...');
    await client.close();
    process.exit(0);
});

// Start server after connecting to MongoDB
connectToMongoDB().then(() => {
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
});
