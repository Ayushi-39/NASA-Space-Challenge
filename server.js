// Deep Dive Backend Server
// Dependencies: express, mongoose, bcrypt, jsonwebtoken, cors, dotenv, multer

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/deepdive', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// ============ SCHEMAS ============

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: String,
  lastName: String,
  avatar: String,
  role: { type: String, enum: ['user', 'researcher', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  preferences: {
    defaultLayer: { type: String, default: 'heat' },
    notifications: { type: Boolean, default: true },
    theme: { type: String, default: 'dark' }
  }
});

// Saved View Schema
const savedViewSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: String,
  layer: String,
  date: String,
  coordinates: {
    lat: Number,
    lng: Number,
    zoom: Number
  },
  tags: [String],
  isPublic: { type: Boolean, default: false },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Annotation Schema
const annotationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  viewId: { type: mongoose.Schema.Types.ObjectId, ref: 'SavedView' },
  layer: String,
  date: String,
  coordinates: {
    lat: Number,
    lng: Number
  },
  content: String,
  type: { type: String, enum: ['note', 'observation', 'alert'], default: 'note' },
  createdAt: { type: Date, default: Date.now }
});

// Analytics Event Schema
const analyticsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  eventType: { type: String, required: true },
  layer: String,
  date: String,
  sessionId: String,
  metadata: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now }
});

// Data Request Schema
const dataRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  layer: { type: String, required: true },
  dateRange: {
    start: Date,
    end: Date
  },
  region: {
    bounds: mongoose.Schema.Types.Mixed
  },
  format: { type: String, enum: ['json', 'csv', 'geojson'], default: 'json' },
  status: { type: String, enum: ['pending', 'processing', 'completed', 'failed'], default: 'pending' },
  downloadUrl: String,
  createdAt: { type: Date, default: Date.now },
  completedAt: Date
});

// Models
const User = mongoose.model('User', userSchema);
const SavedView = mongoose.model('SavedView', savedViewSchema);
const Annotation = mongoose.model('Annotation', annotationSchema);
const Analytics = mongoose.model('Analytics', analyticsSchema);
const DataRequest = mongoose.model('DataRequest', dataRequestSchema);

// ============ MIDDLEWARE ============

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'deepdive-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, firstName, lastName } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      firstName,
      lastName
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'deepdive-secret-key',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'deepdive-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        preferences: user.preferences
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ USER ROUTES ============

// Get user profile
app.get('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update user profile
app.put('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, preferences } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { firstName, lastName, preferences },
      { new: true }
    ).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ SAVED VIEWS ROUTES ============

// Create saved view
app.post('/api/views', authenticateToken, async (req, res) => {
  try {
    const { title, description, layer, date, coordinates, tags, isPublic } = req.body;
    
    const view = new SavedView({
      userId: req.user.id,
      title,
      description,
      layer,
      date,
      coordinates,
      tags,
      isPublic
    });

    await view.save();
    res.status(201).json(view);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user's saved views
app.get('/api/views', authenticateToken, async (req, res) => {
  try {
    const views = await SavedView.find({ userId: req.user.id })
      .sort({ createdAt: -1 });
    res.json(views);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get public views
app.get('/api/views/public', async (req, res) => {
  try {
    const { tag, layer, limit = 20 } = req.query;
    const query = { isPublic: true };
    
    if (tag) query.tags = tag;
    if (layer) query.layer = layer;

    const views = await SavedView.find(query)
      .populate('userId', 'username avatar')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));
    
    res.json(views);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get single view
app.get('/api/views/:id', async (req, res) => {
  try {
    const view = await SavedView.findById(req.params.id)
      .populate('userId', 'username avatar');
    
    if (!view) {
      return res.status(404).json({ error: 'View not found' });
    }
    
    res.json(view);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update saved view
app.put('/api/views/:id', authenticateToken, async (req, res) => {
  try {
    const view = await SavedView.findOne({ _id: req.params.id, userId: req.user.id });
    
    if (!view) {
      return res.status(404).json({ error: 'View not found or unauthorized' });
    }

    Object.assign(view, req.body);
    view.updatedAt = new Date();
    await view.save();
    
    res.json(view);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete saved view
app.delete('/api/views/:id', authenticateToken, async (req, res) => {
  try {
    const view = await SavedView.findOneAndDelete({ 
      _id: req.params.id, 
      userId: req.user.id 
    });
    
    if (!view) {
      return res.status(404).json({ error: 'View not found or unauthorized' });
    }
    
    res.json({ message: 'View deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Like/Unlike view
app.post('/api/views/:id/like', authenticateToken, async (req, res) => {
  try {
    const view = await SavedView.findById(req.params.id);
    
    if (!view) {
      return res.status(404).json({ error: 'View not found' });
    }

    const likeIndex = view.likes.indexOf(req.user.id);
    
    if (likeIndex > -1) {
      view.likes.splice(likeIndex, 1);
    } else {
      view.likes.push(req.user.id);
    }
    
    await view.save();
    res.json({ likes: view.likes.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ ANNOTATIONS ROUTES ============

// Create annotation
app.post('/api/annotations', authenticateToken, async (req, res) => {
  try {
    const annotation = new Annotation({
      userId: req.user.id,
      ...req.body
    });
    
    await annotation.save();
    res.status(201).json(annotation);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get annotations for view
app.get('/api/annotations', authenticateToken, async (req, res) => {
  try {
    const { viewId, layer, date } = req.query;
    const query = { userId: req.user.id };
    
    if (viewId) query.viewId = viewId;
    if (layer) query.layer = layer;
    if (date) query.date = date;

    const annotations = await Annotation.find(query)
      .sort({ createdAt: -1 });
    
    res.json(annotations);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ ANALYTICS ROUTES ============

// Track event
app.post('/api/analytics/track', async (req, res) => {
  try {
    const { userId, eventType, layer, date, sessionId, metadata } = req.body;
    
    const event = new Analytics({
      userId,
      eventType,
      layer,
      date,
      sessionId,
      metadata
    });
    
    await event.save();
    res.status(201).json({ message: 'Event tracked' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get analytics dashboard
app.get('/api/analytics/dashboard', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const query = {};
    
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = new Date(startDate);
      if (endDate) query.timestamp.$lte = new Date(endDate);
    }

    // Get aggregated data
    const totalEvents = await Analytics.countDocuments(query);
    
    const layerStats = await Analytics.aggregate([
      { $match: query },
      { $group: { _id: '$layer', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    const eventTypeStats = await Analytics.aggregate([
      { $match: query },
      { $group: { _id: '$eventType', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    res.json({
      totalEvents,
      layerStats,
      eventTypeStats
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ DATA REQUEST ROUTES ============

// Create data request
app.post('/api/data-requests', authenticateToken, async (req, res) => {
  try {
    const dataRequest = new DataRequest({
      userId: req.user.id,
      ...req.body
    });
    
    await dataRequest.save();
    
    // Trigger async processing (in production, use queue like Bull/Redis)
    processDataRequest(dataRequest._id);
    
    res.status(201).json(dataRequest);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user's data requests
app.get('/api/data-requests', authenticateToken, async (req, res) => {
  try {
    const requests = await DataRequest.find({ userId: req.user.id })
      .sort({ createdAt: -1 });
    res.json(requests);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mock data processing function
async function processDataRequest(requestId) {
  // Simulate async processing
  setTimeout(async () => {
    try {
      const request = await DataRequest.findById(requestId);
      if (request) {
        request.status = 'completed';
        request.downloadUrl = `/api/downloads/${requestId}`;
        request.completedAt = new Date();
        await request.save();
      }
    } catch (error) {
      console.error('Error processing data request:', error);
    }
  }, 5000);
}

// ============ SEARCH ROUTES ============

// Search views
app.get('/api/search', async (req, res) => {
  try {
    const { q, layer, tags } = req.query;
    const query = { isPublic: true };

    if (q) {
      query.$or = [
        { title: { $regex: q, $options: 'i' } },
        { description: { $regex: q, $options: 'i' } }
      ];
    }

    if (layer) query.layer = layer;
    if (tags) query.tags = { $in: tags.split(',') };

    const results = await SavedView.find(query)
      .populate('userId', 'username avatar')
      .limit(50);

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ STATS ROUTES ============

// Get platform statistics
app.get('/api/stats', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalViews = await SavedView.countDocuments();
    const publicViews = await SavedView.countDocuments({ isPublic: true });
    const totalAnnotations = await Annotation.countDocuments();

    res.json({
      totalUsers,
      totalViews,
      publicViews,
      totalAnnotations
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ HEALTH CHECK ============

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// ============ START SERVER ============

app.listen(PORT, () => {
  console.log(`🚀 Deep Dive Backend Server running on port ${PORT}`);
  console.log(`📊 MongoDB connection: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Connecting...'}`);
});

module.exports = app;
