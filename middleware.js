// Deep Dive - Enhanced Middleware and Utilities

const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const { body, validationResult } = require('express-validator');

// ============ Security Middleware ============

// Helmet for security headers
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "https://gibs.earthdata.nasa.gov"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
});

// ============ Rate Limiting ============

// General rate limiter
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

// Auth rate limiter (stricter)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts, please try again later' },
  skipSuccessfulRequests: true
});

// API rate limiter for public endpoints
const publicApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Rate limit exceeded for public API' }
});

// ============ Validation Middleware ============

// Validation error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: errors.array() 
    });
  }
  next();
};

// User registration validation
const validateRegistration = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores, and hyphens'),
  body('email')
    .trim()
    .isEmail()
    .withMessage('Invalid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),
  body('firstName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('First name too long'),
  body('lastName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Last name too long'),
  handleValidationErrors
];

// Login validation
const validateLogin = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Invalid email address'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors
];

// Saved view validation
const validateSavedView = [
  body('title')
    .trim()
    .notEmpty()
    .withMessage('Title is required')
    .isLength({ max: 200 })
    .withMessage('Title too long'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Description too long'),
  body('layer')
    .isIn(['heat', 'coral', 'clouds'])
    .withMessage('Invalid layer type'),
  body('date')
    .notEmpty()
    .withMessage('Date is required'),
  body('coordinates.lat')
    .isFloat({ min: -90, max: 90 })
    .withMessage('Invalid latitude'),
  body('coordinates.lng')
    .isFloat({ min: -180, max: 180 })
    .withMessage('Invalid longitude'),
  body('coordinates.zoom')
    .isInt({ min: 1, max: 20 })
    .withMessage('Invalid zoom level'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
  body('isPublic')
    .optional()
    .isBoolean()
    .withMessage('isPublic must be boolean'),
  handleValidationErrors
];

// Annotation validation
const validateAnnotation = [
  body('layer')
    .isIn(['heat', 'coral', 'clouds'])
    .withMessage('Invalid layer type'),
  body('coordinates.lat')
    .isFloat({ min: -90, max: 90 })
    .withMessage('Invalid latitude'),
  body('coordinates.lng')
    .isFloat({ min: -180, max: 180 })
    .withMessage('Invalid longitude'),
  body('content')
    .trim()
    .notEmpty()
    .withMessage('Content is required')
    .isLength({ max: 2000 })
    .withMessage('Content too long'),
  body('type')
    .optional()
    .isIn(['note', 'observation', 'alert'])
    .withMessage('Invalid annotation type'),
  handleValidationErrors
];

// ============ Error Handling Middleware ============

// 404 Handler
const notFoundHandler = (req, res, next) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method
  });
};

// Global error handler
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation error',
      details: Object.values(err.errors).map(e => e.message)
    });
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    return res.status(409).json({
      error: 'Resource already exists',
      field: Object.keys(err.keyPattern)[0]
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid token' });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'Token expired' });
  }

  // Default error
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

// ============ Logging Middleware ============

// Request logger
const requestLogger = morgan('combined', {
  skip: (req, res) => res.statusCode < 400
});

// ============ CORS Configuration ============

const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',')
      : ['http://localhost:3000', 'http://localhost:8080'];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};

// ============ Authorization Middleware ============

// Check if user is admin
const requireAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Admin access required' });
  }
};

// Check if user is researcher or admin
const requireResearcher = (req, res, next) => {
  if (req.user && ['researcher', 'admin'].includes(req.user.role)) {
    next();
  } else {
    res.status(403).json({ error: 'Researcher access required' });
  }
};

// ============ Caching Middleware ============

const NodeCache = require('node-cache');
const cache = new NodeCache({ stdTTL: 600 }); // 10 minutes default

const cacheMiddleware = (duration = 600) => {
  return (req, res, next) => {
    if (req.method !== 'GET') {
      return next();
    }

    const key = req.originalUrl;
    const cachedResponse = cache.get(key);

    if (cachedResponse) {
      return res.json(cachedResponse);
    }

    res.originalJson = res.json;
    res.json = (body) => {
      cache.set(key, body, duration);
      res.originalJson(body);
    };

    next();
  };
};

// Clear cache for specific pattern
const clearCache = (pattern) => {
  const keys = cache.keys();
  keys.forEach(key => {
    if (key.includes(pattern)) {
      cache.del(key);
    }
  });
};

// ============ Pagination Middleware ============

const paginate = (model) => {
  return async (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    try {
      const total = await model.countDocuments(req.query.filter || {});
      const pages = Math.ceil(total / limit);

      req.pagination = {
        page,
        limit,
        skip,
        total,
        pages,
        hasNext: page < pages,
        hasPrev: page > 1
      };

      next();
    } catch (error) {
      next(error);
    }
  };
};

// ============ Sanitization Utilities ============

const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return input
      .trim()
      .replace(/[<>]/g, '') // Remove potential XSS
      .substring(0, 10000); // Limit length
  }
  return input;
};

const sanitizeObject = (obj) => {
  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeObject(value);
    } else {
      sanitized[key] = sanitizeInput(value);
    }
  }
  return sanitized;
};

// ============ Analytics Helper ============

const trackAnalytics = async (req, eventType, metadata = {}) => {
  try {
    const Analytics = require('./models').Analytics;
    
    await Analytics.create({
      userId: req.user?.id,
      eventType,
      sessionId: req.sessionID || req.headers['x-session-id'],
      metadata: {
        userAgent: req.headers['user-agent'],
        ip: req.ip,
        ...metadata
      }
    });
  } catch (error) {
    console.error('Analytics tracking failed:', error);
  }
};

// ============ Export All ============

module.exports = {
  // Security
  securityHeaders,
  corsOptions,
  
  // Rate limiting
  generalLimiter,
  authLimiter,
  publicApiLimiter,
  
  // Validation
  validateRegistration,
  validateLogin,
  validateSavedView,
  validateAnnotation,
  handleValidationErrors,
  
  // Error handling
  notFoundHandler,
  errorHandler,
  
  // Logging
  requestLogger,
  
  // Authorization
  requireAdmin,
  requireResearcher,
  
  // Caching
  cacheMiddleware,
  clearCache,
  cache,
  
  // Pagination
  paginate,
  
  // Utilities
  sanitizeInput,
  sanitizeObject,
  trackAnalytics,
  
  // Compression
  compression: compression()
};
