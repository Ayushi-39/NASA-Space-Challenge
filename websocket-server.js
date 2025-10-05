// Deep Dive - WebSocket Server for Real-time Features
// Add this to your main server.js or as a separate module

const socketIO = require('socket.io');

function initializeWebSocket(server) {
  const io = socketIO(server, {
    cors: {
      origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
      methods: ['GET', 'POST'],
      credentials: true
    }
  });

  // Store active users and rooms
  const activeUsers = new Map();
  const rooms = new Map();

  // Middleware for socket authentication
  io.use(async (socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
      return next(new Error('Authentication required'));
    }

    try {
      const jwt = require('jsonwebtoken');
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'deepdive-secret-key');
      socket.userId = decoded.id;
      socket.username = decoded.username;
      next();
    } catch (error) {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    console.log(`User connected: ${socket.username} (${socket.userId})`);

    // Store user info
    activeUsers.set(socket.id, {
      userId: socket.userId,
      username: socket.username,
      socketId: socket.id,
      connectedAt: new Date()
    });

    // Emit active users count
    io.emit('activeUsers', activeUsers.size);

    // ============ Collaborative View Session ============

    // Join a shared view session
    socket.on('joinView', (data) => {
      const { viewId, currentState } = data;
      
      socket.join(`view:${viewId}`);
      
      // Initialize room if not exists
      if (!rooms.has(viewId)) {
        rooms.set(viewId, {
          users: new Set(),
          cursors: new Map(),
          state: currentState || {}
        });
      }

      const room = rooms.get(viewId);
      room.users.add(socket.id);

      // Notify others in the room
      socket.to(`view:${viewId}`).emit('userJoined', {
        userId: socket.userId,
        username: socket.username,
        timestamp: new Date()
      });

      // Send current room state to new user
      socket.emit('roomState', {
        users: Array.from(room.users).map(id => activeUsers.get(id)),
        cursors: Array.from(room.cursors.entries()),
        state: room.state
      });

      console.log(`${socket.username} joined view ${viewId}`);
    });

    // Leave view session
    socket.on('leaveView', (viewId) => {
      socket.leave(`view:${viewId}`);
      
      if (rooms.has(viewId)) {
        const room = rooms.get(viewId);
        room.users.delete(socket.id);
        room.cursors.delete(socket.id);

        socket.to(`view:${viewId}`).emit('userLeft', {
          userId: socket.userId,
          username: socket.username,
          timestamp: new Date()
        });

        // Clean up empty rooms
        if (room.users.size === 0) {
          rooms.delete(viewId);
        }
      }

      console.log(`${socket.username} left view ${viewId}`);
    });

    // ============ Real-time Map Synchronization ============

    // Share map state changes
    socket.on('mapStateChange', (data) => {
      const { viewId, state } = data;
      
      if (rooms.has(viewId)) {
        const room = rooms.get(viewId);
        room.state = { ...room.state, ...state };
      }

      // Broadcast to others in the view
      socket.to(`view:${viewId}`).emit('mapStateUpdated', {
        userId: socket.userId,
        username: socket.username,
        state,
        timestamp: new Date()
      });
    });

    // Share cursor position
    socket.on('cursorMove', (data) => {
      const { viewId, position } = data;
      
      if (rooms.has(viewId)) {
        const room = rooms.get(viewId);
        room.cursors.set(socket.id, {
          userId: socket.userId,
          username: socket.username,
          position,
          color: getUserColor(socket.userId)
        });
      }

      socket.to(`view:${viewId}`).emit('cursorMoved', {
        userId: socket.userId,
        username: socket.username,
        position,
        color: getUserColor(socket.userId)
      });
    });

    // ============ Live Annotations ============

    // Create annotation in real-time
    socket.on('createAnnotation', async (data) => {
      const { viewId, annotation } = data;

      try {
        // Save to database
        const Annotation = require('./models').Annotation;
        const newAnnotation = await Annotation.create({
          userId: socket.userId,
          viewId,
          ...annotation
        });

        // Broadcast to all users in the view
        io.to(`view:${viewId}`).emit('annotationCreated', {
          annotation: newAnnotation,
          creator: socket.username,
          timestamp: new Date()
        });
      } catch (error) {
        socket.emit('error', { message: 'Failed to create annotation' });
      }
    });

    // Update annotation
    socket.on('updateAnnotation', async (data) => {
      const { viewId, annotationId, updates } = data;

      try {
        const Annotation = require('./models').Annotation;
        const annotation = await Annotation.findByIdAndUpdate(
          annotationId,
          updates,
          { new: true }
        );

        io.to(`view:${viewId}`).emit('annotationUpdated', {
          annotation,
          updatedBy: socket.username,
          timestamp: new Date()
        });
      } catch (error) {
        socket.emit('error', { message: 'Failed to update annotation' });
      }
    });

    // Delete annotation
    socket.on('deleteAnnotation', async (data) => {
      const { viewId, annotationId } = data;

      try {
        const Annotation = require('./models').Annotation;
        await Annotation.findByIdAndDelete(annotationId);

        io.to(`view:${viewId}`).emit('annotationDeleted', {
          annotationId,
          deletedBy: socket.username,
          timestamp: new Date()
        });
      } catch (error) {
        socket.emit('error', { message: 'Failed to delete annotation' });
      }
    });

    // ============ Live Chat ============

    // Send message to view participants
    socket.on('sendMessage', (data) => {
      const { viewId, message } = data;

      const chatMessage = {
        id: generateId(),
        userId: socket.userId,
        username: socket.username,
        message,
        timestamp: new Date()
      };

      io.to(`view:${viewId}`).emit('messageReceived', chatMessage);
    });

    // Typing indicator
    socket.on('typing', (data) => {
      const { viewId, isTyping } = data;

      socket.to(`view:${viewId}`).emit('userTyping', {
        userId: socket.userId,
        username: socket.username,
        isTyping
      });
    });

    // ============ Notifications ============

    // Subscribe to notifications
    socket.on('subscribeNotifications', () => {
      socket.join(`user:${socket.userId}`);
    });

    // Send notification to specific user
    socket.on('sendNotification', async (data) => {
      const { recipientId, type, title, message, link } = data;

      const notification = {
        id: generateId(),
        type,
        title,
        message,
        link,
        senderId: socket.userId,
        senderName: socket.username,
        timestamp: new Date(),
        read: false
      };

      // Save to database
      try {
        const Notification = require('./models').Notification;
        await Notification.create({
          userId: recipientId,
          ...notification
        });

        // Send to recipient if online
        io.to(`user:${recipientId}`).emit('notification', notification);
      } catch (error) {
        console.error('Notification error:', error);
      }
    });

    // ============ Layer Updates ============

    // Broadcast layer change to followers
    socket.on('layerChanged', (data) => {
      const { viewId, layer } = data;

      socket.to(`view:${viewId}`).emit('layerChanged', {
        userId: socket.userId,
        username: socket.username,
        layer,
        timestamp: new Date()
      });
    });

    // Broadcast time slider change
    socket.on('timeChanged', (data) => {
      const { viewId, date } = data;

      socket.to(`view:${viewId}`).emit('timeChanged', {
        userId: socket.userId,
        username: socket.username,
        date,
        timestamp: new Date()
      });
    });

    // ============ Presence & Status ============

    // Update user status
    socket.on('updateStatus', (status) => {
      if (activeUsers.has(socket.id)) {
        const user = activeUsers.get(socket.id);
        user.status = status;
        activeUsers.set(socket.id, user);
      }

      // Broadcast to all connected users
      io.emit('userStatusChanged', {
        userId: socket.userId,
        username: socket.username,
        status
      });
    });

    // Get list of online users
    socket.on('getOnlineUsers', (callback) => {
      const users = Array.from(activeUsers.values());
      callback(users);
    });

    // ============ Data Streaming ============

    // Stream real-time data updates (e.g., from external APIs)
    socket.on('subscribeDataStream', (data) => {
      const { layer, region } = data;
      const streamId = `stream:${layer}:${region}`;
      socket.join(streamId);
      
      console.log(`${socket.username} subscribed to ${streamId}`);
    });

    socket.on('unsubscribeDataStream', (data) => {
      const { layer, region } = data;
      const streamId = `stream:${layer}:${region}`;
      socket.leave(streamId);
    });

    // ============ Disconnect Handling ============

    socket.on('disconnect', (reason) => {
      console.log(`User disconnected: ${socket.username} - ${reason}`);

      // Remove from active users
      activeUsers.delete(socket.id);

      // Remove from all rooms
      rooms.forEach((room, viewId) => {
        if (room.users.has(socket.id)) {
          room.users.delete(socket.id);
          room.cursors.delete(socket.id);

          socket.to(`view:${viewId}`).emit('userLeft', {
            userId: socket.userId,
            username: socket.username,
            timestamp: new Date()
          });

          // Clean up empty rooms
          if (room.users.size === 0) {
            rooms.delete(viewId);
          }
        }
      });

      // Update active users count
      io.emit('activeUsers', activeUsers.size);
    });

    // Error handling
    socket.on('error', (error) => {
      console.error('Socket error:', error);
      socket.emit('error', { message: 'An error occurred' });
    });
  });

  // ============ Helper Functions ============

  function getUserColor(userId) {
    const colors = [
      '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A',
      '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2'
    ];
    const index = parseInt(userId.slice(-2), 16) % colors.length;
    return colors[index];
  }

  function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
  }

  // ============ Background Jobs ============

  // Periodically clean up inactive rooms
  setInterval(() => {
    const now = Date.now();
    rooms.forEach((room, viewId) => {
      if (room.users.size === 0) {
        rooms.delete(viewId);
      }
    });
  }, 5 * 60 * 1000); // Every 5 minutes

  // Broadcast system-wide updates
  function broadcastUpdate(event, data) {
    io.emit(event, data);
  }

  // Broadcast to specific view
  function broadcastToView(viewId, event, data) {
    io.to(`view:${viewId}`).emit(event, data);
  }

  // Send to specific user
  function sendToUser(userId, event, data) {
    io.to(`user:${userId}`).emit(event, data);
  }

  return {
    io,
    broadcastUpdate,
    broadcastToView,
    sendToUser,
    getActiveUsers: () => Array.from(activeUsers.values()),
    getRooms: () => Array.from(rooms.entries())
  };
}

module.exports = { initializeWebSocket };
