
const mongoose = require('mongoose');

// models/Notification.js
const notificationSchema = new mongoose.Schema({
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    
    refPath: 'recipientModel'
  },
  recipientModel: {
    type: String,
    
    enum: ['Student', 'Faculty']
  },
  student: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  faculty: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'FacultyDetail',
    required: true
  },
  message: {
    type: String,
    required: true
  },
  relatedAppointment: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AppointmentRequest'
  },
  read: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});
notificationSchema.index({ recipient: 1, recipientModel: 1, read: 1 });
notificationSchema.index({ createdAt: -1 });
module.exports = mongoose.model('Notification', notificationSchema);