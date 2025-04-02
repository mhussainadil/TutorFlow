const mongoose = require('mongoose');

const appointmentRequestSchema = new mongoose.Schema({
  // Reference IDs (should come from server-side)
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
  
  // Embedded student details (from hidden inputs)
  studentDetails: {
    fullName: {
      type: String,
      // required: true
    },
    rollNo: {
      type: String,
      // required: true
    },
    department: {
      type: String,
      // required: true
      
    }
  },
  
  // Embedded faculty details (from hidden inputs)
  facultyDetails: {
    name: {
      type: String,
      // required: true
    },
    department: {
      type: String,
      // required: true
    },
    subjects: [{
      type: String
    }]
  },

  // Appointment details
  date: {
    type: Date,
    required: true
  },
  time: {
    type: String,
    required: true
  },
  message: {
    type: String,
    default: ''
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'completed'],
    default: 'pending'
  },
  reminderSent: {
    type: Boolean,
    default: false
  },
  completedAt: Date,
  // Audit fields
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes
appointmentRequestSchema.index({ faculty: 1, status: 1 });
appointmentRequestSchema.index({ student: 1, status: 1 });
appointmentRequestSchema.index({ 'studentDetails.rollNo': 1 });
appointmentRequestSchema.index({ 'facultyDetails.name': 1 });

const AppointmentRequest = mongoose.model('AppointmentRequest', appointmentRequestSchema);
module.exports = AppointmentRequest;