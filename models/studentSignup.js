
const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  fullName: String,
  rollNo: { type: String, unique: true },
  department: String,
  yearOfStudy: String,
  semester: String,
  email: { type: String, unique: true },
  password: String,
  profilePhoto: { 
    type: String, 
    default: '../uploads/default-avatar.jpg' 
  },
  isVerified: { type: Boolean, default: false },
  appointments: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Appointment' 
  }],
  settings: {
    language: { type: String, default: 'en' },
},
preferences: {
  language: {
      type: String,
      default: 'en',
      enum: ['en', 'es', 'fr'] // your supported languages
  },
  theme: {
      type: String,
      default: 'light',
      enum: ['light', 'dark']
  }
}
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
module.exports=User;


