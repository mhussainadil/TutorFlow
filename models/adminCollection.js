const mongoose = require('mongoose');

const AdminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  settings: {
    language: { type: String, default: 'en' },
    theme: { type: String, default: 'light' },
    notifications: {
        email: Boolean,
        sms: Boolean,
        push: Boolean
    }
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

const Admin = mongoose.model('Admin', AdminSchema);
module.exports = Admin;
