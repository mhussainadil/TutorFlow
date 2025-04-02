const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/tutorflow');

const OTPSchema = new mongoose.Schema({
  email: String,
  code: String,
  expiresAt: Date
});

const OTP = mongoose.model('OTP', OTPSchema);
module.exports=OTP;