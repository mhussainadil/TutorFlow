const mongoose = require('mongoose');


const OTPSchema = new mongoose.Schema({
  email: String,
  code: String,
  expiresAt: Date
});

const OTP = mongoose.model('OTP', OTPSchema);
module.exports=OTP;