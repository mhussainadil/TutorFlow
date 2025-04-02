const mongoose = require('mongoose');



const appointmentSchema = new mongoose.Schema({
    date: Date,
    teacher: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['pending', 'confirmed', 'cancelled'], default: 'pending' }
  });

const Appointment=mongoose.model("Appointment",appointmentSchema);
module.exports=Appointment;