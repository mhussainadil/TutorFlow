const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/tutorflow');


const facultySchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  department: { type: String, required: true },
  subjects: [{ type: String }],
  photo: { type: String },
  status: {
    type: String,
    enum: ['available', 'busy', 'unavailable'],
    default: 'available'
  }, settings: {
    language: { type: String, default: 'en' },
  },
  availableSlots: {
    type: [String], // Ensure this is an array of strings
    default: []
  },
   appointments: [{
    studentId: mongoose.Schema.Types.ObjectId,
    date: Date,
    time: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'] }
  }],
  createdAt: { type: Date, default: Date.now }
});
const FacultyDetail = mongoose.model("FacultyDetail", facultySchema);
module.exports = FacultyDetail;