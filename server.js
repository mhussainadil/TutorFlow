const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const app = express();
const MongoStore = require('connect-mongo');
const methodOverride=require("method-override");
app.use(methodOverride("_method"));
mongoose.connect('mongodb://localhost:27017/tutorflow');
const i18n = require('i18n');
const path = require("path");
const cron = require('node-cron');
// const http = require('http').createServer(app);
// const io = require('socket.io')(http);
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB Connected Successfully! '))
.catch(err => console.error('MongoDB Connection Failed:', err));

const server = http.createServer(app);
const io = new Server(server);


const flash = require('express-flash');
app.use(flash());
app.use(session({
  secret: 'your-secret-key',
  resave: true,  
  saveUninitialized: false,  
  store: MongoStore.create({
    client: mongoose.connection.getClient(),
    ttl: 14 * 24 * 60 * 60,
    touchAfter: 24 * 3600 // Reduce session touching frequency
  }),
  cookie: { 
    secure: false,
    maxAge: 14 * 24 * 60 * 60 * 1000 
  }
}));



const sessionMiddleware = session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({
    client: mongoose.connection.getClient(),
    ttl: 14 * 24 * 60 * 60
  }),
  cookie: { secure: false }
});
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});
// Socket.IO Implementation
const userSocketMap = new Map(); // Track connected users


const userSockets = {}; // Store studentId -> socketId mapping

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('register', (studentId) => {
      userSocketMap.set(studentId, socket.id); // Use Map instead of object
      console.log(`User ${studentId} registered with socket ${socket.id}`);
    });
    
    // Update getSocketId function
    const getSocketId = (userId) => {
      return userSocketMap.get(userId.toString());
    };

    socket.on('disconnect', () => {
      // Remove user from userSocketMap
      userSocketMap.forEach((value, key) => {
        if (value === socket.id) {
          userSocketMap.delete(key);
        }
      });
      console.log(`User disconnected: ${socket.id}`);
    });
});


// Database Connections`
const User = require("./models/studentSignup");
const OTP = require("./models/otp"); // Ensure you have OTP model
const appointments = require("./models/appointment");
const Admin = require("./models/adminCollection");
const faculty = require("./models/facultycollection");
const appointmentRequests = require("./models/appointmentRequestsCollection");
const Notification = require('./models/Notification');
mongoose.connection.once("open", async () => {
  console.log("MongoDB Connected!");

  // Create indexes (run once)
  try {
    await User.collection.createIndex({ fullName: "text", rollNo: 1 });
    console.log("Indexes created!");
  } catch (err) {
    console.error("Error creating index:", err);
  }
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json())
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));
app.set('view engine', 'ejs');
app.use(express.static('public'));
// Make io accessible in routes
app.use((req, res, next) => {
  req.io = io;
  next();
});

// Configure i18n
i18n.configure({
  locales: ['en', 'fr', 'es', 'hi'],
  directory: path.join(__dirname, 'locales'), // Translation files will be stored here
  defaultLocale: 'en',
  cookie: 'lang',
  queryParameter: 'lang',
  autoReload: true,
  syncFiles: true
});

// Middleware for i18n
app.use(i18n.init);

// Middleware to set language from session
app.use((req, res, next) => {
  if (req.session.language) {
    req.setLocale(req.session.language);
  }
  next();
});
// Middleware to inject settings into all views
app.use(async (req, res, next) => {
  if (req.user) {
      res.locals.settings = {
          language: req.user.preferences.language,
          theme: req.user.preferences.theme
      };
  } else {
      res.locals.settings = {
          language: req.session.language || 'en',
          theme: req.session.theme || 'light'
      };
  }
  next();
});
// Multer Configuration
const multer = require('multer');
app.use('/uploads', express.static('uploads'));
// Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mhussainadil07@gmail.com',
    pass: 'dsvzxlflnpooqfqe'
  }
});
//middleware to verify session state before password reset
const validatePasswordResetSession = (req, res, next) => {
  if (!req.session.resetEmail || !req.session.passwordResetVerified) {
    return res.redirect('/forgot-password');
  }
  next();
};



app.get("/adminLogin", (req, res) => {
  res.render("adminlogin");
})
app.get("/adminHomepage", async (req, res) => {
  if (!req.session.admin) {
    return res.render("/adminLogin");
  }
  const facultyCount = await faculty.countDocuments();
  const studentCount = await User.countDocuments();

  res.render("adminHomepage", { fcount: facultyCount, scount: studentCount });
})
app.post('/adminHomepage', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find admin by username
    const admin = await Admin.findOne({ username });
    if (!admin) {
      return res.render('adminlogin', { error: 'Invalid credentials' });
    }

    const facultyCount = await faculty.countDocuments();
    const studentCount = await User.countDocuments();

    // Compare hashed password
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.render('adminlogin', { error: 'Incorrect Password !' });
    }

    // Set admin session
    req.session.admin = true;
    res.render('adminHomepage', { admin: req.session.admin, fcount: facultyCount, scount: studentCount });
  } catch (error) {
    console.error('Admin Login Error:', error);
    res.render('adminlogin', { error: 'Login failed. Please try again.' });
  }
});



const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, './uploads'));
  },

  filename: (req, file, cb) => {
    cb(null, `Userimage-${Date.now()}${path.extname(file.originalname)}`);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

    if (mimetype && extname) return cb(null, true);
    cb('Error: Images only!');
  }
});


app.get("/Mstudents", async (req, res) => {
  if (!req.session.admin) { return res.render("adminlogin") };
  let studentslist = await User.find();
  // console.log(facultylist);
  res.render("adminManagestudents", { allstudents: studentslist, });
})

//  endpoint to handle language updates
app.post('/update-language', async (req, res) => {
  try {
    // Get user from session
    const user = await User.findById(req.session.userId);

    // Update user's language preference
    user.languagePreference = req.body.language;
    await user.save();

    res.sendStatus(200);
  } catch (error) {
    console.error('Error updating language:', error);
    res.status(500).json({ error: 'Failed to update language' });
  }
});

// GET Student Settings Page
app.get('/settings', async (req, res) => {
  try {
    console.log(req.session.user._id)
    const student = await User.findById(req.session.user._id)
      .select('settings fullName email')
      .lean();

    if (!student) {
      return res.status(404).send('Student not found');
    }
    res.render('settings', {
      currentPage: 'settings',
      student: {
        name: student.fullName,
        email: student.email,

      },
      settings: student.settings || { language: 'en' },
      availableLanguages: [
        { code: 'en', name: 'English' },
        { code: 'es', name: 'Español' },
        { code: 'fr', name: 'Français' },
        { code: 'de', name: 'Deutsch' }
      ], user: student
    });

  } catch (error) {
    console.error('Settings error:', error);
    res.status(500).send('Error loading settings');
  }
});


//get settings faculty page

app.get('/fsettings', async (req, res) => {
  try {


    const email=req.session.user.email;
    const fac = await faculty.findOne({ email }).select('+password');

const notifications=await Notification.find({});
    const appointmentlist = await appointmentRequests.find({ faculty: fac._id })
      .sort({ createdAt: -1 })
      .select('settings fullName email')
      .lean();
      const unreadCount = await Notification.countDocuments({
        $or: [
         
          { faculty: fac._id }
        ],
        read: false
      });
    console.log(req.session.user._id)


    if (!fac) {
      return res.status(404).send('faculty not found');
    }
    res.render('fsettings', {
      currentPage: 'settings',
      user: {
        ...fac.toObject(),
        status: fac.status || 'available',
        subjects: fac.subjects || [],
        department: fac.department || 'Not specified'
      },
      faculty: {
        name: fac.name,
        email: fac.email,

      },
      settings: fac.settings || { language: 'en' },
      availableLanguages: [
        { code: 'en', name: 'English' },
        { code: 'es', name: 'Español' },
        { code: 'fr', name: 'Français' },
        { code: 'de', name: 'Deutsch' }
      ], user: fac
    });

  } catch (error) {
    console.error('Settings error:', error);
    res.status(500).send('Error loading settings');
  }
});
// POST Update Language Preference

app.post('/update-student-language', async (req, res) => {
  try {
    const { language } = req.body;

    req.session.language = language; // Store language in session
    res.cookie('lang', language);   // Store language in cookie (optional)

    await User.updateOne(
      { _id: req.session.studentId },
      { $set: { 'settings.language': language } }
    );

    res.json({ success: true, message: 'Language updated successfully' });
  } catch (error) {
    console.error('Language update error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update language'
    });
  }
});


app.post('/update-faculty-language', async (req, res) => {
  try {
    const { language } = req.body;

    req.session.language = language; // Store language in session
    res.cookie('lang', language);   // Store language in cookie (optional)

    await faculty.updateOne(
      { _id: req.session.user._id },
      { $set: { 'settings.language': language } }
    );

    res.json({ success: true, message: 'Language updated successfully' });
  } catch (error) {
    console.error('Language update error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update language'
    });
  }
});

app.get('/ASettings',
  async (req, res) => {
    try {
      user = req.session.admin;
      // Prepare settings data
      const settingsData = {
        language: user.settings?.language || 'en',
        theme: user.settings?.theme || 'light',
        notifications: user.settings?.notifications || {
          email: true,
          sms: false,
          push: false
        },
        twoFAEnabled: user.settings?.twoFAEnabled || false
      };

      // Render settings page with user-specific data
      res.render('Adminsettingspage', {
        title: 'System Settings',

        settings: settingsData,
        availableLanguages: [
          { code: 'en', name: 'English' },
          { code: 'es', name: 'Español (Spanish)' },
          { code: 'fr', name: 'Français (French)' },
          { code: 'de', name: 'Deutsch (German)' }
        ],
        accentColors: [
          { name: 'indigo', value: '#4F46E5' },
          { name: 'purple', value: '#6D28D9' },
          { name: 'pink', value: '#EC4899' }
        ]
      });

    } catch (error) {
      console.error('Settings page error:', error);
      res.status(500).render('error', {
        message: 'Error loading settings page'
      });
    }
  });

  app.post('/Aupdate-language', async (req, res) => {
    try {
      await Admin.findByIdAndUpdate(
          req.session.admin._id,
          { 'preferences.language': req.body.language },
          { new: true }
      );
      req.session.language = req.body.language;
      res.sendStatus(200);
  } catch (error) {
      // Handle error
  }
});
//theme
app.post('/update-theme', async (req, res) => {
  try {
      req.session.theme = req.body.theme;
      await req.session.save();
      res.sendStatus(200);
  } catch (error) {
      console.error('Theme update error:', error);
      res.status(500).json({ error: 'Failed to update theme' });
  }
});
app.get("/searchStudents", async (req, res) => {
  try {
    let { query } = req.query;

    // Search for students whose fullName or rollNo matches the query
    let studentsList = await User.find({
      $or: [
        { fullName: { $regex: query, $options: "i" } }, // Case-insensitive search
        { rollNo: { $regex: query, $options: "i" } },  // Case-insensitive search
        { departmemt: { $regex: query, $options: "i" } }
      ]
    }).sort({ fullName: 1 }); // Sort alphabetically by name

    res.json(studentsList); // Send the results as JSON
  } catch (err) {
    console.error("Search Error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


app.get("/searchFaculty", async (req, res) => {
  try {
    let query = req.query.query;
    let regex = new RegExp(query, "i"); // Case-insensitive search

    let faculties = await faculty.find({
      $or: [
        { name: regex },
        { department: regex },
        { subjects: regex }
      ]
    });

    res.json(faculties);
  } catch (error) {
    console.error("Error searching faculty:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});



app.get("/Mfaculty", async (req, res) => {
  if (!req.session.admin) { return res.render("adminlogin") };
  let facultylist = await faculty.find();
  // console.log(facultylist);
  res.render("adminManagefaculty", { allfaculties: facultylist, });
})


// -------------------------------------------//
// Add Faculty Route
app.post('/admin/faculty/add',
  upload.single('photo'),
  async (req, res) => {
    try {
      const { name, email, password, department, subjects } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);

      const newFaculty = new faculty({
        name,
        email,
        password: hashedPassword,
        department,
        subjects: subjects.split(',').map(s => s.trim()),
        photo: req.file ? req.file.path : 'default-avatar.png'
      });

      await newFaculty.save();
      res.redirect('/Mfaculty?success=Faculty added successfully');
    } catch (error) {
      console.error('Add Faculty Error:', error);
      res.redirect('/Mfaculty?error=Failed to add faculty');
    }
  }
);


// Routes
app.get('/', (req, res) => res.render('landingpage')); // Changed to landing page

// Student Signup Flow
app.get('/signup', (req, res) => res.render('signup', { error: null }));

app.post('/signup', upload.single('profilePhoto'), async (req, res) => {

  // const profilePhoto = req.file ? req.file.path : 'default-avatar.png';

  try {
    // Handle file upload
    let profilePhotoPath = '/uploads/default-avatar.png';
    if (req.file) {
      profilePhotoPath = '/uploads/' + req.file.filename;
    }

    const { fullName, rollNo, department, yearOfStudy, semester, email, password, confirmPassword } = req.body;

    // Validation
    if (password !== confirmPassword) {
      return res.render('signup', { error: 'Passwords do not match' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { rollNo }] });
    if (existingUser) {
      return res.render('signup', { error: 'Email or Roll Number already exists' });
    }

    // Store in session for OTP verification
    req.session.tempUser = {
      fullName,
      rollNo,
      department,
      yearOfStudy,
      semester,
      email,
      password: await bcrypt.hash(password, 10),
      // profilePhoto: req.file ? req.file.path : 'default-avatar.png',
      profilePhoto: profilePhotoPath,
      role: 'student'

    };

    // Generate and send OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000);
    const otp = new OTP({
      email,
      code: otpCode,
      expiresAt: new Date(Date.now() + 5 * 60000)
    });
    await otp.save();

    await transporter.sendMail({
      from: 'TutorFlow <support-tutorflow@gmail.com>',
      to: email,
      subject: 'Email Verification OTP',
      html: `<p>Your OTP is: <strong>${otpCode}</strong></p>`
    });

    res.redirect('/verify?type=signup');
  } catch (error) {
    console.error('Signup Error:', error);
    res.render('signup', { error: 'Registration failed. Please try again.' });
  }
});

// Verification Route
app.get('/verify', (req, res) => {
  const type = req.query.type;
  console.log(type);
  res.render('verify', {
    error: null,
    type: type || 'signup',
    email: req.session.tempUser?.email
  });
});


// Login Routes

app.post('/verify', async (req, res) => {
  try {
    const { code } = req.body;
    const { type } = req.query;

    console.log("Session Data at /verify:", req.session); // Debugging

    // Determine email based on verification type
    let email;
    if (type === 'password_reset') {
      email = req.session.resetEmail;
      if (!email) {
        console.error("Missing reset email in session.");
        return res.redirect('/forgot-password');
      }
    } else if (type === 'signup') {
      const tempUser = req.session.tempUser;
      if (!tempUser) {
        console.error("Missing temp user in session.");
        return res.redirect('/');
      }
      email = tempUser.email;
    } else {
      console.error("Invalid verification type:", type);
      return res.redirect('/');
    }

    // Debugging OTP search
    console.log("Checking OTP for Email:", email, "Entered Code:", code);
    console.log("Stored OTPs:", await OTP.find({ email }));

    // Verify OTP
    const validOTP = await OTP.findOne({
      email,
      code: String(code), // Ensure string comparison
      expiresAt: { $gt: new Date() }
    });

    console.log("Found OTP:", validOTP);

    if (!validOTP) {
      return res.render('verify', {
        error: 'Invalid or expired OTP',
        type,
        email
      });
    }

    // Handle password reset flow
    if (type === 'password_reset') {
      req.session.passwordResetVerified = true;
      await OTP.deleteOne({ _id: validOTP._id });

      req.session.save(err => {
        if (err) {
          console.error('Session save error:', err);
          return res.redirect('/forgot-password');
        }
        res.redirect('/reset-password');
      });
      return;
    }

    // Handle signup flow (create new user)
    const tempUser = req.session.tempUser;
    const user = new User({
      fullName: tempUser.fullName,
      rollNo: tempUser.rollNo,
      email: tempUser.email,
      password: tempUser.password,
      department: tempUser.department,
      yearOfStudy: tempUser.yearOfStudy,
      semester: tempUser.semester,
      isVerified: true,
      appointments: []
    });

    await user.save();
    await OTP.deleteMany({ email: tempUser.email });

    req.session.tempUser = null;
    req.session.user = {
      _id: user._id,
      ...tempUser
    };

    res.redirect('/dashboard');
  } catch (error) {
    console.error('Verification Error:', error);
    res.render('verify', {
      error: 'Verification failed. Please try again.',
      type: req.query.type || 'signup',
      email: req.session.tempUser?.email || req.session.resetEmail
    });
  }
});


app.get('/slogin', (req, res) => res.render('slogin', { error: null }));

app.post('/slogin', async (req, res) => {
  try {
    // const rollNo=req.params.rollNo;
    const rollno = req.body.rollNo;
    const password = req.body.password;
    const user = await User.findOne({ rollNo: rollno });
    // console.log(user);

    if (!user) {
      return res.render('slogin', { error: 'User Not Found!' });
    }
    let checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) {
      return res.render("slogin", { error: 'Incorrect Password !' })
    }
    ///////////////////////
    if (!user.isVerified) {
      return res.render('slogin', { error: 'Account not verified. Check your email!' });
    }

    req.session.user = user;

    // const appointmentsList=await appointments.find();
    const studentID = req.session.user._id;
    const allappointments = await appointmentRequests.find({ student: studentID });
    // console.log(allappointments);
    const notifications = await Notification.find({
      recipient: user._id,
      recipientModel: user.role // Assuming user.role is 'Student' or 'Faculty'
    })  .sort({ createdAt: -1 })
    .limit(5)
    .populate('User  appointmentRequests').populate({
      path: 'faculty',
      model: 'FacultyDetail'
    });

    res.render('dashboard', {
      user: req.session.user,
      appointments: appointments || [], // Pass appointments if needed
      currentPage: 'dashboard',// Required for sidebar
      appointments: allappointments,
      notifications,
      unreadCount: notifications.filter(n => !n.read).length,
      currentDate: new Date().toISOString().split('T')[0],
   
    });
  } catch (error) {
    console.error('Login Error:', error);
    res.render('slogin', { error: 'Login failed. Please try again.' });
  }
});

// app.get("/studviewfaculty", async (req, res) => {
//   try {
//     if (!req.session.user) { return res.redirect("/") }
//     const facultylist = await faculty.find();
    
//     const allappointments = await appointmentRequests.find({ student: studentID });
//     // console.log(allappointments);
//     const notifications = await Notification.find({
//       recipient: user._id,
//       recipientModel: user.role // Assuming user.role is 'Student' or 'Faculty'
//     })  .sort({ createdAt: -1 })
//     .limit(5)
//     .populate('User faculty appointmentRequests');
    
//     res.render("studviewfaculty.ejs", {
//       user: req.session.user,
//       allfaculties: facultylist,
//       currentPage: 'studviewfaculty',// Required for sidebar
    
//       appointments: allappointments,
//       notifications,
//       unreadCount: notifications.filter(n => !n.read).length,
//       currentDate: new Date().toISOString().split('T')[0],
  

     
//     })

//   } catch (e) {

//   }
// })

// Password Reset Flow

app.get("/studviewfaculty", async (req, res) => {
  try {
    if (!req.session.user) return res.redirect("/");
    
    const user = req.session.user;
    const [facultylist, allappointments, notifications] = await Promise.all([
      faculty.find(),
      appointmentRequests.find({ student: user._id }),
      Notification.find({
        recipient: user._id,
        recipientModel: user.role
      })
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('student  relatedAppointment').populate({
        path: 'faculty',
        model: 'FacultyDetail'
      })
    ]);

    res.render("studviewfaculty.ejs", {
      user: user,
      allfaculties: facultylist,
      currentPage: 'studviewfaculty',
      appointments: allappointments,
      notifications: notifications,
      unreadCount: notifications.filter(n => !n.read).length,
      currentDate: new Date().toISOString().split('T')[0]
    });

  } catch (e) {
    console.error("Studviewfaculty Error:", e);
    res.status(500).send("Internal Server Error");
  }
});
app.get('/forgot-password', (req, res) => res.render('forgot-password', { error: null }));

// app.post('/forgot-password', async (req, res) => {
//   try {
//     const { email } = req.body;
//     const user = await User.findOne({ email });

//     if (!user) {
//       return res.render('forgot-password', { error: 'Email not found' });
//     }

//     // Store email in session
//     req.session.resetEmail = email;

//     // Generate and send OTP
//     const otpCode = Math.floor(100000 + Math.random() * 900000);
//     const otp = new OTP({
//       email,
//       code: otpCode,
//       expiresAt: new Date(Date.now() + 5 * 60000)
//     });
//     await otp.save();

//     await transporter.sendMail({
//       from: 'TutorFlow <support-tutorflow@gmail.com>',
//       to: email,
//       subject: 'Password Reset OTP',
//       html: `<p>Your OTP is: <strong>${otpCode}</strong></p>`
//     });

//     res.redirect('/verify?type=password_reset');
//   } catch (error) {
//     console.error('Password Reset Error:', error);
//     res.render('forgot-password', { error: 'Failed to initiate password reset' });
//   }
// });
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.render('forgot-password', { error: 'Email not found' });
    }

    // Store email in session and SAVE IT
    req.session.resetEmail = email;
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.render('forgot-password', { error: 'Failed to initiate password reset' });
      }
      console.log("Session Data at /verify:", req.session);
      // Generate and send OTP
      const otpCode = Math.floor(100000 + Math.random() * 900000);
      const otp = new OTP({
        email,
        code: otpCode,
        expiresAt: new Date(Date.now() + 5 * 60000)
      });

      otp.save().then(() => {
        transporter.sendMail({
          from: 'TutorFlow <support-tutorflow@gmail.com>',
          to: email,
          subject: 'Password Reset OTP',
          html: `<p>Your OTP is: <strong>${otpCode}</strong></p>`
        });

        res.redirect('/verify?type=password_reset');
      });
    });
  } catch (error) {
    console.error('Password Reset Error:', error);
    res.render('forgot-password', { error: 'Failed to initiate password reset' });
  }
});
app.get('/reset-password', validatePasswordResetSession, (req, res) => {

  res.render('reset-password', { error: null });
});

app.post('/reset-password', validatePasswordResetSession, async (req, res) => {
  try {
    const { password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
      return res.render('reset-password', { error: 'Passwords do not match' });
    }

    const user = await User.findOne({ email: req.session.resetEmail });
    if (!user) {
      return res.redirect('/forgot-password');
    }
    console.log("logingg from post /reset-password");
    console.log(user);
    user.password = await bcrypt.hash(password, 10);
    await user.save();

    // Cleanup session
    req.session.resetEmail = null;
    req.session.passwordResetVerified = null;
    req.session.user = user;
    res.redirect("/dashboard");
  } catch (error) {
    console.error('Password Reset Error:', error);
    res.render('reset-password', { error: 'Failed to reset password' });
  }
});

// Dashboard Route
// app.get('/dashboard', (req, res) => {
//   if (!req.session.user) return res.redirect('/login');
//   res.render('dashboard', { user: req.session.user });
// });
// // // Calendar helper function
// function generateCalendar(date) {
//   const calendar = [];
//   const monthStart = new Date(date.getFullYear(), date.getMonth(), 1);
//   const monthEnd = new Date(date.getFullYear(), date.getMonth() + 1, 0);

//   // Generate calendar logic here...
//   return calendar;
// }



app.get('/dashboard', async (req, res) => {
  if (!req.session.user) return res.redirect('/');

  try {
    const user = await User.findById(req.session.user._id)
    const notifications = await Notification.find({
      recipient: user._id,
      recipientModel: user.role // Assuming user.role is 'Student' or 'Faculty'
    })  .sort({ createdAt: -1 })
    .limit(5)
    .populate('student  relatedAppointment').populate({
      path: 'faculty',
      model: 'FacultyDetail'
    });


    // Generate calendar with appointments
    const calendar = generateCalendar(new Date(), user.appointments);
    const studentID = req.session.user._id;
    // const allappointments = await appointmentRequests.find({ student: studentID });
    // const allappointments=await appointmentRequests.find();
    const allappointments = await appointmentRequests.find({
      $or: [{ student: user._id }, { faculty: user._id }]
    })
    .populate([
      {
        path: 'student',
        model: 'User'
      },
      
      { path: 'faculty', model: 'FacultyDetail' },
  
    ])
    res.render('dashboard', {
      user: req.session.user,
      appointments: allappointments,
      calendar,
      notifications,
      unreadCount: notifications.filter(n => !n.read).length,
      currentDate: new Date().toISOString().split('T')[0],
      currentPage: 'dashboard' // This is required for the sidebar

    });
  } catch (error) {
    console.error('Dashboard Error:', error);
    res.redirect('/');
  }
});
app.post('/appointments/:id/confirm', async (req, res) => {
  try {
    const appointment = await appointmentRequests.findById(req.params.id)
      .populate('student').populate({
        path: 'faculty',
        model: 'FacultyDetail'
      });

    // Create student notification
    await Notification.create({
      recipient: appointment.student._id,
      recipientModel: 'Student',
      student: appointment.student._id,
      faculty: appointment.faculty._id,
      message: `Your appointment with ${appointment.faculty.name} on ${appointment.date} was approved`,
      relatedAppointment: appointment._id
    });

    // Create faculty notification
    await Notification.create({
      recipient: appointment.faculty._id,
      recipientModel: 'Faculty',
      student: appointment.student._id,
      faculty: appointment.faculty._id,
      message: `You approved appointment with ${appointment.student.name}`,
      relatedAppointment: appointment._id
    });

    // Update appointment status
    appointment.status = 'Confirmed';
    await appointment.save();

    res.redirect('/f/session');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error confirming appointment');
  }
});

app.post('/notifications/mark-read', async (req, res) => {
  try {
    const user = req.session.user;
    await Notification.updateMany(
      {
        recipient: user._id,
        recipientModel: user.role,
        read: false
      },
      { $set: { read: true } }
    );
    res.sendStatus(200);
  } catch (error) {
    res.status(500).send('Error marking notifications as read');
  }
});
app.get('/notifications/count', async (req, res) => {
  try {
    const user = req.session.user;
    const count = await Notification.countDocuments({
      recipient: user._id,
      recipientModel: user.role,
      read: false
    });
    res.json({ unreadCount: count });
  } catch (error) {
    res.status(500).json({ error: 'Error getting notification count' });
  }
});


app.get('/notifications/stream', async (req, res) => {
  if (!req.session.user) return res.status(401).end();

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const sendNotifications = async () => {
    try {
      const count = await Notification.countDocuments({
        recipient: req.session.user._id,
        recipientModel: req.session.user.role,
        read: false
      });
      
      res.write(`data: ${JSON.stringify({ unreadCount: count })}\n\n`);
    } catch (error) {
      console.error('SSE Error:', error);
    }
  };

  // Send initial data
  await sendNotifications();

  // Update every 15 seconds
  const interval = setInterval(sendNotifications, 15000);

  // Cleanup on close
  req.on('close', () => {
    clearInterval(interval);
    res.end();
  });
});
function generateCalendar(date, appointments) {
  const calendar = [];
  const monthStart = new Date(date.getFullYear(), date.getMonth(), 1);
  const monthEnd = new Date(date.getFullYear(), date.getMonth() + 1, 0);
  const startDay = monthStart.getDay();
  const daysInMonth = monthEnd.getDate();

  // Create array of appointment dates
  const appointmentDates = appointments.map(a =>
    new Date(a.date).toISOString().split('T')[0]
  );

  // Add padding for previous month
  for (let i = 0; i < startDay; i++) {
    const prevDate = new Date(monthStart);
    prevDate.setDate(prevDate.getDate() - (startDay - i));
    calendar.push({
      date: prevDate,
      isCurrentMonth: false,
      hasAppointment: false
    });
  }

  // Add current month days
  for (let day = 1; day <= daysInMonth; day++) {
    const currentDate = new Date(date.getFullYear(), date.getMonth(), day);
    const dateString = currentDate.toISOString().split('T')[0];

    calendar.push({
      date: currentDate,
      isCurrentMonth: true,
      hasAppointment: appointmentDates.includes(dateString)
    });
  }

  // Add padding for next month
  const totalCells = Math.ceil(calendar.length / 7) * 7;
  while (calendar.length < totalCells) {
    const nextDate = new Date(monthEnd);
    nextDate.setDate(nextDate.getDate() + (calendar.length - daysInMonth - startDay + 1));
    calendar.push({
      date: nextDate,
      isCurrentMonth: false,
      hasAppointment: false
    });
  }

  return calendar;
}





// Get Profile Data
app.get('/faculty/profile', async (req, res) => {
  try {
    const faculty = await faculty.findById(req.session.user._id);
    res.render('/f/session', { faculty });
  } catch (error) {
    res.status(500).send(error);
  }
});

// Update Profile Photo
// app.post('/update-photo', upload.single('photo'), async (req, res) => {
//     try {
//         await faculty.findByIdAndUpdate(req.session.user._id, {
//             photo: req.file ? `/uploads/${req.file.filename}` : 'default-avatar.png'
//         });
//         res.redirect('/f/session');
//     } catch (error) {
//         res.status(500).send(error);
//     }
// });

app.post('/update-status', async (req, res) => {
  try {
    const userId = req.session.user?._id;
    if (!userId) return res.status(401).json({ error: "Unauthorized" });
    const statusfrombody = req.body.status;
    console.log(statusfrombody);
    console.log(req.body);
    const facStatus = await faculty.findByIdAndUpdate(
      userId,
      { status: req.body.status },
      { new: true, runValidators: true } // Returns the updated document
    );
    console.log('facStatus...')
    console.log(facStatus)

    if (!facStatus) return res.status(404).json({ error: "User not found" });

    res.json({ success: true }); // Send JSON response instead of redirect
  } catch (error) {
    console.error("Status update error:", error);
    res.status(500).json({ error: "Server error" });
  }
});



// Logout
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get("/flogin", (req, res) => {
  res.render("facultylogin.ejs", { error: null });
})
// app.post("/f/session",async(req,res)=>{
// try{
// const email=req.body.email;
// const password=req.body.password;
// let fac=await faculty.findOne({email:email});
// // console.log(fac);
// if(!fac){return res.render("facultylogin",{error:'User Not Found!'});
// }
// const comparePassword=await bcrypt.compare(password,fac.password);
// if(!comparePassword){return res.render("facultylogin",{error:'Incorrect Password !'})}
// req.session.user=fac;
// const facultyId = req.session.user._id; // Get logged-in faculty's ID
// const appointmentlist=await appointmentRequests.find({ faculty: facultyId })
// .sort({ createdAt: -1 });

// // console.log()
// res.render("facultydashboard",{
//   user:req.session.user,
//   currentPage:'dashboard',
// requests:appointmentlist,
// })
// }catch(error){
//   console.error('Login Error:', error);
//   res.render("facultylogin",{error:'login failed ! try again'});
// }
// })

// Faculty Dashboard Route
app.post("/f/session", async (req, res) => {
  try {
    const { email, password } = req.body;
    const fac = await faculty.findOne({ email }).select('+password');

    if (!fac) return res.render("facultylogin", { error: 'User Not Found!' });
    const unreadCount = await Notification.countDocuments({
      $or: [
        
        { faculty:fac._id }
      ],
      read: false
    });
const notifications=await Notification.find({faculty:fac._id});
    const validPassword = await bcrypt.compare(password, fac.password);
    if (!validPassword) return res.render("facultylogin", { error: 'Incorrect Password!' });

    req.session.user = fac;
    const appointmentlist = await appointmentRequests.find({ faculty: fac._id })
      .sort({ createdAt: -1 })
      .lean();


    // Include faculty profile data in the dashboard render
    res.render("facultydashboard", {
      user: {
        ...fac.toObject(),
        status: fac.status || 'available',
        subjects: fac.subjects || [],
        department: fac.department || 'Not specified'
      },
      currentPage: 'dashboard',
      requests: appointmentlist,
      unreadCount:unreadCount,
      notifications:notifications
    });

  } catch (error) {
    console.error('Login Error:', error);
    res.render("facultylogin", { error: 'Login failed! Try again' });
  }
});
app.post("/f/session", async (req, res) => {
  try {
    const { email, password } = req.body;
    const fac = await faculty.findOne({ email }).select('+password');

    if (!fac) return res.render("facultylogin", { error: 'User Not Found!' });

    const validPassword = await bcrypt.compare(password, fac.password);
    if (!validPassword) return res.render("facultylogin", { error: 'Incorrect Password!' });

    req.session.user = fac;
    const appointmentlist = await appointmentRequests.find({ faculty: fac._id })
      .sort({ createdAt: -1 })
      .lean();



    // Include faculty profile data in the dashboard render
    res.render("facultydashboard", {
      user: {
        ...fac.toObject(),
        status: fac.status || 'available',
        subjects: fac.subjects || [],
        department: fac.department || 'Not specified'
      },
      currentPage: 'dashboard',
      requests: appointmentlist
    });

  } catch (error) {
    console.error('Login Error:', error);
    res.render("facultylogin", { error: 'Login failed! Try again' });
  }
});

// Add middleware to get appointment
const getAppointment = async (req, res, next) => {
  try {
    const appointment = await appointmentRequests.findOne({
      _id: req.params.id,
      faculty: req.session.user._id // Ensure faculty ownership
    });

    if (!appointment) {
      return res.status(404).json({ error: 'Appointment not found' });
    }
    
    req.appointment = appointment;
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
};
const authFaculty = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'faculty') {
    return res.status(403).redirect('/login');
    console.log('non authorized user')
  }
  next();
};
// Reject appointment

app.post('/reject/:id', getAppointment, async (req, res) => {
  try {
    console.log(req.params.id);
    console.log("request for reject")
    if (req.appointment.status !== 'pending') {
      return res.status(400).json({ error: 'Appointment already processed' });
    }

    // Update and save
    const updatedAppointment = await appointmentRequests.findOneAndUpdate(
      { _id: req.params.id },
      { 
        status: 'rejected',
        updatedAt: new Date(),
        rejectedBy: req.session.user._id 
      },
      { new: true }
    );

    // Create rejection notification
    await Notification.create({
      recipient: updatedAppointment.student._id,  // Add recipient
      recipientModel: 'Student',                  // Add recipientModel
      student: updatedAppointment.student._id,
      faculty: req.session.user._id,
      message: `Appointment rejected by ${req.session.user.name}`,
      relatedAppointment: req.appointment._id
    });

    res.redirect('/f/session');
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get("/f/session", async (req, res) => {
  try {
    // const { email, password } =;
    const email=req.session.user.email;
    const fac = await faculty.findOne({ email }).select('+password');

    if (!fac) return res.render("facultylogin", { error: 'User Not Found!' });
const notifications=await Notification.find({_id:fac._id});
    const appointmentlist = await appointmentRequests.find({ faculty: fac._id })
      .sort({ createdAt: -1 })
      .lean();
      const unreadCount = await Notification.countDocuments({
        $or: [
         
          { faculty: fac._id }
        ],
        read: false
      });
    // Include faculty profile data in the dashboard render
    res.render("facultydashboard", {
      user: {
        ...fac.toObject(),
        status: fac.status || 'available',
        subjects: fac.subjects || [],
        department: fac.department || 'Not specified'
      },
      currentPage: 'dashboard',
      requests: appointmentlist,
      unreadCount:unreadCount,
      notifications:notifications
    });

  } catch (error) {
    console.error('Login Error:', error);
    res.render("facultylogin", { error: 'Login failed! Try again' });
  }
});
// For graceful shutdown
process.on('SIGTERM', () => {
  cron.getTasks().forEach(task => task.stop());
  logger.info('Reminder scheduler stopped');
});


// Update Profile Photo (AJAX)
app.post('/update-photo', upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) throw new Error('No file uploaded');

    const updated = await faculty.findByIdAndUpdate(
      req.session.user._id,
      { photo: `/uploads/${req.file.filename}` },
      { new: true, lean: true }
    );

    // Update session data
    req.session.user.photo = updated.photo;

    res.json({
      success: true,
      photo: updated.photo,
      message: 'Profile photo updated successfully'
    });

  } catch (error) {
    console.error('Photo upload error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to update photo'
    });
  }
});
app.post('/notifications/mark-all-read', async (req, res) => {
  try {
    // Get user from session
    const user = req.session.user;
    if (!user) return res.status(401).json({ error: 'Unauthorized' });

    await Notification.updateMany(
      {
        $or: [
          // { student: user._id },
          { faculty: user._id }
        ],
        read: false
      },
      { $set: { read: true } }
    );
    
    res.sendStatus(200);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});


// Update Status (AJAX)
// app.post('/update-status', async (req, res) => {
//   try {
//     const status=req.body.status
//     console.log(status)
//     const validStatuses = ['available', 'busy', 'unavailable'];
//     if (!validStatuses.includes(req.body.status)) {
//       throw new Error('Invalid status value');
//     }

//     const updated = await faculty.findByIdAndUpdate(
//       req.session.user._id,
//       { status: req.body.status },
//       { new: true, lean: true }
//     );
// console.log(updated);
//     // Update session data
//     req.session.user.status = updated.status;

//     res.json({
//       success: true,
//       status: updated.status,
//       message: 'Status updated successfully'
//     });

//   } catch (error) {
//     console.error('Status update error:', error);
//     res.status(400).json({
//       success: false,
//       message: error.message || 'Failed to update status'
//     });
//   }
// });


app.post('/approve/:id', async (req, res) => {
  try {
    // Get user from session
    const user = req.session.user;
    if (!user) return res.status(401).redirect('/flogin');

    // Find and update appointment
    const updatedAppointment = await appointmentRequests.findOneAndUpdate(
      { 
        _id: req.params.id,
        faculty: user._id, // Ensure faculty owns the appointment
        status: 'pending'
      },
      { 
        $set: { 
          status: 'approved',
          updatedAt: new Date()
        } 
      },
      { new: true }
    );

    if (!updatedAppointment) {
      return res.status(404).json({ error: 'Appointment not found or already processed' });
    }
const newNotification = await Notification.create({
  student: updatedAppointment.student,
  faculty: updatedAppointment.faculty,
  message: `Your appointment with ${updatedAppointment.facultyDetails.fullName} has been approved`,
  type: 'appointment',
  relatedAppointment: updatedAppointment._id
});

// Get the student's socket ID (you'll need to manage this in your socket connection setup)
const studentId = updatedAppointment.student.toString();
const unreadCount = await Notification.countDocuments({ 
  student: studentId,
  read: false
});

// Emit to specific student's socket
io.to(
  studentId
).emit('notification', {
  message: newNotification.message,
  unreadCount: unreadCount
});

// Populate the notification using a separate query
const populatedNotification = await Notification.findById(newNotification._id)
  .populate([
    { path: 'student', model: 'User' },
    { path: 'faculty', model: 'FacultyDetail' },
    { path: 'relatedAppointment', model: 'AppointmentRequest' }
  ]);

io.to(updatedAppointment.student._id.toString()).emit('new-notification', {
  message: `Appointment approved with ${user.name}`,
  createdAt: new Date()
});
    res.redirect('/f/session');
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});
// Get notifications


app.get('/notifications', async (req, res) => {
  try {
    const user = req.session.user;
    if (!user) return res.redirect('/login');

    // Convert to ObjectId and validate
    const userId = new mongoose.Types.ObjectId(user._id);

    const notifications = await Notification.find({
      $or: [{ User: userId }, { facultyDetails: userId }]
    })
    .sort('-createdAt')
    .limit(50)
    .populate([
      {
        path: 'student',
        model: 'User'
      },
      
      { path: 'faculty', model: 'FacultyDetail' },
      { path: 'relatedAppointment', model: 'AppointmentRequest' }
    ]);

    const unreadCount = await Notification.countDocuments({
      $or: [{ User: userId }, { facultyDetails: userId }],
      read: false
    });

    res.render('notifications', {
      user,
      notifications,
      unreadCount,
      currentPage: 'notifications'
    });

  } catch (error) {
    console.error('Notifications error:', error);
    req.flash('error', 'Error loading notifications');
    res.redirect('/dashboard');
  }
});
// students profile pic update 
// app.post('/update-profile', upload.single('photo'), async (req, res) => {
//   try {
//     if (req.file) {
//       await User.findByIdAndUpdate(req.session.user._id, {
//         profilePhoto: `/uploads/${req.file.filename}`,
//         fullName: req.body.editedName,
//       });
//     }
//     res.redirect('/dashboard');
//   } catch (error) {
//     console.error('Profile update error:', error);
//     res.redirect('/dashboard');
//   }
// });
app.post('/update-profile', upload.single('photo'), async (req, res) => {
  try {
    const updates = {
      fullName: req.body.editedName // Now properly receiving the edited name
    };

    if (req.file) {
      updates.profilePhoto = `/uploads/${req.file.filename}`;
    }

    await User.findByIdAndUpdate(req.session.user._id, updates);
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Profile update error:', error);
    res.redirect('/dashboard');
  }
});

app.get("/faculty/:id", async (req, res) => {
  try {
    const id = req.params.id;
    
    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).send("Invalid Faculty ID");
    }

    // Find faculty member using the model
    const facultyData = await faculty.findById(id).lean();

    // Check if faculty exists
    if (!facultyData) {
      return res.status(404).send("Faculty not found");
    }
    // Sanitize availableSlots (optional: filter valid time strings)
    const validSlots = facultyData.availableSlots.filter(slot => 
      /\d{1,2}:\d{2} [AP]M/.test(slot)
    );
    res.render("requestAppointments", {
      user: req.session.user,
      teacher: {
        ...facultyData,
        // availableSlots: facultyData.availableSlots || [],
        availableSlots: validSlots 
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

// app.post("/faculty/:id/delete", async(req,res)=>{
// const fac=await faculty.find({
//   _id:req.params.id,
// })
// console.log(fac);
// })
// Edit faculty route
// Edit faculty route
app.put('/admin/faculty/:id', upload.single('photo'), async (req, res) => {
  try {
      const { id } = req.params;
      const facultyData = await faculty.findById(id);
      
      if (!facultyData) {
          return res.status(404).send('Faculty not found');
      }

      const updatedData = {
          name: req.body.name,
          email: req.body.email,
          department: req.body.department,
          subjects: req.body.subjects ? req.body.subjects.split(',').map(s => s.trim()) : [],
          // Handle photo update
          photo: req.file ? `/uploads/${req.file.filename}` : facultyData.photo
      };

      const updatedFaculty = await faculty.findByIdAndUpdate(
          id, 
          updatedData, 
          { new: true }
      );
      
      res.redirect('/Mfaculty');
  } catch (error) {
      console.error(error);
      res.status(500).send('Error updating faculty');
  }
});

// Delete faculty route
app.delete('/admin/faculty/:id', async (req, res) => {
  try {
      const { id } = req.params;
      await faculty.findByIdAndDelete(id);
      res.status(200).send();
  } catch (error) {
      console.error(error);
      res.status(500).send('Error deleting faculty');
  }
});
// Delete student route
app.delete('/admin/students/:id', async (req, res) => {
  try {
      const { id } = req.params;
      await User.findByIdAndDelete(id);
      res.status(200).send();
  } catch (error) {
      console.error(error);
      res.status(500).send('Error deleting student');
  }
});

// Get single faculty route
app.get('/admin/faculty/:id', async (req, res) => {
  try {
      const fac = await faculty.findById(req.params.id);
      res.json(fac);
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Server error' });
  }
});

// Server route for faculty search
app.get('/AsearchFaculty', async (req, res) => {
  try {
      const searchQuery = req.query.query;
      const results = await faculty.find({
          $or: [
              { name: new RegExp(searchQuery, 'i') },
              { department: new RegExp(searchQuery, 'i') },
              { subjects: new RegExp(searchQuery, 'i') }
          ]
      }).lean();
      
      res.json(results);
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Server error' });
  }
});

// In your server routes
app.post('/update-availability', async (req, res) => {
  try {
    // Validate input
    if (!Array.isArray(req.body.availableSlots)) {
      return res.status(400).json({
        success: false,
        error: "availableSlots must be an array"
      });
    }

    const updated = await faculty.findByIdAndUpdate(
      req.session.user._id,
      {
        status: req.body.status,
        availableSlots: req.body.availableSlots
      },
      { 
        new: true,
        runValidators: true,
        context: 'query'
      }
    );

    if (!updated) {
      return res.status(404).json({
        success: false,
        error: "Faculty not found"
      });
    }

    res.json({
      success: true,
      status: updated.status,
      availableSlots: updated.availableSlots
    });

  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});
const scheduleReminders = () => {
  cron.schedule('* * * * *', async () => {
    try {
      const now = new Date();
      const tenMinutesLater = new Date(now.getTime() + 10 * 60 * 1000); // Current time + 10 minutes

      const appointments = await appointmentRequests.find({
        status: 'approved',
        date: { $lte: tenMinutesLater }, 
        reminderSent: false
      })
      .populate({
        path: 'student',
        model: 'User',
        options: { retainNullValues: true } // Handle deleted users
      })
      .populate({
        path: 'faculty',
        model: 'FacultyDetail',
        options: { retainNullValues: true }
      });


      for (const appointment of appointments) {
        if (!appointment.faculty || !appointment.student) {
          console.error('Missing populated data in appointment:', appointment._id);
          continue;
        }

        await Notification.create([
          {
            recipient: appointment.student._id,
            recipientModel: 'Student',
            student: appointment.student._id,
            faculty: appointment.faculty._id,
            message: `Appointment with ${appointment.faculty.name} starts in 10 mins`,
            relatedAppointment: appointment._id
          },
          {
            recipient: appointment.faculty._id,
            recipientModel: 'Faculty',
            student: appointment.student._id,
            faculty: appointment.faculty._id,
            message: `Appointment with ${appointment.student.fullName} starts in 10 mins`,
            relatedAppointment: appointment._id
          }
        ]);

        appointment.reminderSent = true;
        await appointment.save();
      }
    } catch (error) {
      console.error('Reminder service error:', error);
    }
  });
};

scheduleReminders(); //Start reminder service after DB connection

app.post("/new/appointment/:id", async (req, res) => {
  console.log(req.body);
  try {
    const id = req.params.id;
    
    const studentId = req.session.user._id; 
    const studentName = req.session.user.fullName;
    
    const fac = await faculty.findById(id);
  
    if (!fac.availableSlots.includes(req.body.time)) {
      return res.status(400).json({ 
        error: 'Selected time slot is no longer available' 
      });
    }


    if (!fac.availableSlots.includes(req.body.time)) {
      return res.status(400).json({ error: 'Selected time not available' });
    }
  
    // Check existing appointments
    const existing = await appointmentRequests.findOne({
      facultyId: req.params.id,
      date: req.body.date,
      time: req.body.time
    });
  
    if (existing) {
      return res.status(400).json({ error: 'Time slot already booked' });
    }


    
    const newAppointmentRequest = new appointmentRequests({
      student: studentId,
      faculty: id,
      studentDetails: {
        fullName: req.body.studentDetails.fullName,
        rollNo: req.body.studentDetails.rollNo,
        department: req.body.studentDetails.department,
      },
      facultyDetails: {
        name: req.body.facultyDetails.name,
        department: req.body.facultyDetails.department,
        subjects: req.body.facultyDetails.subjects
      },
      date: new Date(req.body.date),
      time: req.body.time,
      message: req.body.message
    });
//  newNotification is defined and can be used
const socketId = userSocketMap.get(studentId.toString()); // Get from Map
if (socketId) {
  io.to(socketId).emit('notification', {
    message: newNotification.message,
    unreadCount: unreadCount
  });
} else {
  console.log(`User ${studentId} is not connected.`);
}


    // 2. Get faculty's socket ID (you need to implement this mapping)

    const facultySocketId = userSocketMap.get(id.toString());
  if (facultySocketId) {
    req.io.to(facultySocketId).emit('new-appointment', {
      message: `New appointment request from ${req.session.user.fullName}`,
      appointmentId: newAppointmentRequest._id,
      time: req.body.time
    });
  }
    
    // Create notification

    const newNotification = await Notification.create({
      recipient: id, // Faculty ID is the recipient
      recipientModel: 'Faculty',
      student: studentId,
      faculty: id,
      message: `New appointment request from ${studentName}`,
      relatedAppointment: newAppointmentRequest._id,
      type: 'appointment'
    });


    req.flash('success', 'Appointment request sent successfully');
    const savedRequest = await newAppointmentRequest.save();
    res.redirect("/dashboard");
  } catch (e) {
    req.flash('error', 'Failed to create appointment request');
    console.log(e);
    res.redirect("/dashboard"); // Ensure a response is sent
  }
});
const getSocketId = (userId) => {
  return userSocketMap.get(userId.toString());
};
//  notification cleanup on server shutdown
process.on('SIGINT', () => {
  userSocketMap.clear();
  io.close();
  process.exit();
  
});
app.listen(8000, () => console.log('Server running on http://localhost:8000'));