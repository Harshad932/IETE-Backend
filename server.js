import express from "express";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import cors from "cors";
import crypto from "crypto";
import nodemailer from "nodemailer";
import mongoose from "mongoose";
import { upload, uploadFileToGridFS ,gfs} from './gridfs.js';
import { Strategy as LocalStrategy } from "passport-local";
import { announcement,admin,event,member } from "./projectModel.js";

const app = express();
dotenv.config();

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

app.use(cors({
  origin: process.env.CORS_ORIGIN,
  credentials: true,
}));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: false, // Set to true when using HTTPS
    sameSite: 'Lax', // Use 'Lax' for local development
    maxAge: 1000 * 60 * 60 * 24,
  },
}));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: false, // Set to true when using HTTPS
    sameSite: 'Lax', // Use 'Lax' for local development
    maxAge: 1000 * 60 * 60 * 24,
  },
}));


app.use(passport.initialize());
app.use(passport.session());

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL, 
    pass: process.env.APP_PASSWORD, 
  },
});


passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await admin.findOne({ username });
      if (!user) return done(null, false, { message: "User not found" });
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return done(null, false, { message: "Incorrect password" });

      return done(null, user);
    } catch (error) {
      console.error("Error during authentication:", error);
      return done(error);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await admin.findById(id);
    done(null, user);
  } catch (error) {
    console.error("Error during deserialization:", error);
    done(error);
  }
});

app.get('/auth/check-session', (req, res) => {
  if (req.isAuthenticated()) {
    res.status(200).json({ message: 'Authenticated' });
  } else {
    res.status(401).json({ message: 'Not authenticated' });
  }
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Unauthorized. Please log in." });
}

app.post("/admin/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      console.error("Authentication error:", err);
      return next(err);
    }

    if (!user) {
      return res.status(401).json({ message: info.message || "Invalid credentials" });
    }

    req.logIn(user, (err) => {
      if (err) {
        console.error("Login error:", err);
        return next(err);
      }
      res.status(200).json({ message: "Login successful", user: user.username });
    });
  })(req, res, next);
});

app.post("/admin/forgotPassword",async (req,res)=>
{

  const { username, email } = req.body;

  try {
    const user = await admin.findOne({ username, email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const resetToken = crypto.randomBytes(32).toString('hex');

    // Store the token and expiry time in the user's record
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // Token valid for 1 hour
    await user.save();

    // Send email with the reset token
    const resetLink = `http://localhost:3000/admin/resetpassword?token=${resetToken}`;
    await transporter.sendMail({
      to: user.email,
      subject: 'Password Reset Request',
      text: `You requested a password reset. Please use the following link to reset your password: ${resetLink}`,
    });

    res.status(200).json({ message: 'Password reset link sent to your email.' });
  } catch (error) {
    console.error('Error in forgotPassword:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/admin/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  console.log(token,newPassword)
  try {
    // Find the user by the reset token and check if it's expired
    const user = await admin.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() },
    });

    console.log(user);

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // Hash the new password
    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = undefined;  // Clear the reset token after it's used
    user.resetTokenExpiry = undefined;  // Clear expiry
    await user.save();

    res.status(200).json({ message: 'Password has been reset successfully.' });
  } catch (error) {
    console.error('Error in reset-password:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/admin/addAdmin', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const newAdmin = new admin({
      username,
      email,
      password: hashedPassword,
    });

    await newAdmin.save();
    res.status(201).json({ message: 'Admin added successfully' });
  } catch (error) {
    console.error('Error adding admin:', error);
    res.status(500).json({ message: 'Failed to add admin' });
  }
});

app.post('/admin/logout', (req, res) => {
  req.session.destroy(err => {
      if (err) {
          return res.status(500).json({ message: 'Logout failed', error: err });
      }
      res.clearCookie('connect.sid'); 
      return res.status(200).json({ message: 'Logout successful' });
  });
});

app.get("/admin/dashboard", ensureAuthenticated, async (req, res) => {
  try {
    const events = await event.find();
    if (!events) {
      return res.status(404).json({ message: 'Events not found' });
    }
    res.json({ events }); // Ensure the response has a key to access events in frontend
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/file/:id', async (req, res) => {
  try {
    const fileId = new mongoose.Types.ObjectId(req.params.id);
    const gfsBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
      bucketName: 'fs',
    });

    const fileStream = gfsBucket.openDownloadStream(fileId);

    const file = await gfsBucket.find({ _id: fileId }).toArray();
    if (!file || file.length === 0) {
      return res.status(404).json({ message: 'File not found' });
    }

    res.set('Content-Type', file[0].contentType);
    fileStream.pipe(res);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});




app.post('/admin/addEvent', upload, async (req, res) => {
  try {
    const { eventName, eventAbout, eventWinner, eventRunnerUp, guests, organizers } = req.body;

    // Upload PDF if provided
    let pdfFileId = null;
    if (req.files && req.files.find(file => file.fieldname === 'pdfFile')) {
      const pdfFile = req.files.find(file => file.fieldname === 'pdfFile');
      const pdfFileInfo = await uploadFileToGridFS(pdfFile, 'pdfFile');
      pdfFileId = pdfFileInfo._id;
    }

    // Categorize and upload images
    const guestImageIds = [];
    const winnerImageIds = [];
    const randomImageIds = [];

    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        if (file.fieldname.startsWith('guestImages')) {
          const imageInfo = await uploadFileToGridFS(file, 'guestImage');
          guestImageIds.push(imageInfo._id);
        } else if (file.fieldname.startsWith('winnerRunnerUpImages')) {
          const imageInfo = await uploadFileToGridFS(file, 'winnerImage');
          winnerImageIds.push(imageInfo._id);
        } else if (file.fieldname.startsWith('eventImages')) {
          const imageInfo = await uploadFileToGridFS(file, 'randomImage');
          randomImageIds.push(imageInfo._id);
        }
      }
    }

    // Create a new event with references to GridFS file IDs
    const newEvent = new event({
      eventName,
      eventAbout,
      eventWinner,
      eventRunnerUp,
      guests,
      organizers,
      pdfFile: pdfFileId,
      guestImages: guestImageIds,
      winnerImages: winnerImageIds,
      randomImages: randomImageIds,
    });

    await newEvent.save();
    res.status(201).json({ message: 'Event created successfully' });
  } catch (error) {
    console.error('Error during event creation:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

const deleteFileFromGridFS = async (fileId) => {
  const filesCollection = mongoose.connection.db.collection('fs.files');
  const chunksCollection = mongoose.connection.db.collection('fs.chunks');

  try {
    // Delete the file document from the fs.files collection
    const result = await filesCollection.deleteOne({
      _id: new mongoose.Types.ObjectId(fileId),
    });

    if (result.deletedCount === 0) {
      throw new Error('File not found');
    }

    // Manually delete the corresponding chunks from the fs.chunks collection
    await chunksCollection.deleteMany({
      files_id: new mongoose.Types.ObjectId(fileId),
    });

  } catch (error) {
    console.error('Error deleting file and chunks:', error);
    throw error;
  }
};


app.put('/admin/updateEvent/:id', upload, async (req, res) => {
  const { id } = req.params;
  const { eventName, eventAbout, guests, organizers, eventWinner, eventRunnerUp, deleteImages, deletePdf } = req.body;

  try {
    const e = await event.findById(id);
    if (!e) {
      return res.status(404).json({ message: 'Event not found' });
    }

    // Handle new file uploads (images and PDF)
    const newGuestImageIds = [];
    const newWinnerImageIds = [];
    const newRandomImageIds = [];
    let newPdfFileId = null;

    if (req.files) {
      for (const file of req.files) {
        if (file.fieldname.startsWith('guestImages')) {
          const imageInfo = await uploadFileToGridFS(file, 'guestImage');
          newGuestImageIds.push(imageInfo._id);
        } else if (file.fieldname.startsWith('winnerRunnerUpImages')) {
          const imageInfo = await uploadFileToGridFS(file, 'winnerImage');
          newWinnerImageIds.push(imageInfo._id);
        } else if (file.fieldname.startsWith('eventImages')) {
          const imageInfo = await uploadFileToGridFS(file, 'randomImage');
          newRandomImageIds.push(imageInfo._id);
        } else if (file.fieldname === 'pdfFile') {
          const pdfInfo = await uploadFileToGridFS(file, 'pdfFile');
          newPdfFileId = pdfInfo._id;
        }
      }
    }

    // Handle delete images
    if (deleteImages && deleteImages.length > 0) {
      // Ensure deleteImages is always an array
      const imagesToDelete = Array.isArray(deleteImages) ? deleteImages : [deleteImages];
    
      for (let imageId of imagesToDelete) {
        try {
          await deleteFileFromGridFS(imageId);
          e.guestImages = e.guestImages.filter(imgId => imgId.toString() !== imageId);
          e.winnerImages = e.winnerImages.filter(imgId => imgId.toString() !== imageId);
          e.randomImages = e.randomImages.filter(imgId => imgId.toString() !== imageId);
        } catch (error) {
          console.error('Error deleting image:', error.message);
        }
      }
    }
    

    // Handle delete PDF
    if (deletePdf && e.pdfFile) {
      try {
        await deleteFileFromGridFS(e.pdfFile);
        e.pdfFile = null;
      } catch (error) {
        console.error('Error deleting PDF:', error.message);
      }
    }

    // Update the event with new details and files
    e.eventName = eventName;
    e.eventAbout = eventAbout;
    e.guests = guests;
    e.organizers = organizers;
    e.eventWinner = eventWinner;
    e.eventRunnerUp = eventRunnerUp;
    e.guestImages = [...e.guestImages, ...newGuestImageIds];
    e.winnerImages = [...e.winnerImages, ...newWinnerImageIds];
    e.randomImages = [...e.randomImages, ...newRandomImageIds];

    // Update the event with the new PDF file ID if a new file is uploaded
    if (newPdfFileId) {
      e.pdfFile = newPdfFileId;
    }

    await e.save();
    res.status(200).json({ message: 'Event updated successfully', e });
  } catch (error) {
    console.error('Error updating event:', error.message);
    res.status(500).json({ message: 'Error updating event', error: error.message });
  }
});

app.delete('/admin/deleteEvent/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const e = await event.findById(id);
    if (!e) {
      return res.status(404).json({ message: 'Event not found' });
    }

    // Delete associated PDF file if exists
    if (e.pdfFile) {
      await deleteFileFromGridFS(e.pdfFile);
    }

    // Delete associated guest images if exist
    for (const imageId of e.guestImages) {
      await deleteFileFromGridFS(imageId);
    }

    // Delete associated winner images if exist
    for (const imageId of e.winnerImages) {
      await deleteFileFromGridFS(imageId);
    }

    // Delete associated random images if exist
    for (const imageId of e.randomImages) {
      await deleteFileFromGridFS(imageId);
    }

    // Delete the event from the database
    await event.findByIdAndDelete(id);

    res.status(200).json({ message: 'Event deleted successfully' });
  } catch (error) {
    console.error('Error deleting event:', error.message);
    res.status(500).json({ message: 'Error deleting event', error: error.message });
  }
});

app.post('/admin/addAnnouncement', async (req, res) => {
  const { msg } = req.body;

  try {
    const newAnnouncement = new announcement({ msg });
    await newAnnouncement.save();
    res.status(201).json({ message: 'Announcement added successfully', newAnnouncement });
  } catch (error) {
    console.error('Error adding announcement:', error.message);
    res.status(500).json({ message: 'Error adding announcement', error: error.message });
  }
});

// Show Announcements Route
app.get('/admin/showAnnouncements',ensureAuthenticated ,async (req, res) => {
  try {
    const announcements = await announcement.find().sort({ createdAt: -1 });
    res.status(200).json({ announcements });
  } catch (error) {
    console.error('Error fetching announcements:', error.message);
    res.status(500).json({ message: 'Error fetching announcements', error: error.message });
  }
});

// Delete Announcement Route
app.delete('/admin/deleteAnnouncement/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await announcement.findByIdAndDelete(id);
    if (!result) {
      return res.status(404).json({ message: 'Announcement not found' });
    }
    res.status(200).json({ message: 'Announcement deleted successfully' });
  } catch (error) {
    console.error('Error deleting announcement:', error.message);
    res.status(500).json({ message: 'Error deleting announcement', error: error.message });
  }
});

app.post('/admin/addMember', async (req, res) => {
  const { memberName, position, priority } = req.body;

  try {
    const newMember = new member({ memberName, position, priority });
    await newMember.save();
    res.status(201).json({ message: 'Member added successfully' });
  } catch (error) {
    console.error('Error adding member:', error.message);
    res.status(500).json({ message: 'Error adding member', error: error.message });
  }
});

app.get('/showMembers', ensureAuthenticated,async (req, res) => {
  try {
    const members = await member.find().sort({ priority: 1 }); // Sort by priority
    res.status(200).json({ members });
  } catch (error) {
    console.error('Error fetching members:', error);
    res.status(500).json({ message: 'Failed to fetch members' });
  }
});

app.delete('/deleteMember/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await member.findByIdAndDelete(id);
    if (result) {
      res.status(200).json({ message: 'Member deleted successfully' });
    } else {
      res.status(404).json({ message: 'Member not found' });
    }
  } catch (error) {
    console.error('Error deleting member:', error);
    res.status(500).json({ message: 'Failed to delete member' });
  }
});

app.get('/events', async (req, res) => {
  try {
    const events = await event.find();
    res.status(200).json({ events });
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ message: 'Failed to fetch events' });
  }
});

app.listen(process.env.PORT, () => {
    console.log("Server running on port: " + process.env.PORT);
  });