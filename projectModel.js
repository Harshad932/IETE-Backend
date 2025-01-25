import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

try {
  await mongoose.connect(process.env.MONGOURI); // No additional options required
  console.log("Connected to MongoDB successfully.");
} catch (error) {
  console.error("Error connecting to MongoDB:", error);
}


const announcementSchema = new mongoose.Schema({
    msg:{type: String, required: true}
}, { timestamps: true });

const announcement = mongoose.model('announcements', announcementSchema);

const adminSchema = new mongoose.Schema({
  username:{type:String,required: true,unique:true},
  password:{type:String,required: true},
  email:{type:String,required: true,unique:true},
  resetToken: { type: String },  
  resetTokenExpiry: { type: Date },
}, { timestamps: true });

const admin = mongoose.model('admin', adminSchema);

const eventSchema = new mongoose.Schema({
  eventName: String,
  eventAbout: String,
  eventWinner: String,
  eventRunnerUp: String,
  guests: [String],
  organizers: [String],
  pdfFile: { type: mongoose.Schema.Types.ObjectId, ref: 'fs.files' }, // Reference to GridFS file
  guestImages: [{
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'fs.files' // Reference to GridFS file
  }],
  winnerImages: [{
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'fs.files' // Reference to GridFS file
  }],
  randomImages: [{
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'fs.files' // Reference to GridFS file
  }],
});

const event = mongoose.model('Events', eventSchema);

const memberSchema = new mongoose.Schema({
  memberName: { type: String, required: true },
  position: { type: String, required: true },
  priority: { type: Number, required: true }
}, { timestamps: true });

const member = mongoose.model('Member', memberSchema);

export {announcement,admin,event,member};

