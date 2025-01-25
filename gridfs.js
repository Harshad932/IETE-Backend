import mongoose from 'mongoose';
import Grid from 'gridfs-stream';
import multer from 'multer';
import { Readable } from 'stream';

// Initialize GridFS
const conn = mongoose.connection;
let gfs;
conn.once('open', () => {
  gfs = Grid(conn.db, mongoose.mongo);
  gfs.collection('fs'); // Optional: define collection name (default is 'fs')
});

// Create GridFS storage engine using multer
const storage = multer.memoryStorage();  // Use memory storage to store files temporarily in memory
const upload = multer({ storage: storage }).any(); // Change 'file' to match the field name from your form

const uploadFileToGridFS = async (file, fileType) => {
  const gridfsBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: 'fs',
  });

  // Create a readable stream from the buffer
  const readableStream = new Readable();
  readableStream.push(file.buffer);
  readableStream.push(null);  // End the stream

  const uploadStream = gridfsBucket.openUploadStream(file.originalname, {
    contentType: file.mimetype,
  });

  return new Promise((resolve, reject) => {
    readableStream.pipe(uploadStream)  // Pipe the readable stream to GridFS
      .on('error', (error) => {
        reject(error);
      })
      .on('finish', () => {
        resolve({
          _id: uploadStream.id,
          filename: file.originalname,
          contentType: file.mimetype,
        });
      });
  });
};

export { upload, uploadFileToGridFS,gfs };
