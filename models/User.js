// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  name: {
    type: String,
    required: true
  },
  usage: {
    type: Number,
    default: 0, // in USD
    min: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Pre-save hook to hash password
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Method to check password
userSchema.methods.comparePassword = async function (candidate) {
  return await bcrypt.compare(candidate, this.password);
};

// Virtual: isEligibleForFreeTier
userSchema.virtual('isEligibleForFreeTier').get(function () {
  return this.email === 'theceoion@gmail.com';
});

// Ensure virtuals are serialized
userSchema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('User', userSchema);
