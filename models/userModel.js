const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: [true, 'User name is required'],
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    validate: [validator.isEmail, 'please provide a valid emial'],
  },
  photo: String,
  password: {
    type: String,
    required: [true, 'Provide password'],
    minlength: 8,
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confrim password'],
    validate: {
      validator: function (el) {
        return el === this.password;
      },
      message: 'Password is not the same',
    },
  },
  passwordChangedAt: Date,
  role: {
    type: String,
    enum: ['user', 'admin', 'guide', 'lead-guide'],
    default: 'user',
  },
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.passwordChangeAt = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changeTimeStamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp > changeTimeStamp;
  }
  return false;
};
// eslint-disable-next-line new-cap
const User = new mongoose.model('User', userSchema);

module.exports = User;
