const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWt_EXPIRES_IN,
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  const token = signToken(newUser._id);

  res.status(201).json({
    status: 'success',
    token,
    data: {
      user: newUser,
    },
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError('Please provide email and password', 404));
  }
  const user = await User.findOne({ email }).select('+password');

  // console.log(user);
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  const token = signToken(user._id);
  res.status(200).json({
    status: 'sucess',
    token,
  });
});

exports.protectedTour = catchAsync(async (req, res, next) => {
  let token;
  //getting the token from the header and checking if it exist

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(new AppError('You are not logged in, please log in', 401));
  }

  //verifying the token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  //checking if user still exist
  const freshUser = await User.findById(decoded.id);
  if (!freshUser) {
    return next(new AppError('The user to the token no longer exist', 401));
  }
  //checking if password is changed
  if (freshUser.passwordChangeAt(decoded.iat)) {
    return next(
      new AppError('User recenty logged password, Please log in again', 401)
    );
  }

  //grant access
  req.user = freshUser;
  next();
});

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles) {
      return next(new AppError('You dont have permission', 403));
    }

    next();
  };
};
