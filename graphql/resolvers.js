const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const config = require('../config');

module.exports = {
  createUser: async ({ userInput }, req) => {
    const email = userInput.email;
    const name = userInput.name;

    const errors = [];

    if (!validator.isEmail(email)) {
      errors.push({ message: 'Email is invalid' });
    }
    if (validator.isEmpty(userInput.password) || !validator.isLength(userInput.password, { min: 5 })) {
      errors.push({ message: 'Password is too short' })
    }

    if (errors.length) {
      const error = new Error('Invalid input');
      error.data = errors;
      error.code = 422;
      throw error;
    }

    const existing = await User.findOne({ email });

    if (existing) {
      const error = new Error('User exists already');
      error.code = 422;
      throw error;
    }

    const password = await bcrypt.hash(userInput.password, 12);
    const user = new User({
      email,
      name,
      password
    });

    const createdUser = await user.save();

    return { ...createdUser._doc, _id: createdUser._id.toString() };
  },
  login: async ({ email, password }) => {
    const user = await User.findOne({ email });
    if (!user) {
      const error = new Error('Incorrect email or password');
      error.code = 401;
      throw error;
    }

    const isEqual = await bcrypt.compare(password, user.password);

    if (!isEqual) {
      const error = new Error('Incorrect email or password');
      error.code = 401;
      throw error;
    }

    const userId = user._id.toString();

    const token = jwt.sign({
      userId,
      email: user.email
    }, config.jwtSecretKey, { expiresIn: '1h' });

    return { token, userId };
  }
}