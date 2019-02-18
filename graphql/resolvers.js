const bcrypt = require('bcryptjs');
const validator = require('validator');
const User = require('../models/user');

module.exports = {
  createUser: async function({ userInput }, req) {
    const email = userInput.email;
    const name = userInput.name;

    const errors = [];

    if (validator.isEmail(email)) {
      errors.push({ message: 'Email is invalid' });
    }
    if (validator.isEmpty(userInput.password) || !validator.isLength(userInput.password, { min: 5 })) {
      errors.push({ message: 'Password is too short' })
    }

    if (errors.length) {
      const error = new Error('Invalid input');
      throw error;
    }

    const existing = await User.findOne({ email });

    if (existing) {
      const error = new Error('User exists already');
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
  }
}