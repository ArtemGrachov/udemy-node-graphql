const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const Post = require('../models/post');
const config = require('../config');
const clearImage = require('../utils/clear-image');

const checkAuth = (req) => {
  if (!req.isAuth) {
    const error = new Error('Not authenticated');
    error.code = 401;
    throw error;
  }
}

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
  },
  createPost: async ({ postInput }, req) => {
    checkAuth(req);

    const errors = [];

    const title = postInput.title;
    const content = postInput.content;
    const imageUrl = postInput.imageUrl;

    if (validator.isEmpty(title) || !validator.isLength(title, { min: 5 })) {
      errors.push({
        message: 'Title is invalid'
      })
    }

    if (validator.isEmpty(content) || !validator.isLength(content, { min: 5 })) {
      errors.push({
        message: 'Content is invalid'
      })
    }

    if (errors.length) {
      const error = new Error('Invalid input');
      error.data = errors;
      error.status = 422;
      throw error;
    }

    const creator = await User.findById(req.userId);

    if (!creator) {
      const error = new Error('Invalid user');
      error.status = 401;
      throw error;
    }

    const post = new Post({
      title,
      content,
      imageUrl,
      creator
    })

    const createdPost = await post.save();

    creator.posts.push(createdPost);

    await creator.save();

    return { 
      ...createdPost._doc,
      _id: createdPost._id.toString(),
      createdAt: createdPost.createdAt.toISOString(),
      updatedAt: createdPost.updatedAt.toISOString(),
    }
  },
  posts: async ({ page, perPage }, req) => {
    checkAuth(req);

    if (!page) {
      page = 1;
    }

    if (!perPage) {
      perPage = 2;
    }

    const totalPosts = await Post
      .find()
      .countDocuments();
    const posts = await Post
      .find()
      .sort({ createdAt: -1 })
      .skip((page - 1) * perPage)
      .limit(perPage)
      .populate('creator');

    return {
      posts: posts.map(p => {
        return {
          ...p._doc,
          _id: p._id.toString(),
          createdAt: p.createdAt.toISOString(),
          updatedAt: p.updatedAt.toISOString()
        }
      }),
      totalPosts
    }
  },
  post: async ({ id }, req) => {
    checkAuth(req);

    const post = await Post.findById(id).populate('creator');

    if (!post) {
      const error = new Error('No post found');
      error.code = 404;
      throw error;
    }

    return {
      ...post._doc,
      _id: post._id.toString(),
      createdAt: post.createdAt.toISOString(),
      updatedAt: post.updatedAt.toISOString()
    }
  },
  updatePost: async ( { id, postInput }, req) => {
    checkAuth(req);

    const post = await Post.findById(id).populate('creator');

    if (!post) {
      const error = new Error('No post found');
      error.code = 404;
      throw error;
    }

    if (post.creator._id.toString() !== req.userId.toString()) {
      const error = new Error('Not authorized');
      error.code = 403;
      throw error;
    }

    const errors = [];

    const title = postInput.title;
    const content = postInput.content;
    const imageUrl = postInput.imageUrl;

    if (validator.isEmpty(title) || !validator.isLength(title, { min: 5 })) {
      errors.push({
        message: 'Title is invalid'
      })
    }

    if (validator.isEmpty(content) || !validator.isLength(content, { min: 5 })) {
      errors.push({
        message: 'Content is invalid'
      })
    }

    post.title = title;
    post.content = content;

    if (imageUrl !== 'undefined') {
      post.imageUrl = imageUrl;
    }

    const updatedPost = await post.save();

    return {
      ...updatedPost._doc,
      _id: updatedPost._id.toString(),
      createdAt: updatedPost.createdAt.toISOString(),
      updatedAt: updatedPost.updatedAt.toISOString()
    }
  },
  deletePost: async ({ id }, req) => {
    checkAuth(req);

    const post = await Post.findById(id);
    const creatorId = post.creator.toString();

    if (creatorId !== req.userId.toString()) {
      const error = new Error('Not authorized');
      error.code = 403;
      throw error;
    }

    clearImage(post.imageUrl);

    await post.remove();

    const user = await User.findById(creatorId);
    user.posts.pull(id);

    await user.save();

    return true;
  },
  user: async (args, req) => {
    checkAuth(req);

    const user = await User.findById(req.userId);

    if (!user) {
      const error = new Error('No user found)');
      error.code = 404;
      throw error;
    }

    return {
      ...user._doc,
      _id: user._id.toString()
    }
  },
  updateStatus: async ({ status }, req) => {
    checkAuth(req);

    const user = await User.findById(req.userId);

    if (!user) {
      const error = new Error('No user found)');
      error.code = 404;
      throw error;
    }

    user.status = status;

    await user.save();

    return {
      ...user._doc,
      _id: user._id.toString()
    }
  }
}