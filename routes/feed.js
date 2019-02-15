const express = require('express');
const router = express.Router();
const { body } = require('express-validator/check');
const feedController = require('../controllers/feed');

router.get('/posts', feedController.getPosts);

router.post(
  '/post',
  [
    body('title')
      .trim()
      .isLength({ min: 5 }),
    body('content')
      .trim()
      .isLength({ min: 5 })
  ],
  feedController.postPost
);

module.exports = router;