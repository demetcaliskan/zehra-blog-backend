// server.js

const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
require('dotenv').config()

const app = express()
app.use(express.json())

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to database!')
    app.listen(3001, () => {
      console.log('Server is running on port 3001')
    })
  })
  .catch((err) => {
    console.log('Connection failed!')
    console.log('error: ', err)
  })

// Schema definitions
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String },
})

// hash the password
UserSchema.methods.generateHash = function (password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null)
}

// checking if password is valid
UserSchema.methods.validPassword = function (password) {
  return bcrypt.compareSync(password, this.password)
}

const User = mongoose.model('User', UserSchema)

const PostSchema = new mongoose.Schema({
  slug: { type: String, required: true, unique: true },
  title: { type: String, required: true },
  description: { type: String },
  banner: { type: String },
  body: { type: String },
  status: { type: String, enum: ['published', 'draft'], default: 'draft' },
})
const Post = mongoose.model('Post', PostSchema)

// Generate JWT secret dynamically
const jwtSecret = Math.random().toString(36).substring(7)

// Routes

// Register Endpoint
app.post('/register', function (req, res) {
  console.log('req body', req.body)
  if (!req.body.email || !req.body.name || !req.body.password) {
    return res.status(401).send('missing body!!!! call the police!!!!!')
  }
  const { email, name, password } = req.body
  var new_user = new User({
    email: email,
    name: name,
  })
  try {
    new_user.password = new_user.generateHash(password)
    new_user.save()
    return res.status(200).json({ message: 'User successfully created!' })
  } catch (error) {
    res.status(500).send('Server Error')
  }
})

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body
  try {
    const user = await User.findOne({ email })
    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }

    if (!user.validPassword(password)) {
      return res.status(500).json({ message: 'Invalid credentials' })
    }

    // JWT payload
    const payload = {
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    }

    // Generate JWT token with expiration (1 hour in this example)
    jwt.sign(payload, jwtSecret, { expiresIn: '1h' }, (err, token) => {
      if (err) throw err
      res.json({ token })
    })
  } catch (err) {
    console.error(err)
    res.status(500).send('Server Error')
  }
})

function checkAuth(req, res, next) {
  const token = req.header('Authorization')
  if (token) {
    try {
      const decoded = jwt.verify(token, jwtSecret)
      console.log('decoded', decoded)
      req.user = decoded.user // Attach user information to request object
    } catch (error) {
      console.log('error', error)
    }
  }
  next()
}

// Middleware to verify token
function auth(req, res, next) {
  const token = req.header('Authorization')
  if (!token) {
    return res
      .status(401)
      .json({ message: 'Authorization denied, token required' })
  }
  try {
    const decoded = jwt.verify(token, jwtSecret)
    req.user = decoded.user // Attach user information to request object
    next()
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' })
  }
}

// Create a new post
app.post('/post', auth, async (req, res) => {
  const post = new Post(req.body)
  try {
    const savedPost = await post.save()
    res.json(savedPost)
  } catch (err) {
    console.error(err)
    res.status(500).send('Server Error')
  }
})

// Update a post
app.put('/post/:postId', auth, async (req, res) => {
  const { postId } = req.params
  try {
    const updatedPost = await Post.findByIdAndUpdate(postId, req.body, {
      new: true,
    })
    if (!updatedPost) {
      return res.status(404).json({ message: 'Post not found' })
    }
    res.json(updatedPost)
  } catch (err) {
    console.error(err)
    res.status(500).send('Server Error')
  }
})

// Delete a post
app.delete('/post/:postId', auth, async (req, res) => {
  const { postId } = req.params
  try {
    const deletedPost = await Post.findByIdAndDelete(postId)
    if (!deletedPost) {
      return res.status(404).json({ message: 'Post not found' })
    }
    res.json({ message: 'Post deleted' })
  } catch (err) {
    console.error(err)
    res.status(500).send('Server Error')
  }
})

// Get all posts
app.get('/post', checkAuth, async (req, res) => {
  console.log('req user', req.user)
  if (!req.user) {
    try {
      const posts = await Post.find({ status: 'published' }).exec()
      res.json({ posts: posts, message: 'Post list for losers.' })
    } catch (err) {
      console.error(err)
      res.status(500).send('Server Error')
    }
  } else {
    try {
      const posts = await Post.find().exec()
      res.json({ posts: posts, message: 'Post list for winners.' })
    } catch (err) {
      console.error(err)
      res.status(500).send('Server Error')
    }
  }
})

// Get a specific post
app.get('/post/:postId', async (req, res) => {
  const { postId } = req.params
  try {
    const post = await Post.findById(postId).exec()
    if (!post) {
      return res.status(404).json({ message: 'Post not found' })
    }
    res.json(post)
  } catch (err) {
    console.error(err)
    res.status(500).send('Server Error')
  }
})
