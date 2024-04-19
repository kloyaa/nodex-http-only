require("dotenv").config();

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const mongoose = require('mongoose');

app.use(cookieParser());
app.use(express.json());

const RefreshToken = mongoose.model("RefreshToken", {
  token: String,
});

const User = mongoose.model("User", {
  username: String,
  password: String,
});

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/token_demo', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));


app.post("/token", async (req, res) => {
  const refreshToken = req.cookies?.token;
  if (!refreshToken) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const existingToken = await RefreshToken.findOne({ token: refreshToken });
  if (!existingToken) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const decodedJwt = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    return user;
  });

  delete decodedJwt.iat; //should delete `issued at` to generate a new one
  const accessToken = generateAccessToken(decodedJwt);
  res.json({ accessToken: accessToken });
});

app.delete("/logout", async (req, res) => {
  const refreshToken = req.cookies?.token;
  if (!refreshToken) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const existingToken = await RefreshToken.findOne({ token: refreshToken });
  if (!existingToken) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  await existingToken.deleteOne();
  return res.status(200).json({ message: "success" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username, password });
  if (!user) {
    res.status(401).json({ message: "Invalid username or password" });
  }

  const accessToken = generateAccessToken(user.toJSON());
  const refreshToken =  generateRefreshToken(user.toJSON());

  await saveRefreshToken(refreshToken);

  res.cookie("token", refreshToken, { httpOnly: true });
  res.json({ accessToken: accessToken });
});

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
}

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15s" });
}

// Function to save refresh token to MongoDB
async function saveRefreshToken(token) {
  const refreshToken = new RefreshToken({ token });
  await refreshToken.save();
}

app.listen(4000);
