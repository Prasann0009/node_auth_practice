const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const userSchema = require("./schemas/userSchema");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

//constants
const app = express();
const PORT = process.env.PORT;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");

//db Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(console.log("mongodb connected Successfully"))
  .catch((err) => console.log(err));

app.get("/", (req, res) => {
  return res.send({
    status: 200,
    message: "server is up and running!",
  });
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await userSchema.findOne({ username });
    if (existingUser) {
      return res.status(400).json({
        message: "User already exist",
      });
    }
    //hashing the password
    const hashedPassword = await bcrypt.hash(
      password,
      Number(process.env.SALT)
    );

    //Create user
    const newUser = new userSchema({
      username,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({
      message: "server error",
      error: error,
    });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await userSchema.findOne({ username });
    if (!user) {
      return res.status(400).json({
        message: "Invalid Username",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        message: "Invalid Password",
      });
    }

    //Generate Token
    const token = jwt.sign(username, process.env.SECRET_KEY);

    res.status(200).json({
      message: "Login Successfull",
      token: token,
    });
  } catch (error) {
    res.status(500).json({
      message: "server error",
      error: error,
    });
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token === null) {
    return res.status(401).json({
      message: "No token found, Please login again",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

app.get("/dashboard", authenticateToken, (req, res) => {
  return res.json({
    message: "On Dashboard",
  });
});
app.listen(PORT, () => {
  console.log(`server is running on port:- ${PORT}`);
});
