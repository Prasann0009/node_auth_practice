const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const userSchema = require("./schemas/userSchema");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

//constants
const app = express();
const PORT = process.env.PORT;

//middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(cookieParser());

//db Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(console.log("mongodb connected Successfully"))
  .catch((err) => console.log(err));

app.get("/", (req, res) => {
  return res.send(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Document</title>
  </head>
  <body>
    <form action="register" method="get">
      <button>Register</button>
    </form>

    <form action="login" method="get">
      <button>Login</button>
    </form>
  </body>
</html>
`);
});

app.get("/register", (req, res) => {
  return res.render("registerPage");
});

app.get("/login", (req, res) => {
  return res.render("loginPage");
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

    res.redirect("/login");
  } catch (error) {
    console.log(error);
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

    res.cookie("authToken", token, {
      httpOnly: true, //Prevent Javascript access to the cookie
      secure: process.env.NODE_ENV === "production", //Use secure cookies only in production
      sameSite: "strict", //prevent CSRF
      // maxAge: 60 * 60 * 1000, // 1 hour
    });

    res.redirect("/dashboard");
  } catch (error) {
    res.status(500).json({
      message: "server error",
      error: error,
    });
  }
});

const authenticateToken = (req, res, next) => {
  // const authHeader = req.headers["authorization"];
  // const token = authHeader && authHeader.split(" ")[1];

  const token = req.cookies.authToken;

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
  return res.send(`On Dashboard, Username:- ${req.user}`);
  // return res.json({
  //   message: "On Dashboard",
  //   user: req.user,
  // });
});
app.listen(PORT, () => {
  console.log(`server is running on URL:- ${process.env.URL}`);
});
