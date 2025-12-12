import { Router } from "express";
import loginAttempt from "../middleware/loginAttempt.mjs";
import signupAttempt from "../middleware/signupAttempt.mjs";
import User from "../models/User.mjs";
import crypto from "crypto";
import { rateLimit } from "express-rate-limit";
import csrfDoubleSubmit from "../middleware/csrfDoubleSubmit.mjs";
import validateToken from "../middleware/auth.mjs";
import validateUserUpdate from "../validations/userUpdateValidation.mjs";

const userRouter = Router();
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: "Too many login attempts, try again later!",
});
userRouter.post("/login", limiter, loginAttempt, (req, res) => {
  try {
    let { user, authOptions } = req;
    const mongooseUser = new User(user);
    const token = mongooseUser.generateToken(authOptions.accessTokenExpiresIn);
    const cookieMaxAgeMs = authOptions.cookieMaxAgeMs;
    req.session.token = token;
    req.sessionOptions.maxAge = cookieMaxAgeMs;
    delete user.password;
    delete user.__v;
    delete user.createdAt;
    delete user.role;
    user.id = user._id.toString();
    delete user._id;
    const csrfToken = crypto.randomBytes(32).toString("hex");
    res.cookie("XSRF-TOKEN", csrfToken, {
      maxAge: cookieMaxAgeMs,
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    });
    res.status(200).json({
      message: "Login successful",
      user: user,
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Server Error" });
  }
});

userRouter.post("/signup", signupAttempt, async (req, res) => {
  try {
    const user = req.body;
    // Check if email already exists
    const existingUser = await User.findOne({ email: user.email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already in use" });
    }
    const newUser = new User(user);
    await newUser.save();
    const token = newUser.generateToken(24 * 60 * 60 * 1000); // 1 day
    req.session.token = token;
    req.sessionOptions.maxAge = 2 * 60 * 60 * 1000;
    delete user.password;
    delete user.confirm_password;
    user.id = newUser._id.toString();
    const csrfToken = crypto.randomBytes(32).toString("hex");
    res.cookie("XSRF-TOKEN", csrfToken, {
      maxAge: 2 * 60 * 60 * 1000,
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    });
    res.status(201).json({ message: "User created successfully", user: user });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Server error" });
  }
});

userRouter.post("/logout", (req, res) => {
  req.session = null;
  res.clearCookie("XSRF-TOKEN");
  res.status(200).json({ message: "Logged out successfully" });
});

userRouter.delete("/:id", csrfDoubleSubmit, validateToken, async (req, res) => {
  try {
    const userId = req.id;
    const deletedUser = await User.findByIdAndDelete(userId);
    if (!deletedUser) {
      return res.status(404).json({ error: "User not found" });
    }
    res.status(200).json({ message: "User deleted successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Server error" });
  }
});

userRouter.put("/:id", csrfDoubleSubmit, validateToken, async (req, res) => {
  try {
    const userId = req.id;
    const updates = req.body;
    const { error } = validateUserUpdate.validate(updates);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }
    if (updates.id !== userId) {
      return res.status(403).json({ error: "Forbidden" });
    }
    delete updates.confirm_password;
    const updatedUser = await User.findByIdAndUpdate(userId, updates, {
      new: true,
    }).lean();
    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }
    delete updatedUser.password;
    delete updatedUser.__v;
    delete updatedUser.createdAt;
    delete updatedUser.role;
    res
      .status(200)
      .json({ message: "User updated successfully", user: updatedUser });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Server error" });
  }
});

export default userRouter;
