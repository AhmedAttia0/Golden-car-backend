import User from "../models/User.mjs";
import loginValidation from "../validations/loginValidation.mjs";
export default async function loginAttempt(req, res, next) {
  try {
    const { email, password, remember_me } = req.body;

    // 2) Validate email/password with Joi
    const { error, value } = loginValidation.validate({ email, password });
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }
    const user = await User.findByCredentials(email, password);
    const remember = Boolean(remember_me);
    const authOptions = {
      accessTokenExpiresIn: remember ? "7d" : "2h", // JWT option
      cookieMaxAgeMs: remember ? 7 * 24 * 60 * 60 * 1000 : 2 * 60 * 60 * 1000, // Cookie option
      remember,
    };
    // 6) Attach to req for the route handler
    req.user = user;
    req.authOptions = authOptions;

    next();
  } catch (err) {
    if (err.message === "Invalid email or password") {
      return res.status(401).json({ error: err.message });
    }
    return res.status(500).json({ error: "Server error" });
  }
}
