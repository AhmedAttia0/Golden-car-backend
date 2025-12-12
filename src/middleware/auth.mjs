import jwt from "jsonwebtoken";
const validateToken = (req, res, next) => {
  if (!req.session || !req.session.token) {
    return res.status(401).json({ message: "No active session" });
  }
  const token = req.session.token;
  try {
    // Verify the JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.id = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired session" });
  }
};

export default validateToken;
