import User from "../models/User.mjs";
async function validateRole(req, res, next) {
  try {
    const user = await User.findById(req.id).lean(); // الصح
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    if (user.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Server error" });
  }
}

export default validateRole;
