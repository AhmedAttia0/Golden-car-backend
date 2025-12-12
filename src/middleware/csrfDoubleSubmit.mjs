export default function csrfDoubleSubmit(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }
  const headerToken = req.get("X-CSRF-Token") || req.get("X-CSRF-TOKEN");
  const cookieToken = req.cookies && req.cookies["XSRF-TOKEN"];

  if (!headerToken || !cookieToken) {
    return res.status(403).json({ error: "CSRF token missing" });
  }
  if (headerToken !== cookieToken) {
    return res.status(403).json({ error: "CSRF token mismatch" });
  }
  next();
}
