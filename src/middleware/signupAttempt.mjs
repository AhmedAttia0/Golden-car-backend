import userValidation from "../validations/userValidation.mjs";
export default async function signupAttempt(req, res, next) {
  const user = req.body;
  const { error, value } = userValidation.validate(user);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  next();
}
