import Joi from "joi";

const validateUserUpdate = Joi.object({
  first_name: Joi.string()
    .min(3)
    .max(50)
    .pattern(/^[\p{Script=Arabic}a-zA-Z\s'-]+$/u)
    .optional(),
  last_name: Joi.string()
    .min(3)
    .max(50)
    .pattern(/^[\p{Script=Arabic}a-zA-Z\s'-]+$/u)
    .optional(),
  email: Joi.string().email().required(),
  password: Joi.string()
    .min(8)
    .max(30)
    .pattern(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
    )
    .optional(),
  confirm_password: Joi.string()
    .min(8)
    .max(30)
    .valid(Joi.ref("password"))
    .optional()
    .messages({ "any.only": "Passwords do not match" }),
  phone: Joi.string()
    .pattern(/^01[0125][0-9]{8}$/)
    .optional(),
}).min(1);
export default validateUserUpdate.with("password", "confirm_password");
