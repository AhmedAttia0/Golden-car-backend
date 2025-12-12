import Joi from "joi";

const validateUser = Joi.object({
  first_name: Joi.string()
    .min(3)
    .max(50)
    .pattern(/^[\p{Script=Arabic}a-zA-Z\s'-]+$/u)
    .required(),
  last_name: Joi.string()
    .min(3)
    .max(50)
    .pattern(/^[\p{Script=Arabic}a-zA-Z\s'-]+$/u)
    .required(),
  email: Joi.string().email().required(),
  password: Joi.string()
    .min(8)
    .max(30)
    .pattern(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
    )
    .required(),
  confirm_password: Joi.string()
    .min(8)
    .max(30)
    .valid(Joi.ref("password"))
    .required()
    .messages({ "any.only": "Passwords do not match" }),
  phone: Joi.string()
    .pattern(/^01[0125][0-9]{8}$/)
    .required(),
});
export default validateUser.with("password", "confirm_password");
