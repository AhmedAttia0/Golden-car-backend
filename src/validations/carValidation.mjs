import Joi from "joi";

const validateCar = Joi.object({
  brand: Joi.string()
    .trim()
    .pattern(/^[^<>]*$/) // Remove HTML tags
    .required()
    .messages({
      "string.pattern.base": "الاسم لا يمكن أن يحتوي على علامات HTML",
    }),
  model: Joi.string()
    .required()
    .trim()
    .pattern(/^[^<>]*$/)
    .messages({
      "string.pattern.base": "الاسم لا يمكن أن يحتوي على علامات HTML",
    }),
  type: Joi.string()
    .required()
    .trim()
    .pattern(/^[^<>]*$/)
    .messages({
      "string.pattern.base": "الاسم لا يمكن أن يحتوي على علامات HTML",
    }),
  price: Joi.number().required(),
  year: Joi.number().min(1900).max(new Date().getFullYear()).required(),
  status: Joi.string().valid("متاحة", "تحت الصيانة").default("متاحة"),
  transmission: Joi.string().valid("اوتوماتيكي", "يدوي").required(),
  mileage: Joi.number().min(0).default(0),
  fuelType: Joi.string()
    .valid("بنزين", "ديزل", "كهرباء", "هجين")
    .default("بنزين"),
  seats: Joi.number().min(1).default(4),
  doors: Joi.number().min(1).default(4),
  ac: Joi.boolean().required(),
  mileage: Joi.number().min(0).default(0),
  features: Joi.array().items(Joi.string()).default([]),
  images: Joi.array().items(Joi.string()).default([]),
});
export default validateCar;
