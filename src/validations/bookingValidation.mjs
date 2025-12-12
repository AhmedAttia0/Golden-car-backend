import Joi from "joi";

const validateBooking = Joi.object({
  user: Joi.string().hex().length(24).required().messages({
    "string.length": "معرف المستخدم غير صالح",
    "any.required": "معرف المستخدم مطلوب",
  }),

  car: Joi.string().hex().length(24).required().messages({
    "string.length": "معرف السيارة غير صالح",
    "any.required": "معرف السيارة مطلوب",
  }),

  startDate: Joi.date().min("now").required().messages({
    "date.min": "لا يمكن حجز سيارة في تاريخ سابق",
    "any.required": "تاريخ بداية الحجز مطلوب",
  }),

  endDate: Joi.date().greater(Joi.ref("startDate")).required().messages({
    "date.greater": "تاريخ النهاية يجب أن يكون أكبر من تاريخ البداية",
    "any.required": "تاريخ نهاية الحجز مطلوب",
  }),

  totalPrice: Joi.number().positive().greater(0).required().messages({
    "number.greater": "السعر الإجمالي يجب أن يكون أكبر من 0",
    "any.required": "السعر الإجمالي مطلوب",
  }),

  status: Joi.string()
    .valid("قيد الانتظار", "تم التأكيد", "تم الإلغاء", "مكتمل")
    .default("قيد الانتظار")
    .messages({
      "any.only": "حالة الحجز غير صحيحة",
    }),
});

export default validateBooking;
