import mongoose, { Schema, model } from "mongoose";

const bookingSchema = new Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },

  car: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Car",
    required: true,
  },

  startDate: {
    type: Date,
    required: true,
  },

  endDate: {
    type: Date,
    required: true,
  },

  totalPrice: {
    type: Number,
    required: true,
  },

  status: {
    type: String,
    enum: ["قيد الانتظار", "تم التأكيد", "تم الإلغاء", "مكتمل"],
    default: "قيد الانتظار",
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export default model("Booking", bookingSchema);
