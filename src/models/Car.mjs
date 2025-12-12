import { Schema, model } from "mongoose";

const carSchema = new Schema({
  brand: {
    type: String,
    required: true,
  },

  model: {
    type: String,
    required: true,
  },

  type: {
    type: String,
    required: true,
  },

  price: {
    type: Number,
    required: true,
  },

  year: {
    type: Number,
    required: true,
  },

  status: {
    type: String,
    enum: ["متاحة", "تحت الصيانة"],
    default: "متاحة",
  },

  transmission: {
    type: String,
    enum: ["اوتوماتيكي", "يدوي"],
    required: true,
  },

  seats: {
    type: Number,
  },

  doors: {
    type: Number,
  },

  ac: {
    // air conditioner
    type: Boolean,
    required: true,
  },

  mileage: {
    type: Number,
    default: 0,
  },

  fuelType: {
    type: String,
    enum: ["بنزين", "ديزل", "كهرباء", "هجين"],
    default: "بنزين",
  },

  features: {
    type: [String], // ABS, Airbags, Cruise Control, ...
    default: [],
  },

  images: {
    type: [String],
    default: [],
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export default model("Car", carSchema);
