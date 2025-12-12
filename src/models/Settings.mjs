import { Schema, model } from "mongoose";

const settingsSchema = new Schema(
  {
    companyName: {
      type: String,
      required: true,
      trim: true,
    },

    supportEmail: {
      type: String,
      required: true,
      match: /^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/, // Regex للتحقق من الإيميل
    },

    phone: {
      type: String,
      required: true,
      trim: true,
    },

    address: {
      type: String,
      default: "",
      trim: true,
    },

    city: {
      type: String,
      default: "",
      trim: true,
    },

    state: {
      type: String,
      default: "",
      trim: true,
    },

    zipCode: {
      type: String,
      default: "",
      trim: true,
    },

    country: {
      type: String,
      default: "",
      trim: true,
    },
  },
  {
    timestamps: true, // إضافة createdAt & updatedAt تلقائيًا
  }
);

export default model("Settings", settingsSchema);
