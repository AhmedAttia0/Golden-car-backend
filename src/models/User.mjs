import { Schema, model } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
const userSchema = new Schema({
  first_name: {
    type: String,
    required: true,
    match: [
      /^[\p{Script=Arabic}a-zA-Z\s'-]+$/u,
      "يجب أن تحتوي الأسامي على أحرف فقط",
    ],
  },
  last_name: {
    type: String,
    required: true,
    match: [
      /^[\p{Script=Arabic}a-zA-Z\s'-]+$/u,
      "يجب أن تحتوي الأسامي على أحرف فقط",
    ],
  },
  email: {
    type: String,
    required: true,
    unique: true,
    match: [
      /^(?:[a-zA-Z0-9_'^&/+-])+(?:\.(?:[a-zA-Z0-9_'^&/+-])+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/,
      "من فضلك أدخل بريدًا إلكترونيًا صحيحًا",
    ],
  },

  password: {
    type: String,
    required: true,
    minlength: 8,
    maxlength: 30,
    match: [
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
      "يجب أن تحتوي كلمة السر على  علي الأقل حرف كابيتال واحد، حرف سمول واحد، رقم واحد، رمز من هذه الرموز@?!%&*$",
    ],
  },

  phone: {
    type: String,
    required: true,
    match: [/^01[0125][0-9]{8}$/, "يجب إدخال رقم تليفون صالح"],
  },

  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});
userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.statics.findByCredentials = async function (email, password) {
  const user = await User.findOne({ email: email }).lean();

  if (!user) {
    throw new Error("Invalid email or password");
  }
  const isPasswordMatch = await bcrypt.compare(password, user.password);

  if (!isPasswordMatch) {
    throw new Error("Invalid email or password");
  }
  return user;
};

userSchema.methods.generateToken = function (authOptions) {
  return jwt.sign({ id: this._id.toString() }, process.env.JWT_SECRET, {
    expiresIn: authOptions,
  });
};
const User = model("User", userSchema);

export default User;
