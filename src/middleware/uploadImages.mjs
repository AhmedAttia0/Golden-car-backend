// import multer from "multer";
// import path from "path";

// // مكان تخزين الصور
// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//     if (file.fieldname === "carImages") {
//       cb(null, "uploads/cars");
//     } else if (file.fieldname === "userImages") {
//       cb(null, "uploads/users");
//     } else {
//       cb(null, "uploads/others");
//     }
//   },
//   filename: function (req, file, cb) {
//     const ext = path.extname(file.originalname);
//     const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
//     cb(null, uniqueName);
//   },
// });

// // فلتر للتأكد إن الملفات صور فقط
// const fileFilter = (req, file, cb) => {
//   if (file.mimetype.startsWith("image/")) {
//     cb(null, true);
//   } else {
//     cb(new Error("جميع الملفات يجب أن تكون صور"), false);
//   }
// };

// export const upload = multer({
//   storage,
//   fileFilter,
//   limits: { fileSize: 5 * 1024 * 1024 }, // 5MB لكل صورة
// });
import multer from "multer";

// نخزن الملفات مؤقتًا في الذاكرة بدل الهارد
const storage = multer.memoryStorage();

// فلتر للتأكد إن الملفات صور فقط
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("جميع الملفات يجب أن تكون صور"), false);
  }
};

// إعدادات Multer
export const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB لكل صورة
});