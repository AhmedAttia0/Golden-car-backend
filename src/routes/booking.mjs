import { Router } from "express";
import bookingSchema from "../models/Booking.mjs";
import validateBooking from "../validations/bookingValidation.mjs";
import Car from "../models/Car.mjs";
import validateToken from "../middleware/auth.mjs";
import csrfDoubleSubmit from "../middleware/csrfDoubleSubmit.mjs";
import validateRole from "../middleware/authz.mjs";
import User from "../models/User.mjs";
const router = Router();

router.get("/", validateToken, validateRole, async (req, res) => {
  let { page = 1, limit = 10 } = req.query;

  page = Number(page);
  limit = Number(limit);
  if (isNaN(page) || page < 1) page = 1;
  if (isNaN(limit) || limit < 1) limit = 10;
  if (limit > 100) limit = 100;

  const skip = (page - 1) * limit;
  try {
    const total = await bookingSchema.countDocuments();
    const total_pages = Math.ceil(total / limit);
    if (page > total_pages && total_pages > 0) {
      return res.status(404).send({ message: "Page not found" });
    }

    const bookings = await bookingSchema
      .find()
      .skip(skip)
      .limit(limit)
      .populate("user")
      .populate("car")
      .lean();

    const sanitizedBookings = bookings.map((booking) => {
      booking.id = booking._id.toString();
      booking.user.id = booking.user._id.toString();
      booking.car.id = booking.car._id.toString();
      delete booking.user._id;
      delete booking.car._id;
      delete booking.user.__v;
      delete booking.car.__v;
      delete booking.user.createdAt;
      delete booking.car.createdAt;
      delete booking._id;
      delete booking.__v;
      delete booking.createdAt;
      return booking;
    });

    res.send({
      page,
      limit,
      totalBookings: total,
      totalPages: total_pages,
      bookings: sanitizedBookings,
    });
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
});

router.get("/:id", async (req, res) => {
  const booking = await bookingSchema
    .findById(req.params.id)
    .populate("car")
    .populate("user");
  if (!booking)
    return res.status(404).send({ message: "لم يتم العثور على الحجز" });
  res.send(booking);
});

router.post(
  "/",
  csrfDoubleSubmit,
  validateToken,
  validateRole,
  async (req, res) => {
    try {
      await validateBooking.validateAsync(req.body);

      const {
        user: userId,
        car: carId,
        startDate,
        endDate,
        totalPrice,
        status,
      } = req.body;
      const user = await User.findById(userId);

      if (!user)
        return res.status(404).send({ message: "لم يتم العثور على المستخدم" });

      if (user.role === "banned") {
        return res
          .status(403)
          .send({ message: "هذا المستخدم غير مسموح له بالحجز" });
      }
      const car = await Car.findById(carId);
      if (!car)
        return res.status(404).send({ message: "لم يتم العثور على السيارة" });

      if (car.status === "تحت الصيانة") {
        return res
          .status(400)
          .send({ message: "السيارة تحت الصيانة ولا يمكن حجزها حاليا" });
      }

      const overlappingBooking = await bookingSchema.findOne({
        car: carId,
        $or: [
          { startDate: { $lte: new Date(endDate), $gte: new Date(startDate) } },
          { endDate: { $gte: new Date(startDate), $lte: new Date(endDate) } },
          {
            startDate: { $lte: new Date(startDate) },
            endDate: { $gte: new Date(endDate) },
          },
        ],
        status: { $in: ["قيد الانتظار", "تم التأكيد"] },
      });

      if (overlappingBooking) {
        return res.status(400).send({ message: "السيارة محجوزة في هذا الوقت" });
      }

      const booking = await bookingSchema.create({
        user: userId,
        car: carId,
        startDate,
        endDate,
        totalPrice,
        status,
      });

      res.status(201).send({ message: "تم حجز السيارة بنجاح", booking });
    } catch (error) {
      res.status(400).send({ message: error.message });
    }
  }
);

router.put("/:id", csrfDoubleSubmit, async (req, res) => {
  try {
    await validateBooking.validateAsync(req.body);
    const booking = await bookingSchema.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
      }
    );
    if (!booking)
      return res.status(404).send({ message: "لم يتم العثور على الحجز" });
    res.send({ message: "تم تحديث الحجز بنجاح", booking });
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
});

export default router;
