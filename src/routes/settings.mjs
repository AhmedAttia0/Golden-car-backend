import { Router } from "express";
import Settings from "../models/Settings.mjs";
import validateSettingsForm from "../validations/settingsvalidation.mjs";
import csrfDoubleSubmit from "../middleware/csrfDoubleSubmit.mjs";
import validateToken from "../middleware/auth.mjs";
import validateRole from "../middleware/authz.mjs";

const router = Router();

router.get("/", async (req, res) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({
        companyName: "",
        supportEmail: "",
        phone: "",
        address: "",
        city: "",
        state: "",
        zipCode: "",
        country: "",
      });
    }
    res.json(settings);
  } catch (error) {
    res.status(500).send({ message: "حدث خطأ داخلي", error: error.message });
  }
});

router.put(
  "/",
  csrfDoubleSubmit,
  validateToken,
  validateRole,
  async (req, res) => {
    try {
      await validateSettingsForm.validateAsync(req.body, { abortEarly: false });

      let settings = await Settings.findOne();
      if (!settings) {
        settings = await Settings.create(req.body);
      } else {
        Object.assign(settings, req.body);
        await settings.save();
      }

      res.send({ message: "تم تحديث الإعدادات بنجاح", settings });
    } catch (error) {
      res.status(400).send({ message: error.message });
    }
  }
);

export default router;
