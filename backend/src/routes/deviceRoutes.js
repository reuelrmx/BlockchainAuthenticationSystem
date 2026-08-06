"use strict";

const express = require("express");

const {
    registerDevice,
    getDevice,
    getAllDevices,
    suspendDevice,
    activateDevice,
    revokeDevice
} = require("../controllers/deviceController");

const router = express.Router();

router.get("/", getAllDevices);
router.get("/:did", getDevice);
router.post("/register", registerDevice);
router.patch("/:did/suspend", suspendDevice);
router.patch("/:did/activate", activateDevice);
router.patch("/:did/revoke", revokeDevice);

module.exports = router;