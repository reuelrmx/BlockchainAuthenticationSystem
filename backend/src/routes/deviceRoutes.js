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
const {
    requireAdminAuthentication,
    requireAdminRole
} = require("../middleware/adminAuth");

const router = express.Router();
const canView = [
    requireAdminAuthentication,
    requireAdminRole("ADMIN", "VIEWER")
];
const canManage = [
    requireAdminAuthentication,
    requireAdminRole("ADMIN")
];

router.post("/register", registerDevice);
router.get("/", canView, getAllDevices);
router.get("/:did", canView, getDevice);
router.patch("/:did/suspend", canManage, suspendDevice);
router.patch("/:did/activate", canManage, activateDevice);
router.patch("/:did/revoke", canManage, revokeDevice);

module.exports = router;
