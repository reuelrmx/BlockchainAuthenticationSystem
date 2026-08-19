"use strict";

const express = require("express");

const {
    getAuthenticationEvents,
    getAuthenticationEventById,
    getDeviceAuthenticationEvents
} = require("../controllers/auditController");
const {
    requireAdminAuthentication,
    requireAdminRole
} = require("../middleware/adminAuth");

const router = express.Router();
const canView = [
    requireAdminAuthentication,
    requireAdminRole("ADMIN", "VIEWER")
];

router.get("/authentication", canView, getAuthenticationEvents);
router.get("/authentication/:eventId", canView, getAuthenticationEventById);
router.get("/devices/:did/authentication", canView, getDeviceAuthenticationEvents);

module.exports = router;
