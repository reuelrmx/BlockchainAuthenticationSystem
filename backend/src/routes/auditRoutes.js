"use strict";

const express = require("express");

const {
    getAuthenticationEvents,
    getAuthenticationEventById,
    getDeviceAuthenticationEvents
} = require("../controllers/auditController");

const router = express.Router();

router.get("/authentication", getAuthenticationEvents);
router.get("/authentication/:eventId", getAuthenticationEventById);
router.get("/devices/:did/authentication", getDeviceAuthenticationEvents);

module.exports = router;
