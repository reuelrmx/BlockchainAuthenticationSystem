"use strict";

const express = require("express");

const {
    getPerformanceSummary
} = require("../controllers/performanceController");
const {
    requireAdminAuthentication,
    requireAdminRole
} = require("../middleware/adminAuth");

const router = express.Router();
const canView = [
    requireAdminAuthentication,
    requireAdminRole("ADMIN", "VIEWER")
];

router.get("/summary", canView, getPerformanceSummary);

module.exports = router;
