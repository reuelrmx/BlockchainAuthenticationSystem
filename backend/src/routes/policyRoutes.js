"use strict";

const express = require("express");

const {
    getPolicy,
    updatePolicy
} = require("../controllers/policyController");
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

router.get("/", canView, getPolicy);
router.put("/", canManage, updatePolicy);

module.exports = router;
