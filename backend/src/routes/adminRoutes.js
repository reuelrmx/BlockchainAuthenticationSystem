"use strict";

const express = require("express");

const {
    getCurrentAdmin,
    login,
    logout
} = require("../controllers/adminController");
const {
    requireAdminAuthentication
} = require("../middleware/adminAuth");

const router = express.Router();

router.post("/login", login);
router.post("/logout", logout);
router.get("/me", requireAdminAuthentication, getCurrentAdmin);

module.exports = router;
