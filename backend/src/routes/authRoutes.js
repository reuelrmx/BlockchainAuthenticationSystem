"use strict";

const express = require("express");

const {
    createAuthenticationChallenge,
    verifyAuthenticationChallenge
} = require("../controllers/authController");

const router = express.Router();

router.post("/challenge", createAuthenticationChallenge);
router.post("/verify", verifyAuthenticationChallenge);

module.exports = router;
