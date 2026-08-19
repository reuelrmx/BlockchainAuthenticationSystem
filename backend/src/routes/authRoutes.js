"use strict";

const express = require("express");

const {
    createAuthenticationChallenge
} = require("../controllers/authController");

const router = express.Router();

router.post("/challenge", createAuthenticationChallenge);

module.exports = router;
