"use strict";

function errorHandler(error, req, res, next) {
    console.error("Request failed:", error);

    const message =
        error.details?.[0]?.message ||
        error.message ||
        "Unexpected server error";

    let statusCode = Number.isSafeInteger(error.statusCode)
        ? error.statusCode
        : 500;

    if (statusCode === 500 && (
        message.includes("does not exist") ||
        message.includes("not found")
    )) {
        statusCode = 404;
    }

    if (statusCode === 500 && (
        message.includes("already registered") ||
        message.includes("already revoked") ||
        message.includes("already suspended") ||
        message.includes("already active")
    )) {
        statusCode = 409;
    }

    if (statusCode === 500 && (
        message.includes("is required") ||
        message.includes("invalid")
    )) {
        statusCode = 400;
    }

    res.status(statusCode).json({
        success: false,
        message
    });
}

module.exports = errorHandler;
