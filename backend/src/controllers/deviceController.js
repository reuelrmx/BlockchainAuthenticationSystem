"use strict";

const crypto = require("node:crypto");
const {
    submitTransaction,
    evaluateTransaction
} = require("../services/fabricService");

/**
 * Creates a simple project DID.
 *
 * This is currently a prototype DID method identifier.
 * It will later be documented as did:fabric:<UUID>.
 *
 * @returns {string}
 */
function generateDid() {
    return `did:fabric:${crypto.randomUUID()}`;
}

/**
 * POST /api/devices/register
 */
async function registerDevice(req, res, next) {
    try {
        const {
            publicKey,
            owner,
            macAddress,
            ipAddress,
            did: suppliedDid
        } = req.body;

        const missingFields = [];

        if (!publicKey) missingFields.push("publicKey");
        if (!owner) missingFields.push("owner");
        if (!macAddress) missingFields.push("macAddress");
        if (!ipAddress) missingFields.push("ipAddress");

        if (missingFields.length > 0) {
            return res.status(400).json({
                success: false,
                message: "Required fields are missing",
                missingFields
            });
        }

        const did = suppliedDid || generateDid();

        const device = await submitTransaction(
            "RegisterDevice",
            did,
            publicKey,
            owner,
            macAddress,
            ipAddress
        );

        return res.status(201).json({
            success: true,
            message: "Device registered successfully",
            data: device
        });
    } catch (error) {
        next(error);
    }
}

/**
 * GET /api/devices/:did
 */
async function getDevice(req, res, next) {
    try {
        const device = await evaluateTransaction(
            "GetDevice",
            req.params.did
        );

        return res.status(200).json({
            success: true,
            data: device
        });
    } catch (error) {
        next(error);
    }
}

/**
 * GET /api/devices
 */
async function getAllDevices(req, res, next) {
    try {
        const devices = await evaluateTransaction(
            "GetAllDevices"
        );

        return res.status(200).json({
            success: true,
            count: Array.isArray(devices)
                ? devices.length
                : 0,
            data: devices
        });
    } catch (error) {
        next(error);
    }
}

/**
 * PATCH /api/devices/:did/suspend
 */
async function suspendDevice(req, res, next) {
    try {
        const { reason } = req.body;

        if (!reason) {
            return res.status(400).json({
                success: false,
                message: "Suspension reason is required"
            });
        }

        const device = await submitTransaction(
            "SuspendDevice",
            req.params.did,
            reason
        );

        return res.status(200).json({
            success: true,
            message: "Device suspended",
            data: device
        });
    } catch (error) {
        next(error);
    }
}

/**
 * PATCH /api/devices/:did/activate
 */
async function activateDevice(req, res, next) {
    try {
        const device = await submitTransaction(
            "ActivateDevice",
            req.params.did
        );

        return res.status(200).json({
            success: true,
            message: "Device activated",
            data: device
        });
    } catch (error) {
        next(error);
    }
}

/**
 * PATCH /api/devices/:did/revoke
 */
async function revokeDevice(req, res, next) {
    try {
        const { reason } = req.body;

        if (!reason) {
            return res.status(400).json({
                success: false,
                message: "Revocation reason is required"
            });
        }

        const device = await submitTransaction(
            "RevokeDevice",
            req.params.did,
            reason
        );

        return res.status(200).json({
            success: true,
            message: "Device revoked permanently",
            data: device
        });
    } catch (error) {
        next(error);
    }
}

module.exports = {
    registerDevice,
    getDevice,
    getAllDevices,
    suspendDevice,
    activateDevice,
    revokeDevice
};