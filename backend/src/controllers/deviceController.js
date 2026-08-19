"use strict";

const crypto = require("node:crypto");
const {
    submitAdminTransaction,
    evaluateTransaction
} = require("../services/fabricService");
const {
    buildMetadataRecord,
    deleteDeviceMetadata,
    mergeDeviceMetadata,
    saveDeviceMetadata
} = require("../services/deviceMetadataService");
const {
    hashMacAddress,
    normalizeAllowedIpCidr,
    normalizeMacAddress
} = require("../services/networkContextService");

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

function isValidFabricDid(did) {
    return (
        typeof did === "string" &&
        /^did:fabric:[^\s]+$/.test(did)
    );
}

function normalizePublicKey(publicKey) {
    if (
        typeof publicKey !== "string" ||
        publicKey.trim() === "" ||
        !publicKey.includes("-----BEGIN PUBLIC KEY-----") ||
        !publicKey.includes("-----END PUBLIC KEY-----") ||
        publicKey.includes("PRIVATE KEY")
    ) {
        return null;
    }

    return publicKey.trim();
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
            allowedIpCidr,
            did: suppliedDid
        } = req.body;

        const missingFields = [];

        if (!publicKey) missingFields.push("publicKey");
        if (!owner) missingFields.push("owner");
        if (!macAddress) missingFields.push("macAddress");
        if (!ipAddress && !allowedIpCidr) {
            missingFields.push("ipAddress");
        }

        if (missingFields.length > 0) {
            return res.status(400).json({
                success: false,
                message: "Required fields are missing",
                missingFields
            });
        }

        const normalizedPublicKey = normalizePublicKey(publicKey);
        const normalizedOwner = owner.trim();
        const normalizedMacAddress = normalizeMacAddress(macAddress);
        const normalizedAllowedIpCidr = normalizeAllowedIpCidr(
            allowedIpCidr || ipAddress
        );
        const did = suppliedDid ? suppliedDid.trim() : generateDid();

        if (!isValidFabricDid(did)) {
            return res.status(400).json({
                success: false,
                message: "DID must use the did:fabric:<identifier> format"
            });
        }

        if (!normalizedPublicKey) {
            return res.status(400).json({
                success: false,
                message: "Public key must be a PEM public key"
            });
        }

        if (!normalizedMacAddress) {
            return res.status(400).json({
                success: false,
                message: "MAC address must use AA:BB:CC:DD:EE:FF format"
            });
        }

        if (!normalizedAllowedIpCidr) {
            return res.status(400).json({
                success: false,
                message: "Allowed IP context must be an IPv4 address or CIDR range"
            });
        }

        const metadataRecord = buildMetadataRecord({
            did,
            owner: normalizedOwner,
            rawMacAddress: normalizedMacAddress,
            allowedIpCidr: normalizedAllowedIpCidr,
            publicKey: normalizedPublicKey
        });

        saveDeviceMetadata(metadataRecord);

        let device;

        try {
            device = await submitAdminTransaction(
                "RegisterDevice",
                did,
                normalizedPublicKey,
                normalizedOwner,
                hashMacAddress(normalizedMacAddress),
                normalizedAllowedIpCidr,
                metadataRecord.metadataHash,
                metadataRecord.didDocumentHash
            );
        } catch (error) {
            deleteDeviceMetadata(did);
            throw error;
        }

        return res.status(201).json({
            success: true,
            message: "Device registered successfully",
            data: mergeDeviceMetadata(device)
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
            data: mergeDeviceMetadata(device)
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
        const mergedDevices = Array.isArray(devices)
            ? devices.map(mergeDeviceMetadata)
            : devices;

        return res.status(200).json({
            success: true,
            count: Array.isArray(mergedDevices)
                ? mergedDevices.length
                : 0,
            data: mergedDevices
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

        const device = await submitAdminTransaction(
            "SuspendDevice",
            req.params.did,
            reason
        );

        return res.status(200).json({
            success: true,
            message: "Device suspended",
            data: mergeDeviceMetadata(device)
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
        const device = await submitAdminTransaction(
            "ActivateDevice",
            req.params.did
        );

        return res.status(200).json({
            success: true,
            message: "Device activated",
            data: mergeDeviceMetadata(device)
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

        const device = await submitAdminTransaction(
            "RevokeDevice",
            req.params.did,
            reason
        );

        return res.status(200).json({
            success: true,
            message: "Device revoked permanently",
            data: mergeDeviceMetadata(device)
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
