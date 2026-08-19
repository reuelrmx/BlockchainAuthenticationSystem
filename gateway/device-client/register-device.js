"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

/**
 * Reads a named command-line argument.
 *
 * Example:
 * node register-device.js --owner "CBU Lab" \
 *   --mac "AA:BB:CC:DD:EE:FF" \
 *   --ip "192.168.1.30"
 *
 * @param {string} name
 * @returns {string|null}
 */
function getArgument(name) {
    const index = process.argv.indexOf(`--${name}`);

    if (index === -1 || index + 1 >= process.argv.length) {
        return null;
    }

    return process.argv[index + 1];
}

/**
 * Ensures that a required command-line argument was supplied.
 *
 * @param {string|null} value
 * @param {string} name
 * @returns {string}
 */
function requireArgument(value, name) {
    if (!value || value.trim() === "") {
        throw new Error(`Missing required argument: --${name}`);
    }

    return value.trim();
}

/**
 * Validates and normalizes a MAC address.
 *
 * @param {string} macAddress
 * @returns {string}
 */
function normalizeMacAddress(macAddress) {
    const normalized = macAddress.trim().toUpperCase();

    const pattern =
        /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/;

    if (!pattern.test(normalized)) {
        throw new Error(
            "Invalid MAC address. Expected format: AA:BB:CC:DD:EE:FF"
        );
    }

    return normalized;
}

/**
 * Performs basic IPv4 validation.
 *
 * @param {string} ipAddress
 * @returns {boolean}
 */
function validateIpv4Address(ipAddress) {
    const sections = ipAddress.trim().split(".");

    return sections.length === 4 &&
        sections.every((section) => {
            if (!/^\d{1,3}$/.test(section)) {
                return false;
            }

            const number = Number(section);

            return number >= 0 && number <= 255;
        });
}

/**
 * Accepts either a single IPv4 address or CIDR range.
 *
 * A single address is normalized to /32.
 *
 * Examples:
 * 192.168.1.30    -> 192.168.1.30/32
 * 192.168.1.0/24  -> 192.168.1.0/24
 *
 * @param {string} ipContext
 * @returns {string}
 */
function normalizeAllowedIpCidr(ipContext) {
    const value = ipContext.trim();
    const parts = value.split("/");

    if (parts.length > 2) {
        throw new Error(
            "Invalid IP context. Expected IPv4 or CIDR."
        );
    }

    const address = parts[0];
    const prefix = parts[1];

    if (!validateIpv4Address(address)) {
        throw new Error(
            "Invalid IP context. Expected IPv4 or CIDR, " +
            "for example 192.168.1.10 or 192.168.1.0/24"
        );
    }

    if (prefix === undefined) {
        return `${address}/32`;
    }

    if (!/^\d{1,2}$/.test(prefix)) {
        throw new Error(
            "Invalid CIDR prefix. Expected range: 0-32"
        );
    }

    const prefixLength = Number(prefix);

    if (prefixLength < 0 || prefixLength > 32) {
        throw new Error(
            "Invalid CIDR prefix. Expected range: 0-32"
        );
    }

    return `${address}/${prefixLength}`;
}

/**
 * Generates the device's ECDSA P-256 key pair.
 *
 * The private key is stored locally using PKCS#8 PEM format.
 * The public key uses SPKI PEM format.
 *
 * @returns {{publicKey: string, privateKey: string}}
 */
function generateDeviceKeyPair() {
    return crypto.generateKeyPairSync("ec", {
        namedCurve: "prime256v1",

        publicKeyEncoding: {
            type: "spki",
            format: "pem"
        },

        privateKeyEncoding: {
            type: "pkcs8",
            format: "pem"
        }
    });
}

async function main() {
    const owner = requireArgument(
        getArgument("owner"),
        "owner"
    );

    const macAddress = normalizeMacAddress(
        requireArgument(
            getArgument("mac"),
            "mac"
        )
    );

    const allowedIpCidr = normalizeAllowedIpCidr(
        requireArgument(
            getArgument("ip"),
            "ip"
        )
    );

    const localDeviceId = crypto.randomUUID();

    const devicesDirectory = path.join(
        __dirname,
        "devices"
    );

    const deviceDirectory = path.join(
        devicesDirectory,
        localDeviceId
    );

    await fs.mkdir(deviceDirectory, {
        recursive: true,
        mode: 0o700
    });

    try {
        const {
            publicKey,
            privateKey
        } = generateDeviceKeyPair();

        const privateKeyPath = path.join(
            deviceDirectory,
            "private-key.pem"
        );

        const publicKeyPath = path.join(
            deviceDirectory,
            "public-key.pem"
        );

        const enrollmentPath = path.join(
            deviceDirectory,
            "enrollment.json"
        );

        /*
         * The private key must remain exclusively on the device.
         */
        await fs.writeFile(
            privateKeyPath,
            privateKey,
            {
                encoding: "utf8",
                mode: 0o600
            }
        );

        await fs.writeFile(
            publicKeyPath,
            publicKey,
            {
                encoding: "utf8",
                mode: 0o644
            }
        );

        /*
         * enrollment.json contains PUBLIC registration information
         * only. It can safely be supplied to the administrator for
         * registration through the Administrator Dashboard.
         */
        const enrollment = {
            localDeviceId,
            owner,
            macAddress,
            allowedIpCidr,
            publicKey,
            algorithm: "ECDSA",
            curve: "P-256",
            signatureHash: "SHA-256",
            preparedAt: new Date().toISOString()
        };

        await fs.writeFile(
            enrollmentPath,
            JSON.stringify(enrollment, null, 2),
            {
                encoding: "utf8",
                mode: 0o600
            }
        );

        console.log(
            "\nDevice enrollment package created successfully.\n"
        );

        console.log(
            JSON.stringify(
                {
                    localDeviceId,
                    owner,
                    macAddress,
                    allowedIpCidr,
                    localDirectory: deviceDirectory,
                    enrollmentFile: enrollmentPath,
                    privateKeyStoredLocally: true,
                    blockchainRegistrationPerformed: false
                },
                null,
                2
            )
        );

        console.log(
            "\nNext step:"
        );

        console.log(
            "Give the public information in enrollment.json " +
            "to an authorized administrator."
        );

        console.log(
            "The administrator must register the device through " +
            "the Administrator Dashboard."
        );

        console.log(
            "After registration, assign the returned DID to this " +
            "device using assign-did.js."
        );

        console.log(
            "\nIMPORTANT: Never share or commit private-key.pem."
        );
    } catch (error) {
        await fs.rm(deviceDirectory, {
            recursive: true,
            force: true
        });

        throw error;
    }
}

main().catch((error) => {
    console.error(
        `\nDevice enrollment preparation failed: ${error.message}`
    );

    process.exit(1);
});