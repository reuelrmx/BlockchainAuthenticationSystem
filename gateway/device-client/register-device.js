"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEFAULT_API_URL = "http://localhost:3000";

/**
 * Reads a named command-line argument.
 *
 * Example:
 * node register-device.js --owner "CBU Lab" --mac "AA:BB:CC:DD:EE:FF"
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
 * Ensures a value was supplied.
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
 * Performs basic MAC-address validation.
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
 * @returns {string}
 */
function validateIpAddress(ipAddress) {
    const value = ipAddress.trim();
    const sections = value.split(".");

    const valid =
        sections.length === 4 &&
        sections.every((section) => {
            if (!/^\d{1,3}$/.test(section)) {
                return false;
            }

            const number = Number(section);

            return number >= 0 && number <= 255;
        });

    if (!valid) {
        throw new Error(
            "Invalid IPv4 address. Expected format: 192.168.1.10"
        );
    }

    return value;
}

/**
 * Generates a device ECDSA key pair.
 *
 * The private key uses PKCS#8 PEM format.
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

/**
 * Registers the public key through the gateway.
 *
 * @param {string} apiUrl
 * @param {object} registration
 * @returns {Promise<object>}
 */
async function registerWithGateway(apiUrl, registration) {
    const response = await fetch(
        `${apiUrl}/api/devices/register`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(registration)
        }
    );

    let body;

    try {
        body = await response.json();
    } catch {
        throw new Error(
            `Gateway returned a non-JSON response with status ${response.status}`
        );
    }

    if (!response.ok || !body.success) {
        throw new Error(
            body.message ||
            `Gateway registration failed with status ${response.status}`
        );
    }

    return body;
}

async function main() {
    const owner = requireArgument(
        getArgument("owner"),
        "owner"
    );

    const macAddress = normalizeMacAddress(
        requireArgument(getArgument("mac"), "mac")
    );

    const ipAddress = validateIpAddress(
        requireArgument(getArgument("ip"), "ip")
    );

    const apiUrl =
        getArgument("api") ||
        process.env.GATEWAY_API_URL ||
        DEFAULT_API_URL;

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
        const { publicKey, privateKey } =
            generateDeviceKeyPair();

        const privateKeyPath = path.join(
            deviceDirectory,
            "private-key.pem"
        );

        const publicKeyPath = path.join(
            deviceDirectory,
            "public-key.pem"
        );

        const identityPath = path.join(
            deviceDirectory,
            "identity.json"
        );

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

        const result = await registerWithGateway(
            apiUrl,
            {
                publicKey,
                owner,
                macAddress,
                ipAddress
            }
        );

        const device = result.data;

        const localIdentity = {
            localDeviceId,
            did: device.did,
            owner,
            macAddress,
            ipAddress,
            algorithm: "ECDSA",
            curve: "P-256",
            signatureHash: "SHA-256",
            status: device.status,
            registeredAt: device.registeredAt,
            publicKeyFile: "public-key.pem",
            privateKeyFile: "private-key.pem"
        };

        await fs.writeFile(
            identityPath,
            JSON.stringify(localIdentity, null, 2),
            {
                encoding: "utf8",
                mode: 0o600
            }
        );

        console.log("\nDevice registered successfully\n");

        console.log(
            JSON.stringify(
                {
                    did: device.did,
                    owner,
                    macAddress,
                    ipAddress,
                    status: device.status,
                    localDirectory: deviceDirectory,
                    privateKeyStoredLocally: true,
                    publicKeyRegisteredOnBlockchain: true
                },
                null,
                2
            )
        );

        console.log(
            "\nImportant: Do not share or commit private-key.pem."
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
    console.error(`\nDevice registration failed: ${error.message}`);
    process.exit(1);
});