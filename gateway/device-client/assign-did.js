"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");

function hasFlag(name) {
    return process.argv.includes(`--${name}`);
}

/**
 * Validates the project-specific Fabric DID syntax.
 *
 * This validates the prototype's did:fabric identifier format.
 * It does not claim that did:fabric is a registered W3C DID method.
 *
 * @param {string} did
 * @returns {string}
 */
function validateDid(did) {
    if (!did || typeof did !== "string") {
        throw new Error("A DID must be supplied.");
    }

    const normalized = did.trim();

    if (!/^did:fabric:[A-Za-z0-9._-]+$/.test(normalized)) {
        throw new Error(
            "Invalid DID. Expected format: did:fabric:<identifier>"
        );
    }

    return normalized;
}

async function readRequiredFile(filePath, description) {
    try {
        return await fs.readFile(filePath, "utf8");
    } catch (error) {
        if (error.code === "ENOENT") {
            throw new Error(
                `${description} was not found at ${filePath}`
            );
        }

        throw error;
    }
}

async function readEnrollment(enrollmentPath) {
    const contents = await readRequiredFile(
        enrollmentPath,
        "enrollment.json"
    );

    try {
        return JSON.parse(contents);
    } catch (error) {
        throw new Error(
            `enrollment.json is invalid JSON: ${error.message}`
        );
    }
}

async function fileExists(filePath) {
    try {
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
}

async function main() {
    const directoryArgument = process.argv[2];
    const didArgument = process.argv[3];

    if (!directoryArgument || !didArgument) {
        throw new Error(
            "Usage: node assign-did.js " +
            "devices/<device-folder> did:fabric:<identifier>"
        );
    }

    const deviceDirectory = path.resolve(
        __dirname,
        directoryArgument
    );

    const did = validateDid(didArgument);

    const enrollmentPath = path.join(
        deviceDirectory,
        "enrollment.json"
    );

    const publicKeyPath = path.join(
        deviceDirectory,
        "public-key.pem"
    );

    const privateKeyPath = path.join(
        deviceDirectory,
        "private-key.pem"
    );

    const identityPath = path.join(
        deviceDirectory,
        "identity.json"
    );

    const enrollment = await readEnrollment(
        enrollmentPath
    );

    const publicKey = await readRequiredFile(
        publicKeyPath,
        "public-key.pem"
    );

    await readRequiredFile(
        privateKeyPath,
        "private-key.pem"
    );

    /*
     * Ensure the public key being provisioned is the same public key
     * that was included in the enrollment package.
     */
    if (
        typeof enrollment.publicKey !== "string" ||
        enrollment.publicKey.trim() !== publicKey.trim()
    ) {
        throw new Error(
            "public-key.pem does not match the public key in enrollment.json"
        );
    }

    /*
     * An enrollment package must never contain a private key.
     */
    if (
        Object.prototype.hasOwnProperty.call(
            enrollment,
            "privateKey"
        ) ||
        Object.prototype.hasOwnProperty.call(
            enrollment,
            "privateKeyPem"
        )
    ) {
        throw new Error(
            "Security violation: enrollment.json contains private-key material"
        );
    }

    if (
        await fileExists(identityPath) &&
        !hasFlag("force")
    ) {
        throw new Error(
            "identity.json already exists. " +
            "Use --force only if you intentionally want to replace it."
        );
    }

    const identity = {
        localDeviceId:
            enrollment.localDeviceId ||
            path.basename(deviceDirectory),

        did,

        owner: enrollment.owner,
        macAddress: enrollment.macAddress,
        allowedIpCidr: enrollment.allowedIpCidr,

        algorithm:
            enrollment.algorithm || "ECDSA",

        curve:
            enrollment.curve || "P-256",

        signatureHash:
            enrollment.signatureHash || "SHA-256",

        publicKeyFile: "public-key.pem",
        privateKeyFile: "private-key.pem",

        provisionedAt: new Date().toISOString()
    };

    await fs.writeFile(
        identityPath,
        JSON.stringify(identity, null, 2),
        {
            encoding: "utf8",
            mode: 0o600
        }
    );

    console.log(
        "\nDID assigned to local device successfully.\n"
    );

    console.log(
        JSON.stringify(
            {
                did,
                deviceDirectory,
                identityFile: identityPath,
                privateKeyRemainedLocal: true
            },
            null,
            2
        )
    );

    console.log(
        "\nThe device is now ready to authenticate."
    );
}

main().catch((error) => {
    console.error(
        `\nDID assignment failed: ${error.message}`
    );

    process.exit(1);
});