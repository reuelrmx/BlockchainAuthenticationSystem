"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const DEFAULT_API_URL = "http://localhost:3000";

function getArgument(name) {
    const index = process.argv.indexOf(`--${name}`);

    if (index === -1 || index + 1 >= process.argv.length) {
        return null;
    }

    return process.argv[index + 1];
}

function hasFlag(name) {
    return process.argv.includes(`--${name}`);
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

        throw new Error(
            `Unable to read ${description} at ${filePath}: ${error.message}`
        );
    }
}

async function readIdentity(identityPath) {
    const identityJson = await readRequiredFile(
        identityPath,
        "identity.json"
    );

    try {
        return JSON.parse(identityJson);
    } catch (error) {
        throw new Error(
            `identity.json is not valid JSON: ${error.message}`
        );
    }
}

function requireDid(identity) {
    if (
        !identity.did ||
        typeof identity.did !== "string" ||
        identity.did.trim() === ""
    ) {
        throw new Error("DID is missing from identity.json");
    }

    return identity.did.trim();
}

function resolveDeviceDirectory(deviceDirectory) {
    if (!deviceDirectory || deviceDirectory.trim() === "") {
        throw new Error(
            "Usage: node authenticate-device.js devices/<device-folder>"
        );
    }

    return path.resolve(
        __dirname,
        deviceDirectory
    );
}

async function requestChallenge(apiUrl, did) {
    const response = await fetch(
        `${apiUrl}/api/auth/challenge`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ did })
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
            `Challenge request failed with status ${response.status}`
        );
    }

    return body;
}

function validateChallengeResponse(body, did) {
    const data = body.data;

    if (!data || typeof data !== "object") {
        throw new Error("Challenge response is missing data");
    }

    const {
        challengeId,
        challengePayload,
        expiresAt,
        expiresInSeconds
    } = data;

    if (
        typeof challengeId !== "string" ||
        challengeId.trim() === ""
    ) {
        throw new Error("Challenge response is missing challengeId");
    }

    if (
        typeof challengePayload !== "string" ||
        challengePayload.trim() === ""
    ) {
        throw new Error("Challenge response is missing challengePayload");
    }

    if (
        typeof expiresAt !== "string" ||
        expiresAt.trim() === ""
    ) {
        throw new Error("Challenge response is missing expiresAt");
    }

    if (typeof expiresInSeconds !== "number") {
        throw new Error(
            "Challenge response is missing numeric expiresInSeconds"
        );
    }

    const payloadParts = challengePayload.split("|");

    if (payloadParts.length !== 4) {
        throw new Error(
            "Challenge payload must use did|challengeId|nonce|expiresAt"
        );
    }

    if (payloadParts[0] !== did) {
        throw new Error("Challenge payload DID does not match identity DID");
    }

    if (payloadParts[1] !== challengeId) {
        throw new Error(
            "Challenge payload challengeId does not match response challengeId"
        );
    }

    if (payloadParts[2].trim() === "") {
        throw new Error("Challenge payload nonce is empty");
    }

    if (payloadParts[3] !== expiresAt) {
        throw new Error(
            "Challenge payload expiresAt does not match response expiresAt"
        );
    }

    return {
        challengeId,
        challengePayload,
        expiresAt,
        expiresInSeconds
    };
}

function signChallengePayload(privateKey, challengePayload) {
    try {
        const signer = crypto.createSign("SHA256");
        signer.update(challengePayload);
        signer.end();

        return signer.sign(privateKey, "base64");
    } catch (error) {
        throw new Error(`Challenge signing failed: ${error.message}`);
    }
}

async function submitVerification(apiUrl, proof) {
    const response = await fetch(
        `${apiUrl}/api/auth/verify`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(proof)
        }
    );

    let body;

    try {
        body = await response.json();
    } catch {
        throw new Error(
            `Gateway returned a non-JSON verification response with status ${response.status}`
        );
    }

    if (
        body.decision !== "GRANTED" &&
        body.decision !== "DENIED"
    ) {
        throw new Error("Verification response is missing a decision");
    }

    if (typeof body.authenticated !== "boolean") {
        throw new Error(
            "Verification response is missing authenticated status"
        );
    }

    return {
        statusCode: response.status,
        body
    };
}

async function main() {
    const deviceDirectory = resolveDeviceDirectory(process.argv[2]);
    const apiUrl =
        getArgument("api") ||
        process.env.GATEWAY_API_URL ||
        DEFAULT_API_URL;

    const identityPath = path.join(deviceDirectory, "identity.json");
    const privateKeyPath = path.join(deviceDirectory, "private-key.pem");

    const identity = await readIdentity(identityPath);
    const did = requireDid(identity);

    const privateKey = await readRequiredFile(
        privateKeyPath,
        "private-key.pem"
    );

    const challengeBody = await requestChallenge(apiUrl, did);
    const challenge = validateChallengeResponse(challengeBody, did);
    const signature = signChallengePayload(
        privateKey,
        challenge.challengePayload
    );

    if (!signature) {
        throw new Error("Signing produced an empty signature");
    }

    const verificationRequest = {
        did,
        challengeId: challenge.challengeId,
        signature
    };

    const verification = await submitVerification(
        apiUrl,
        verificationRequest
    );

    const output = {
        did,
        authenticated: verification.body.authenticated,
        decision: verification.body.decision
    };

    if (verification.body.reason) {
        output.reason = verification.body.reason;
    }

    if (hasFlag("include-payload")) {
        output.challengeId = challenge.challengeId;
        output.expiresAt = challenge.expiresAt;
        output.signature = signature;
        output.signatureEncoding = "base64";
        output.algorithm = "ECDSA-SHA256";
        output.challengePayload = challenge.challengePayload;
        output.verificationStatusCode = verification.statusCode;
    }

    console.log(JSON.stringify(output, null, 2));

    if (!verification.body.authenticated) {
        process.exitCode = 1;
    }
}

main().catch((error) => {
    console.error(
        `Device authentication signing failed: ${error.message}`
    );
    process.exit(1);
});
