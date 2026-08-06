"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

async function main() {
    const deviceDirectory = process.argv[2];

    if (!deviceDirectory) {
        throw new Error(
            "Usage: node test-signature.js devices/<device-folder>"
        );
    }

    const absoluteDirectory = path.resolve(
        __dirname,
        deviceDirectory
    );

    const privateKeyPath = path.join(
        absoluteDirectory,
        "private-key.pem"
    );

    const publicKeyPath = path.join(
        absoluteDirectory,
        "public-key.pem"
    );

    const privateKey = await fs.readFile(
        privateKeyPath,
        "utf8"
    );

    const publicKey = await fs.readFile(
        publicKeyPath,
        "utf8"
    );

    const testNonce = crypto.randomBytes(32).toString("hex");

    const signer = crypto.createSign("SHA256");
    signer.update(testNonce);
    signer.end();

    const signature = signer.sign(
        privateKey,
        "base64"
    );

    const verifier = crypto.createVerify("SHA256");
    verifier.update(testNonce);
    verifier.end();

    const valid = verifier.verify(
        publicKey,
        signature,
        "base64"
    );

    console.log(
        JSON.stringify(
            {
                testNonce,
                signature,
                signatureEncoding: "base64",
                algorithm: "ECDSA-SHA256",
                valid
            },
            null,
            2
        )
    );

    if (!valid) {
        process.exitCode = 1;
    }
}

main().catch((error) => {
    console.error(`Signature test failed: ${error.message}`);
    process.exit(1);
});