"use strict";

const crypto = require("node:crypto");

function verifySignature(publicKeyPem, payload, signatureBase64) {
    if (
        typeof publicKeyPem !== "string" ||
        publicKeyPem.trim() === "" ||
        typeof payload !== "string" ||
        payload === "" ||
        typeof signatureBase64 !== "string" ||
        signatureBase64.trim() === ""
    ) {
        return false;
    }

    try {
        const verifier = crypto.createVerify("SHA256");
        verifier.update(payload);
        verifier.end();

        return verifier.verify(
            publicKeyPem,
            signatureBase64,
            "base64"
        );
    } catch {
        return false;
    }
}

module.exports = {
    verifySignature
};
