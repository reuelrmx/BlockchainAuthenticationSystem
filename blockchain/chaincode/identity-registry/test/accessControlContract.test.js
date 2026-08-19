"use strict";

const assert = require("node:assert");
const crypto = require("node:crypto");

const AccessControlContract = require("../lib/AccessControlContract");

class MockStub {
    constructor() {
        this.state = new Map();
        this.events = [];
        this.txId = "mock-tx-1";
    }

    createCompositeKey(objectType, attributes) {
        return `${objectType}\u0000${attributes.join("\u0000")}\u0000`;
    }

    async getState(key) {
        return this.state.get(key) || Buffer.alloc(0);
    }

    async putState(key, value) {
        this.state.set(key, Buffer.from(value));
    }

    setEvent(name, payload) {
        this.events.push({
            name,
            payload: JSON.parse(Buffer.from(payload).toString("utf8"))
        });
    }

    getTxID() {
        return this.txId;
    }

    getTxTimestamp() {
        return {
            seconds: {
                toNumber: () => 1797667200
            },
            nanos: 123000000
        };
    }
}

function createContext() {
    return {
        stub: new MockStub(),
        clientIdentity: {
            getID: () => "x509::mock"
        }
    };
}

function generateCredential() {
    return crypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
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

function signPayload(privateKey, payload) {
    const signer = crypto.createSign("SHA256");

    signer.update(payload);
    signer.end();

    return signer.sign(privateKey, "base64");
}

async function putDevice(ctx, {
    did,
    publicKey,
    status = "ACTIVE"
}) {
    const key = ctx.stub.createCompositeKey("DEVICE", [did]);

    await ctx.stub.putState(
        key,
        Buffer.from(JSON.stringify({
            docType: "deviceIdentity",
            did,
            publicKey,
            status,
            registeredMacAddress: "AA:BB:CC:DD:EE:01",
            registeredIpAddress: "192.168.1.30"
        }))
    );
}

async function verify(contract, ctx, {
    eventId,
    did,
    payload,
    signature,
    classification = "NONE",
    denyIncomplete = false
}) {
    const response = await contract.VerifyAuthentication(
        ctx,
        eventId,
        did,
        payload,
        signature,
        "AA:BB:CC:DD:EE:01",
        "192.168.1.30",
        classification,
        String(denyIncomplete)
    );

    return JSON.parse(response);
}

async function run() {
    const contract = new AccessControlContract();
    const did = "did:fabric:test-device";
    const payload = "did:fabric:test-device|challenge-id|nonce|expires";
    const {
        publicKey,
        privateKey
    } = generateCredential();
    const otherCredential = generateCredential();
    const signature = signPayload(privateKey, payload);

    {
        const ctx = createContext();
        await putDevice(ctx, {
            did,
            publicKey
        });

        const result = await verify(contract, ctx, {
            eventId: "event-valid",
            did,
            payload,
            signature
        });

        assert.strictEqual(result.authenticated, true);
        assert.strictEqual(result.decision, "GRANTED");
        assert.strictEqual(result.reason, "VALID_SIGNATURE");
        assert.strictEqual(result.spoofingClassification, "NONE");

        const storedEvent = JSON.parse(
            [...ctx.stub.state.values()]
                .map((value) => value.toString())
                .find((value) => value.includes("\"event-valid\""))
        );

        assert.strictEqual(storedEvent.challengePayload, undefined);
        assert.strictEqual(storedEvent.signature, undefined);
    }

    {
        const ctx = createContext();
        await putDevice(ctx, {
            did,
            publicKey
        });

        const result = await verify(contract, ctx, {
            eventId: "event-modified-payload",
            did,
            payload: `${payload}-modified`,
            signature
        });

        assert.strictEqual(result.authenticated, false);
        assert.strictEqual(result.reason, "INVALID_SIGNATURE");
        assert.strictEqual(result.spoofingClassification, "NOT_EVALUATED");
    }

    {
        const ctx = createContext();
        await putDevice(ctx, {
            did,
            publicKey
        });

        const result = await verify(contract, ctx, {
            eventId: "event-wrong-signature",
            did,
            payload,
            signature: signPayload(otherCredential.privateKey, payload)
        });

        assert.strictEqual(result.authenticated, false);
        assert.strictEqual(result.reason, "INVALID_SIGNATURE");
        assert.strictEqual(result.spoofingClassification, "NOT_EVALUATED");
    }

    {
        const ctx = createContext();
        await putDevice(ctx, {
            did,
            publicKey,
            status: "SUSPENDED"
        });

        const result = await verify(contract, ctx, {
            eventId: "event-suspended",
            did,
            payload,
            signature
        });

        assert.strictEqual(result.authenticated, false);
        assert.strictEqual(result.reason, "DEVICE_NOT_ACTIVE");
    }

    {
        const ctx = createContext();

        const result = await verify(contract, ctx, {
            eventId: "event-unknown-device",
            did,
            payload,
            signature
        });

        assert.strictEqual(result.authenticated, false);
        assert.strictEqual(result.reason, "UNKNOWN_DEVICE");
        assert.strictEqual(result.spoofingClassification, "NOT_EVALUATED");
    }

    for (const classification of [
        "MAC_MISMATCH",
        "IP_MISMATCH",
        "MAC_AND_IP_MISMATCH"
    ]) {
        const ctx = createContext();
        await putDevice(ctx, {
            did,
            publicKey
        });

        const result = await verify(contract, ctx, {
            eventId: `event-${classification}`,
            did,
            payload,
            signature,
            classification
        });

        assert.strictEqual(result.authenticated, false);
        assert.strictEqual(result.reason, classification);
        assert.strictEqual(result.spoofingClassification, classification);
    }

    {
        const ctx = createContext();
        await putDevice(ctx, {
            did,
            publicKey
        });

        const result = await verify(contract, ctx, {
            eventId: "event-context-incomplete-accepted",
            did,
            payload,
            signature,
            classification: "CONTEXT_INCOMPLETE",
            denyIncomplete: false
        });

        assert.strictEqual(result.authenticated, true);
        assert.strictEqual(result.reason, "VALID_SIGNATURE");
        assert.strictEqual(
            result.spoofingClassification,
            "CONTEXT_INCOMPLETE"
        );
    }

    {
        const ctx = createContext();
        await putDevice(ctx, {
            did,
            publicKey
        });

        const result = await verify(contract, ctx, {
            eventId: "event-context-incomplete-denied",
            did,
            payload,
            signature,
            classification: "CONTEXT_INCOMPLETE",
            denyIncomplete: true
        });

        assert.strictEqual(result.authenticated, false);
        assert.strictEqual(result.reason, "CONTEXT_INCOMPLETE");
    }

    {
        const ctx = createContext();
        await putDevice(ctx, {
            did,
            publicKey
        });

        await verify(contract, ctx, {
            eventId: "event-duplicate",
            did,
            payload,
            signature
        });

        await assert.rejects(
            () => verify(contract, ctx, {
                eventId: "event-duplicate",
                did,
                payload,
                signature
            }),
            /already exists/
        );
    }

    console.log("AccessControlContract VerifyAuthentication tests passed");
}

run().catch((error) => {
    console.error(error);
    process.exit(1);
});
