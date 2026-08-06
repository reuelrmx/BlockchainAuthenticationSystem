"use strict";

const { Contract } = require("fabric-contract-api");

class IdentityRegistryContract extends Contract {
    constructor() {
        super("IdentityRegistryContract");
    }

    /**
     * Verifies that the submitted value is not empty.
     *
     * @param {string} value
     * @param {string} fieldName
     */
    _requireValue(value, fieldName) {
        if (typeof value !== "string" || value.trim() === "") {
            throw new Error(`${fieldName} is required`);
        }
    }

    /**
     * Converts a Fabric transaction timestamp into ISO format.
     *
     * Fabric transaction time is deterministic because it comes from
     * the submitted transaction rather than the local system clock.
     *
     * @param {object} ctx
     * @returns {string}
     */
    _getTransactionTimestamp(ctx) {
        const timestamp = ctx.stub.getTxTimestamp();

        const seconds =
            typeof timestamp.seconds === "object"
                ? timestamp.seconds.toNumber()
                : Number(timestamp.seconds);

        const milliseconds =
            seconds * 1000 + Math.floor(timestamp.nanos / 1000000);

        return new Date(milliseconds).toISOString();
    }

    /**
     * Creates the ledger key used to store a device.
     *
     * @param {object} ctx
     * @param {string} did
     * @returns {string}
     */
    _createDeviceKey(ctx, did) {
        return ctx.stub.createCompositeKey("DEVICE", [did]);
    }

    /**
     * Checks whether a device identity exists.
     *
     * @param {object} ctx
     * @param {string} did
     * @returns {Promise<boolean>}
     */
    async DeviceExists(ctx, did) {
        this._requireValue(did, "DID");

        const deviceKey = this._createDeviceKey(ctx, did);
        const deviceBytes = await ctx.stub.getState(deviceKey);

        return Boolean(deviceBytes && deviceBytes.length > 0);
    }

    /**
     * Registers a new device identity on the blockchain.
     *
     * @param {object} ctx
     * @param {string} did
     * @param {string} publicKey
     * @param {string} owner
     * @param {string} macAddress
     * @param {string} ipAddress
     * @returns {Promise<string>}
     */
    async RegisterDevice(
        ctx,
        did,
        publicKey,
        owner,
        macAddress,
        ipAddress
    ) {
        this._requireValue(did, "DID");
        this._requireValue(publicKey, "Public key");
        this._requireValue(owner, "Owner");
        this._requireValue(macAddress, "MAC address");
        this._requireValue(ipAddress, "IP address");

        const exists = await this.DeviceExists(ctx, did);

        if (exists) {
            throw new Error(`Device ${did} is already registered`);
        }

        const timestamp = this._getTransactionTimestamp(ctx);

        const device = {
            docType: "deviceIdentity",
            did: did.trim(),
            publicKey: publicKey.trim(),
            owner: owner.trim(),
            registeredMacAddress: macAddress.trim().toUpperCase(),
            registeredIpAddress: ipAddress.trim(),
            status: "ACTIVE",
            registeredAt: timestamp,
            updatedAt: timestamp,
            revokedAt: null,
            revocationReason: null,
            createdBy: ctx.clientIdentity.getID(),
            transactionId: ctx.stub.getTxID()
        };

        const deviceKey = this._createDeviceKey(ctx, did);

        await ctx.stub.putState(
            deviceKey,
            Buffer.from(JSON.stringify(device))
        );

        ctx.stub.setEvent(
            "DeviceRegistered",
            Buffer.from(
                JSON.stringify({
                    did: device.did,
                    status: device.status,
                    registeredAt: device.registeredAt,
                    transactionId: device.transactionId
                })
            )
        );

        return JSON.stringify(device);
    }

    /**
     * Retrieves one registered device.
     *
     * @param {object} ctx
     * @param {string} did
     * @returns {Promise<string>}
     */
    async GetDevice(ctx, did) {
        this._requireValue(did, "DID");

        const deviceKey = this._createDeviceKey(ctx, did);
        const deviceBytes = await ctx.stub.getState(deviceKey);

        if (!deviceBytes || deviceBytes.length === 0) {
            throw new Error(`Device ${did} does not exist`);
        }

        return deviceBytes.toString();
    }

    /**
     * Returns the current status of a device.
     *
     * @param {object} ctx
     * @param {string} did
     * @returns {Promise<string>}
     */
    async GetDeviceStatus(ctx, did) {
        const deviceJson = await this.GetDevice(ctx, did);
        const device = JSON.parse(deviceJson);

        return JSON.stringify({
            did: device.did,
            status: device.status
        });
    }

    /**
     * Suspends an active device without permanently revoking it.
     *
     * @param {object} ctx
     * @param {string} did
     * @param {string} reason
     * @returns {Promise<string>}
     */
    async SuspendDevice(ctx, did, reason) {
        this._requireValue(reason, "Suspension reason");

        const deviceJson = await this.GetDevice(ctx, did);
        const device = JSON.parse(deviceJson);

        if (device.status === "REVOKED") {
            throw new Error(`Device ${did} is revoked and cannot be suspended`);
        }

        if (device.status === "SUSPENDED") {
            throw new Error(`Device ${did} is already suspended`);
        }

        device.status = "SUSPENDED";
        device.suspensionReason = reason.trim();
        device.updatedAt = this._getTransactionTimestamp(ctx);
        device.updatedBy = ctx.clientIdentity.getID();
        device.lastTransactionId = ctx.stub.getTxID();

        const deviceKey = this._createDeviceKey(ctx, did);

        await ctx.stub.putState(
            deviceKey,
            Buffer.from(JSON.stringify(device))
        );

        ctx.stub.setEvent(
            "DeviceSuspended",
            Buffer.from(
                JSON.stringify({
                    did,
                    reason: device.suspensionReason,
                    timestamp: device.updatedAt
                })
            )
        );

        return JSON.stringify(device);
    }

    /**
     * Reactivates a suspended device.
     *
     * @param {object} ctx
     * @param {string} did
     * @returns {Promise<string>}
     */
    async ActivateDevice(ctx, did) {
        const deviceJson = await this.GetDevice(ctx, did);
        const device = JSON.parse(deviceJson);

        if (device.status === "REVOKED") {
            throw new Error(`Revoked device ${did} cannot be reactivated`);
        }

        if (device.status === "ACTIVE") {
            throw new Error(`Device ${did} is already active`);
        }

        device.status = "ACTIVE";
        device.suspensionReason = null;
        device.updatedAt = this._getTransactionTimestamp(ctx);
        device.updatedBy = ctx.clientIdentity.getID();
        device.lastTransactionId = ctx.stub.getTxID();

        const deviceKey = this._createDeviceKey(ctx, did);

        await ctx.stub.putState(
            deviceKey,
            Buffer.from(JSON.stringify(device))
        );

        ctx.stub.setEvent(
            "DeviceActivated",
            Buffer.from(
                JSON.stringify({
                    did,
                    timestamp: device.updatedAt
                })
            )
        );

        return JSON.stringify(device);
    }

    /**
     * Permanently revokes a device identity.
     *
     * @param {object} ctx
     * @param {string} did
     * @param {string} reason
     * @returns {Promise<string>}
     */
    async RevokeDevice(ctx, did, reason) {
        this._requireValue(reason, "Revocation reason");

        const deviceJson = await this.GetDevice(ctx, did);
        const device = JSON.parse(deviceJson);

        if (device.status === "REVOKED") {
            throw new Error(`Device ${did} is already revoked`);
        }

        const timestamp = this._getTransactionTimestamp(ctx);

        device.status = "REVOKED";
        device.revokedAt = timestamp;
        device.revocationReason = reason.trim();
        device.updatedAt = timestamp;
        device.updatedBy = ctx.clientIdentity.getID();
        device.lastTransactionId = ctx.stub.getTxID();

        const deviceKey = this._createDeviceKey(ctx, did);

        await ctx.stub.putState(
            deviceKey,
            Buffer.from(JSON.stringify(device))
        );

        ctx.stub.setEvent(
            "DeviceRevoked",
            Buffer.from(
                JSON.stringify({
                    did,
                    reason: device.revocationReason,
                    revokedAt: device.revokedAt
                })
            )
        );

        return JSON.stringify(device);
    }

    /**
     * Returns all registered devices.
     *
     * @param {object} ctx
     * @returns {Promise<string>}
     */
    async GetAllDevices(ctx) {
        const iterator = await ctx.stub.getStateByPartialCompositeKey(
            "DEVICE",
            []
        );

        const devices = [];

        try {
            while (true) {
                const result = await iterator.next();

                if (result.value && result.value.value) {
                    const value = result.value.value.toString("utf8");

                    if (value) {
                        devices.push(JSON.parse(value));
                    }
                }

                if (result.done) {
                    break;
                }
            }
        } finally {
            await iterator.close();
        }

        return JSON.stringify(devices);
    }
}

module.exports = IdentityRegistryContract;
