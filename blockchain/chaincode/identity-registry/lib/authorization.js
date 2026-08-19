"use strict";

const ADMIN_MSP_IDS = new Set([
    "Org1MSP",
    "Org2MSP"
]);

function getAttribute(ctx, name) {
    try {
        return ctx.clientIdentity.getAttributeValue(name);
    } catch {
        return null;
    }
}

function isFabricAdministrator(ctx) {
    const mspId = ctx.clientIdentity.getMSPID
        ? ctx.clientIdentity.getMSPID()
        : null;
    const identity = ctx.clientIdentity.getID
        ? ctx.clientIdentity.getID()
        : "";
    const role = String(
        getAttribute(ctx, "role") ||
        getAttribute(ctx, "admin") ||
        getAttribute(ctx, "hf.Type") ||
        ""
    ).toLowerCase();

    return (
        ADMIN_MSP_IDS.has(mspId) &&
        (
            role === "admin" ||
            role === "true" ||
            identity.includes("Admin@")
        )
    );
}

function assertFabricAdministrator(ctx, action) {
    if (!isFabricAdministrator(ctx)) {
        throw new Error(
            `Fabric administrator authorization required for ${action}`
        );
    }
}

module.exports = {
    assertFabricAdministrator,
    isFabricAdministrator
};
