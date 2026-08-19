"use strict";

const path = require("node:path");

const testNetworkPath = process.env.FABRIC_TEST_NETWORK_PATH;

if (!testNetworkPath) {
    throw new Error("FABRIC_TEST_NETWORK_PATH is not configured");
}

const org1Path = path.join(
    testNetworkPath,
    "organizations",
    "peerOrganizations",
    "org1.example.com"
);

const org1UsersPath = path.join(
    org1Path,
    "users"
);

function resolveOrg1UserPath(userName) {
    return path.join(
        org1UsersPath,
        userName
    );
}

function resolveCertificatePath(userPath) {
    return path.join(
        userPath,
        "msp",
        "signcerts",
        "cert.pem"
    );
}

function resolvePrivateKeyDirectory(userPath) {
    return path.join(
        userPath,
        "msp",
        "keystore"
    );
}

const applicationUserPath = resolveOrg1UserPath(
    process.env.FABRIC_APP_USER ||
    "User1@org1.example.com"
);

const adminUserPath = resolveOrg1UserPath(
    process.env.FABRIC_ADMIN_USER ||
    "Admin@org1.example.com"
);

module.exports = {
    channelName: process.env.FABRIC_CHANNEL_NAME || "mychannel",
    chaincodeName:
        process.env.FABRIC_CHAINCODE_NAME || "identityregistry",
    contractName:
        process.env.FABRIC_CONTRACT_NAME ||
        "IdentityRegistryContract",
    accessControlContractName:
        process.env.FABRIC_ACCESS_CONTROL_CONTRACT_NAME ||
        "AccessControlContract",
    auditLogContractName:
        process.env.FABRIC_AUDIT_LOG_CONTRACT_NAME ||
        "AuditLogContract",
    mspId: process.env.FABRIC_MSP_ID || "Org1MSP",
    peerEndpoint:
        process.env.FABRIC_PEER_ENDPOINT || "localhost:7051",
    peerHostAlias:
        process.env.FABRIC_PEER_HOST_ALIAS ||
        "peer0.org1.example.com",

    tlsCertPath: path.join(
        org1Path,
        "peers",
        "peer0.org1.example.com",
        "tls",
        "ca.crt"
    ),

    certificatePath: resolveCertificatePath(applicationUserPath),

    privateKeyDirectory: resolvePrivateKeyDirectory(applicationUserPath),

    adminCertificatePath: resolveCertificatePath(adminUserPath),

    adminPrivateKeyDirectory: resolvePrivateKeyDirectory(adminUserPath)
};
