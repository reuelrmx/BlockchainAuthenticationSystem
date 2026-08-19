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

    certificatePath: path.join(
        org1Path,
        "users",
        "User1@org1.example.com",
        "msp",
        "signcerts",
        "cert.pem"
    ),

    privateKeyDirectory: path.join(
        org1Path,
        "users",
        "User1@org1.example.com",
        "msp",
        "keystore"
    )
};
