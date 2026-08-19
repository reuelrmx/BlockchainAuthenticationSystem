"use strict";

const grpc = require("@grpc/grpc-js");
const {
    connect,
    hash,
    signers
} = require("@hyperledger/fabric-gateway");

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const fabricConfig = require("../config/fabricConfig");

const connections = new Map();
const identityProfiles = {
    application: {
        mspId: fabricConfig.mspId,
        certificatePath: fabricConfig.certificatePath,
        privateKeyDirectory: fabricConfig.privateKeyDirectory
    },
    admin: {
        mspId: fabricConfig.mspId,
        certificatePath: fabricConfig.adminCertificatePath,
        privateKeyDirectory: fabricConfig.adminPrivateKeyDirectory
    }
};

/**
 * Finds the first regular file in a directory.
 *
 * Fabric test-network private-key filenames are generated dynamically,
 * so the exact filename cannot safely be hard-coded.
 *
 * @param {string} directoryPath
 * @returns {Promise<string>}
 */
async function getFirstFile(directoryPath) {
    const entries = await fs.readdir(directoryPath, {
        withFileTypes: true
    });

    const fileEntry = entries.find((entry) => entry.isFile());

    if (!fileEntry) {
        throw new Error(
            `No private key was found in ${directoryPath}`
        );
    }

    return path.join(directoryPath, fileEntry.name);
}

/**
 * Confirms that a required Fabric credential file exists.
 *
 * @param {string} filePath
 * @param {string} description
 */
async function requireFile(filePath, description) {
    try {
        await fs.access(filePath);
    } catch {
        throw new Error(
            `${description} was not found at ${filePath}. ` +
            "Confirm the Fabric test network is running with CA identities."
        );
    }
}

/**
 * Creates one reusable Fabric Gateway connection for a named identity.
 */
async function connectToFabric(identityProfile = "application") {
    const existingConnection = connections.get(identityProfile);

    if (existingConnection?.network) {
        return getContract(
            fabricConfig.contractName,
            identityProfile
        );
    }

    const profile = identityProfiles[identityProfile];

    if (!profile) {
        throw new Error(`Unknown Fabric identity profile: ${identityProfile}`);
    }

    await requireFile(
        fabricConfig.tlsCertPath,
        "Peer TLS certificate"
    );

    await requireFile(
        profile.certificatePath,
        `Fabric ${identityProfile} certificate`
    );

    const privateKeyPath = await getFirstFile(
        profile.privateKeyDirectory
    );

    const tlsRootCertificate = await fs.readFile(
        fabricConfig.tlsCertPath
    );

    const clientCredentials = await fs.readFile(
        profile.certificatePath
    );

    const privateKeyPem = await fs.readFile(privateKeyPath);
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const signer = signers.newPrivateKeySigner(privateKey);

    const tlsCredentials =
        grpc.credentials.createSsl(tlsRootCertificate);

    const grpcClient = new grpc.Client(
        fabricConfig.peerEndpoint,
        tlsCredentials,
        {
            "grpc.ssl_target_name_override":
                fabricConfig.peerHostAlias
        }
    );

    const gateway = connect({
        client: grpcClient,
        identity: {
            mspId: profile.mspId,
            credentials: clientCredentials
        },
        signer,
        hash: hash.sha256,

        evaluateOptions: () => ({
            deadline: Date.now() + 5000
        }),

        endorseOptions: () => ({
            deadline: Date.now() + 15000
        }),

        submitOptions: () => ({
            deadline: Date.now() + 5000
        }),

        commitStatusOptions: () => ({
            deadline: Date.now() + 60000
        })
    });

    const network = gateway.getNetwork(
        fabricConfig.channelName
    );

    connections.set(identityProfile, {
        grpcClient,
        gateway,
        network,
        contracts: new Map()
    });

    console.log(
        `Connected to Fabric channel '${fabricConfig.channelName}', ` +
        `chaincode '${fabricConfig.chaincodeName}' as ${identityProfile}`
    );

    return getContract(fabricConfig.contractName, identityProfile);
}

async function getContract(
    contractName = fabricConfig.contractName,
    identityProfile = "application"
) {
    let connection = connections.get(identityProfile);

    if (!connection?.network) {
        await connectToFabric(identityProfile);
        connection = connections.get(identityProfile);
    }

    if (!connection.contracts.has(contractName)) {
        connection.contracts.set(
            contractName,
            connection.network.getContract(
                fabricConfig.chaincodeName,
                contractName
            )
        );
    }

    return connection.contracts.get(contractName);
}

/**
 * Submits a transaction that changes ledger state.
 *
 * @param {string} transactionName
 * @param {...string} args
 * @returns {Promise<object|string|null>}
 */
async function submitTransaction(transactionName, ...args) {
    return submitTransactionForContract(
        fabricConfig.contractName,
        transactionName,
        ...args
    );
}

/**
 * Submits a transaction against a named contract.
 *
 * @param {string} contractName
 * @param {string} transactionName
 * @param {...string} args
 * @returns {Promise<object|string|null>}
 */
async function submitTransactionForContract(
    contractName,
    transactionName,
    ...args
) {
    return submitTransactionForContractWithIdentity(
        "application",
        contractName,
        transactionName,
        ...args
    );
}

async function submitAdminTransaction(transactionName, ...args) {
    return submitAdminTransactionForContract(
        fabricConfig.contractName,
        transactionName,
        ...args
    );
}

async function submitAdminTransactionForContract(
    contractName,
    transactionName,
    ...args
) {
    return submitTransactionForContractWithIdentity(
        "admin",
        contractName,
        transactionName,
        ...args
    );
}

async function submitTransactionForContractWithIdentity(
    identityProfile,
    contractName,
    transactionName,
    ...args
) {
    const fabricContract = await getContract(
        contractName,
        identityProfile
    );

    const resultBytes =
        await fabricContract.submitTransaction(
            transactionName,
            ...args.map(String)
        );

    return decodeResult(resultBytes);
}

/**
 * Evaluates a read-only ledger transaction.
 *
 * @param {string} transactionName
 * @param {...string} args
 * @returns {Promise<object|string|null>}
 */
async function evaluateTransaction(transactionName, ...args) {
    return evaluateTransactionForContract(
        fabricConfig.contractName,
        transactionName,
        ...args
    );
}

/**
 * Evaluates a read-only transaction against a named contract.
 *
 * @param {string} contractName
 * @param {string} transactionName
 * @param {...string} args
 * @returns {Promise<object|string|null>}
 */
async function evaluateTransactionForContract(
    contractName,
    transactionName,
    ...args
) {
    const fabricContract = await getContract(contractName);

    const resultBytes =
        await fabricContract.evaluateTransaction(
            transactionName,
            ...args.map(String)
        );

    return decodeResult(resultBytes);
}

/**
 * Converts Fabric byte responses into JSON where possible.
 *
 * @param {Uint8Array} resultBytes
 * @returns {object|string|null}
 */
function decodeResult(resultBytes) {
    if (!resultBytes || resultBytes.length === 0) {
        return null;
    }

    const text = Buffer.from(resultBytes).toString("utf8");

    try {
        return JSON.parse(text);
    } catch {
        return text;
    }
}

/**
 * Closes the reusable gateway and gRPC connection.
 */
function closeFabricConnection() {
    for (const connection of connections.values()) {
        connection.gateway.close();
        connection.grpcClient.close();
        connection.contracts.clear();
    }

    connections.clear();
}

module.exports = {
    connectToFabric,
    getContract,
    submitTransaction,
    submitTransactionForContract,
    submitAdminTransaction,
    submitAdminTransactionForContract,
    evaluateTransaction,
    evaluateTransactionForContract,
    closeFabricConnection
};
