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

let grpcClient = null;
let gateway = null;
let network = null;
const contracts = new Map();

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
 * Creates one reusable Fabric Gateway connection.
 */
async function connectToFabric() {
    if (network) {
        return getContract(fabricConfig.contractName);
    }

    await requireFile(
        fabricConfig.tlsCertPath,
        "Peer TLS certificate"
    );

    await requireFile(
        fabricConfig.certificatePath,
        "Org1 user certificate"
    );

    const privateKeyPath = await getFirstFile(
        fabricConfig.privateKeyDirectory
    );

    const tlsRootCertificate = await fs.readFile(
        fabricConfig.tlsCertPath
    );

    const clientCredentials = await fs.readFile(
        fabricConfig.certificatePath
    );

    const privateKeyPem = await fs.readFile(privateKeyPath);
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const signer = signers.newPrivateKeySigner(privateKey);

    const tlsCredentials =
        grpc.credentials.createSsl(tlsRootCertificate);

    grpcClient = new grpc.Client(
        fabricConfig.peerEndpoint,
        tlsCredentials,
        {
            "grpc.ssl_target_name_override":
                fabricConfig.peerHostAlias
        }
    );

    gateway = connect({
        client: grpcClient,
        identity: {
            mspId: fabricConfig.mspId,
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

    network = gateway.getNetwork(
        fabricConfig.channelName
    );

    console.log(
        `Connected to Fabric channel '${fabricConfig.channelName}', ` +
        `chaincode '${fabricConfig.chaincodeName}'`
    );

    return getContract(fabricConfig.contractName);
}

async function getContract(contractName = fabricConfig.contractName) {
    if (!network) {
        await connectToFabric();
    }

    if (!contracts.has(contractName)) {
        contracts.set(
            contractName,
            network.getContract(
                fabricConfig.chaincodeName,
                contractName
            )
        );
    }

    return contracts.get(contractName);
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
    const fabricContract = await getContract(contractName);

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
    if (gateway) {
        gateway.close();
        gateway = null;
    }

    if (grpcClient) {
        grpcClient.close();
        grpcClient = null;
    }

    network = null;
    contracts.clear();
}

module.exports = {
    connectToFabric,
    getContract,
    submitTransaction,
    submitTransactionForContract,
    evaluateTransaction,
    evaluateTransactionForContract,
    closeFabricConnection
};
