"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

const backendRoot = path.resolve(__dirname, "../..");
const DEFAULT_DB_PATH = path.join(
    backendRoot,
    "data",
    "device-metadata.sqlite"
);

let database = null;

function resolveDatabasePath() {
    const configuredPath = process.env.DEVICE_METADATA_DB_PATH;

    if (!configuredPath || configuredPath.trim() === "") {
        return DEFAULT_DB_PATH;
    }

    if (path.isAbsolute(configuredPath)) {
        return configuredPath;
    }

    return path.resolve(backendRoot, configuredPath);
}

function getDatabase() {
    if (database) {
        return database;
    }

    const databasePath = resolveDatabasePath();

    fs.mkdirSync(path.dirname(databasePath), {
        recursive: true
    });

    database = new DatabaseSync(databasePath);
    database.exec(`
        CREATE TABLE IF NOT EXISTS device_metadata (
            did TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            raw_mac_address TEXT NOT NULL,
            allowed_ip_cidr TEXT NOT NULL,
            did_document_json TEXT NOT NULL,
            did_document_hash TEXT NOT NULL,
            metadata_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    `);

    return database;
}

function stableStringify(value) {
    if (Array.isArray(value)) {
        return `[${value.map(stableStringify).join(",")}]`;
    }

    if (value && typeof value === "object") {
        return `{${Object.keys(value)
            .sort()
            .map((key) =>
                `${JSON.stringify(key)}:${stableStringify(value[key])}`
            )
            .join(",")}}`;
    }

    return JSON.stringify(value);
}

function sha256Hex(value) {
    return crypto
        .createHash("sha256")
        .update(value)
        .digest("hex");
}

function buildDidDocument({ did, publicKey }) {
    return {
        id: did,
        verificationMethod: [
            {
                id: `${did}#key-1`,
                type: "JsonWebKey2020-Pem",
                controller: did,
                publicKeyPem: publicKey
            }
        ],
        authentication: [
            `${did}#key-1`
        ]
    };
}

function buildMetadataRecord({
    did,
    owner,
    rawMacAddress,
    allowedIpCidr,
    publicKey
}) {
    const now = new Date().toISOString();
    const didDocument = buildDidDocument({
        did,
        publicKey
    });
    const didDocumentJson = stableStringify(didDocument);
    const didDocumentHash = sha256Hex(didDocumentJson);
    const metadataHash = sha256Hex(stableStringify({
        did,
        owner,
        rawMacAddress,
        allowedIpCidr,
        didDocumentHash
    }));

    return {
        did,
        owner,
        rawMacAddress,
        allowedIpCidr,
        didDocument,
        didDocumentJson,
        didDocumentHash,
        metadataHash,
        createdAt: now,
        updatedAt: now
    };
}

function rowToMetadata(row) {
    if (!row) {
        return null;
    }

    return {
        did: row.did,
        owner: row.owner,
        rawMacAddress: row.raw_mac_address,
        allowedIpCidr: row.allowed_ip_cidr,
        didDocument: JSON.parse(row.did_document_json),
        didDocumentHash: row.did_document_hash,
        metadataHash: row.metadata_hash,
        createdAt: row.created_at,
        updatedAt: row.updated_at
    };
}

function saveDeviceMetadata(record) {
    const db = getDatabase();

    db.prepare(`
        INSERT INTO device_metadata (
            did,
            owner,
            raw_mac_address,
            allowed_ip_cidr,
            did_document_json,
            did_document_hash,
            metadata_hash,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(did) DO UPDATE SET
            owner = excluded.owner,
            raw_mac_address = excluded.raw_mac_address,
            allowed_ip_cidr = excluded.allowed_ip_cidr,
            did_document_json = excluded.did_document_json,
            did_document_hash = excluded.did_document_hash,
            metadata_hash = excluded.metadata_hash,
            updated_at = excluded.updated_at
    `).run(
        record.did,
        record.owner,
        record.rawMacAddress,
        record.allowedIpCidr,
        record.didDocumentJson,
        record.didDocumentHash,
        record.metadataHash,
        record.createdAt,
        record.updatedAt
    );

    return getDeviceMetadata(record.did);
}

function getDeviceMetadata(did) {
    const row = getDatabase()
        .prepare("SELECT * FROM device_metadata WHERE did = ?")
        .get(did);

    return rowToMetadata(row);
}

function getAllDeviceMetadata() {
    return getDatabase()
        .prepare("SELECT * FROM device_metadata ORDER BY created_at ASC")
        .all()
        .map(rowToMetadata);
}

function deleteDeviceMetadata(did) {
    getDatabase()
        .prepare("DELETE FROM device_metadata WHERE did = ?")
        .run(did);
}

function mergeDeviceMetadata(device) {
    if (!device || !device.did) {
        return device;
    }

    const metadata = getDeviceMetadata(device.did);

    if (!metadata) {
        return device;
    }

    return {
        ...device,
        owner: metadata.owner,
        registeredMacAddress: metadata.rawMacAddress,
        registeredIpAddress: metadata.allowedIpCidr,
        allowedIpCidr: metadata.allowedIpCidr,
        didDocumentHash: metadata.didDocumentHash,
        metadataHash: metadata.metadataHash,
        metadataReference: `sqlite:device_metadata:${device.did}`,
        didDocument: metadata.didDocument
    };
}

module.exports = {
    buildDidDocument,
    buildMetadataRecord,
    deleteDeviceMetadata,
    getAllDeviceMetadata,
    getDeviceMetadata,
    mergeDeviceMetadata,
    saveDeviceMetadata,
    sha256Hex,
    stableStringify
};
