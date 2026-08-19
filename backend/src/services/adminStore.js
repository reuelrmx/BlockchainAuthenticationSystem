"use strict";

const bcrypt = require("bcryptjs");
const fs = require("node:fs/promises");
const path = require("node:path");

const adminConfig = require("../config/adminConfig");

const BCRYPT_COST = 12;
const LOCK_RETRY_INTERVAL_MS = 50;
const LOCK_TIMEOUT_MS = 5000;
const VALID_ROLES = new Set(Object.values(adminConfig.roles));

function normalizeUsername(username) {
    if (typeof username !== "string") {
        return "";
    }

    return username.trim().toLowerCase();
}

function normalizeRole(role) {
    if (typeof role !== "string") {
        return "";
    }

    return role.trim().toUpperCase();
}

function sanitizeAdmin(admin) {
    return {
        username: admin.username,
        role: admin.role,
        enabled: admin.enabled !== false,
        createdAt: admin.createdAt,
        updatedAt: admin.updatedAt
    };
}

async function readAdminStore() {
    try {
        const storeJson = await fs.readFile(
            adminConfig.adminStorePath,
            "utf8"
        );
        const store = JSON.parse(storeJson);

        if (!Array.isArray(store.admins)) {
            throw new Error("Admin store must contain an admins array");
        }

        return {
            admins: store.admins
        };
    } catch (error) {
        if (error.code === "ENOENT") {
            return {
                admins: []
            };
        }

        if (error instanceof SyntaxError) {
            throw new Error("Admin store is not valid JSON");
        }

        throw error;
    }
}

async function writeAdminStore(store) {
    await fs.mkdir(path.dirname(adminConfig.adminStorePath), {
        recursive: true
    });

    await fs.writeFile(
        adminConfig.adminStorePath,
        `${JSON.stringify(store, null, 2)}\n`,
        {
            mode: 0o600
        }
    );

    try {
        await fs.chmod(adminConfig.adminStorePath, 0o600);
    } catch {
        // Best effort only. Windows and some filesystems may not support chmod.
    }
}

function wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function acquireAdminStoreLock() {
    const lockPath = `${adminConfig.adminStorePath}.lock`;
    const startedAt = Date.now();

    await fs.mkdir(path.dirname(adminConfig.adminStorePath), {
        recursive: true
    });

    while (Date.now() - startedAt < LOCK_TIMEOUT_MS) {
        try {
            return {
                lockFile: await fs.open(lockPath, "wx", 0o600),
                lockPath
            };
        } catch (error) {
            if (error.code !== "EEXIST") {
                throw error;
            }

            await wait(LOCK_RETRY_INTERVAL_MS);
        }
    }

    throw new Error("Timed out waiting for admin store lock");
}

async function withAdminStoreLock(operation) {
    const {
        lockFile,
        lockPath
    } = await acquireAdminStoreLock();

    try {
        return await operation();
    } finally {
        await lockFile.close();

        try {
            await fs.unlink(lockPath);
        } catch {
            // The lock file may already have been removed during cleanup.
        }
    }
}

async function findAdminRecord(username) {
    const normalizedUsername = normalizeUsername(username);

    if (!normalizedUsername) {
        return null;
    }

    const store = await readAdminStore();

    return store.admins.find((admin) =>
        normalizeUsername(admin.username) === normalizedUsername
    ) || null;
}

async function getAdminByUsername(username) {
    const admin = await findAdminRecord(username);

    return admin ? sanitizeAdmin(admin) : null;
}

async function createAdmin({
    username,
    password,
    role,
    enabled = true
}) {
    const normalizedUsername = normalizeUsername(username);
    const normalizedRole = normalizeRole(role);

    if (!normalizedUsername) {
        throw new Error("Admin username is required");
    }

    if (typeof password !== "string" || password.length < 12) {
        throw new Error(
            "Admin password must contain at least 12 characters"
        );
    }

    if (!VALID_ROLES.has(normalizedRole)) {
        throw new Error("Admin role must be ADMIN or VIEWER");
    }

    return withAdminStoreLock(async () => {
        const store = await readAdminStore();
        const existingAdmin = store.admins.find((admin) =>
            normalizeUsername(admin.username) === normalizedUsername
        );

        if (existingAdmin) {
            throw new Error("Admin username already exists");
        }

        const now = new Date().toISOString();
        const admin = {
            username: normalizedUsername,
            passwordHash: await bcrypt.hash(password, BCRYPT_COST),
            role: normalizedRole,
            enabled: Boolean(enabled),
            createdAt: now,
            updatedAt: now
        };

        store.admins.push(admin);
        await writeAdminStore(store);

        return sanitizeAdmin(admin);
    });
}

async function verifyAdminCredentials(username, password) {
    if (
        typeof username !== "string" ||
        username.trim() === "" ||
        typeof password !== "string" ||
        password === ""
    ) {
        return null;
    }

    const admin = await findAdminRecord(username);

    if (
        !admin ||
        admin.enabled === false ||
        typeof admin.passwordHash !== "string"
    ) {
        return null;
    }

    const passwordMatches = await bcrypt.compare(
        password,
        admin.passwordHash
    );

    if (!passwordMatches) {
        return null;
    }

    return sanitizeAdmin(admin);
}

async function listAdmins() {
    const store = await readAdminStore();

    return store.admins.map(sanitizeAdmin);
}

module.exports = {
    createAdmin,
    getAdminByUsername,
    listAdmins,
    sanitizeAdmin,
    verifyAdminCredentials
};
