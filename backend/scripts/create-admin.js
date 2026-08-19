"use strict";

const path = require("node:path");
const readline = require("node:readline/promises");

require("dotenv").config({
    path: path.resolve(__dirname, "../.env")
});

const {
    createAdmin
} = require("../src/services/adminStore");

function getArgument(name) {
    const index = process.argv.indexOf(`--${name}`);

    if (index === -1 || index + 1 >= process.argv.length) {
        return null;
    }

    return process.argv[index + 1];
}

function hasFlag(name) {
    return process.argv.includes(`--${name}`);
}

function parseEnabled(value) {
    if (value === null) {
        return true;
    }

    return !["false", "0", "no", "off"].includes(
        String(value).trim().toLowerCase()
    );
}

async function promptText(question) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    try {
        return (await rl.question(question)).trim();
    } finally {
        rl.close();
    }
}

async function promptHidden(question) {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
        throw new Error(
            "Password input requires a TTY or --password-stdin"
        );
    }

    process.stdout.write(question);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");

    let password = "";

    try {
        for await (const char of process.stdin) {
            if (char === "\u0003") {
                throw new Error("Password prompt cancelled");
            }

            if (char === "\r" || char === "\n") {
                process.stdout.write("\n");
                break;
            }

            if (char === "\u007f") {
                password = password.slice(0, -1);
                continue;
            }

            password += char;
        }
    } finally {
        process.stdin.setRawMode(false);
        process.stdin.pause();
    }

    return password;
}

async function readPassword() {
    if (hasFlag("password-stdin")) {
        const chunks = [];

        for await (const chunk of process.stdin) {
            chunks.push(Buffer.from(chunk));
        }

        const input = Buffer.concat(chunks).toString("utf8");

        return input.replace(/\r?\n$/, "");
    }

    return promptHidden("Password: ");
}

async function main() {
    const username =
        getArgument("username") ||
        await promptText("Username: ");
    const role =
        getArgument("role") ||
        await promptText("Role (ADMIN or VIEWER): ");
    const password = await readPassword();
    const admin = await createAdmin({
        username,
        password,
        role,
        enabled: parseEnabled(getArgument("enabled"))
    });

    console.log(JSON.stringify({
        success: true,
        message: "Administrator account created",
        data: {
            admin
        }
    }, null, 2));
}

main().catch((error) => {
    console.error(`Admin bootstrap failed: ${error.message}`);
    process.exit(1);
});
