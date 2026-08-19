"use strict";

require("dotenv").config();

const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");

const express = require("express");
const cors = require("cors");

const adminConfig = require("./config/adminConfig");
const adminRoutes = require("./routes/adminRoutes");
const auditRoutes = require("./routes/auditRoutes");
const authRoutes = require("./routes/authRoutes");
const deviceRoutes = require("./routes/deviceRoutes");
const performanceRoutes = require("./routes/performanceRoutes");
const errorHandler = require("./middleware/errorHandler");

const {
    connectToFabric,
    evaluateTransaction,
    closeFabricConnection
} = require("./services/fabricService");

const app = express();

app.use(cors({
    credentials: true,
    origin(origin, callback) {
        if (!origin) {
            return callback(null, true);
        }

        if (adminConfig.dashboardOrigins.includes(origin)) {
            return callback(null, true);
        }

        const error = new Error("Dashboard origin is not allowed");

        error.statusCode = 403;

        return callback(error);
    }
}));
app.use(express.json({
    limit: "1mb"
}));

app.get("/", (req, res) => {
    res.status(200).json({
        project:
            "Blockchain-Based Secure Network Authentication System",
        service: "Authentication Gateway API",
        status: "running"
    });
});

app.get("/api/health", async (req, res, next) => {
    try {
        await evaluateTransaction("GetAllDevices");

        res.status(200).json({
            success: true,
            api: "healthy",
            fabric: "connected"
        });
    } catch (error) {
        console.error(
            "Fabric health check failed:",
            {
                message: error.message,
                code: error.code,
                details: error.details
            }
        );

        res.status(503).json({
            success: false,
            api: "healthy",
            fabric: "unavailable"
        });
    }
});

app.use("/api/admin", adminRoutes);
app.use("/api/audit", auditRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/devices", deviceRoutes);
app.use("/api/performance", performanceRoutes);

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Route not found"
    });
});

app.use(errorHandler);

const port = Number(process.env.PORT || 3000);

function loadHttpsOptions() {
    try {
        return {
            cert: fs.readFileSync(adminConfig.tlsCertPath),
            key: fs.readFileSync(adminConfig.tlsKeyPath)
        };
    } catch (error) {
        throw new Error(
            "HTTPS is enabled but TLS certificate/key files could not be read. " +
            `Check TLS_CERT_PATH (${adminConfig.tlsCertPath}) and ` +
            `TLS_KEY_PATH (${adminConfig.tlsKeyPath}).`
        );
    }
}

function listen(server, listenPort, url) {
    return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(listenPort, () => {
            server.off("error", reject);
            console.log(`Gateway API running at ${url}`);
            resolve(server);
        });
    });
}

async function startServer() {
    const runningServers = [];

    try {
        await connectToFabric();

        const httpsOptions = adminConfig.httpsEnabled
            ? loadHttpsOptions()
            : null;

        const httpServer = http.createServer(app);

        runningServers.push(
            await listen(
                httpServer,
                port,
                `http://localhost:${port}`
            )
        );

        if (adminConfig.httpsEnabled) {
            const httpsServer = https.createServer(httpsOptions, app);

            runningServers.push(
                await listen(
                    httpsServer,
                    adminConfig.httpsPort,
                    `https://localhost:${adminConfig.httpsPort}`
                )
            );
        }

        function shutdown(signal) {
            console.log(`\nReceived ${signal}. Shutting down.`);

            let remaining = runningServers.length;

            function finish() {
                remaining -= 1;

                if (remaining <= 0) {
                    closeFabricConnection();
                    process.exit(0);
                }
            }

            if (remaining === 0) {
                closeFabricConnection();
                process.exit(0);
            }

            for (const server of runningServers) {
                server.close(finish);
            }
        }

        process.on("SIGINT", () => shutdown("SIGINT"));
        process.on("SIGTERM", () => shutdown("SIGTERM"));
    } catch (error) {
        console.error(
            "Gateway API failed to start:",
            error.message
        );

        closeFabricConnection();
        process.exit(1);
    }
}

startServer();
