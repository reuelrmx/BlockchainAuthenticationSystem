"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");

const auditRoutes = require("./routes/auditRoutes");
const authRoutes = require("./routes/authRoutes");
const deviceRoutes = require("./routes/deviceRoutes");
const errorHandler = require("./middleware/errorHandler");

const {
    connectToFabric,
    evaluateTransaction,
    closeFabricConnection
} = require("./services/fabricService");

const app = express();

app.use(cors());
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

app.use("/api/audit", auditRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/devices", deviceRoutes);

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Route not found"
    });
});

app.use(errorHandler);

const port = Number(process.env.PORT || 3000);

async function startServer() {
    try {
        await connectToFabric();

        const server = app.listen(port, () => {
            console.log(
                `Gateway API running at http://localhost:${port}`
            );
        });

        function shutdown(signal) {
            console.log(`\nReceived ${signal}. Shutting down.`);

            server.close(() => {
                closeFabricConnection();
                process.exit(0);
            });
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
