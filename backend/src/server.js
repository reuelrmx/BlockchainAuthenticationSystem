"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");

const deviceRoutes = require("./routes/deviceRoutes");
const errorHandler = require("./middleware/errorHandler");

const {
    connectToFabric,
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
        await connectToFabric();

        res.status(200).json({
            success: true,
            api: "healthy",
            fabric: "connected"
        });
    } catch (error) {
        next(error);
    }
});

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