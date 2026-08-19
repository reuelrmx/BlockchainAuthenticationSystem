"use strict";

const {
    getAuthenticationEvent,
    getAllAuthenticationEvents,
    getAuthenticationEventsByDevice
} = require("../services/auditService");

function requireParam(value, name, res) {
    if (typeof value !== "string" || value.trim() === "") {
        res.status(400).json({
            success: false,
            message: `${name} is required`
        });

        return null;
    }

    return value.trim();
}

async function getAuthenticationEvents(req, res, next) {
    try {
        const events = await getAllAuthenticationEvents();

        return res.status(200).json({
            success: true,
            count: Array.isArray(events) ? events.length : 0,
            data: events
        });
    } catch (error) {
        next(error);
    }
}

async function getAuthenticationEventById(req, res, next) {
    try {
        const eventId = requireParam(
            req.params.eventId,
            "Event ID",
            res
        );

        if (!eventId) {
            return;
        }

        const event = await getAuthenticationEvent(eventId);

        return res.status(200).json({
            success: true,
            data: event
        });
    } catch (error) {
        next(error);
    }
}

async function getDeviceAuthenticationEvents(req, res, next) {
    try {
        const did = requireParam(req.params.did, "DID", res);

        if (!did) {
            return;
        }

        const events = await getAuthenticationEventsByDevice(did);

        return res.status(200).json({
            success: true,
            did,
            count: Array.isArray(events) ? events.length : 0,
            data: events
        });
    } catch (error) {
        next(error);
    }
}

module.exports = {
    getAuthenticationEvents,
    getAuthenticationEventById,
    getDeviceAuthenticationEvents
};
