"use strict";

const {
    buildPerformanceSummary
} = require("../services/performanceSummaryService");

async function getPerformanceSummary(req, res, next) {
    try {
        const summary = await buildPerformanceSummary();

        return res.status(200).json({
            success: true,
            data: summary
        });
    } catch (error) {
        next(error);
    }
}

module.exports = {
    getPerformanceSummary
};
