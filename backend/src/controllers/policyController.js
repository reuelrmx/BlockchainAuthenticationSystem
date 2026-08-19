"use strict";

const {
    getAccessPolicy,
    updateAccessPolicy
} = require("../services/accessPolicyService");

async function getPolicy(req, res, next) {
    try {
        const policy = await getAccessPolicy();

        return res.status(200).json({
            success: true,
            data: policy
        });
    } catch (error) {
        next(error);
    }
}

async function updatePolicy(req, res, next) {
    try {
        const policy = await updateAccessPolicy(req.body);

        return res.status(200).json({
            success: true,
            message: "Access policy updated",
            data: policy
        });
    } catch (error) {
        next(error);
    }
}

module.exports = {
    getPolicy,
    updatePolicy
};
