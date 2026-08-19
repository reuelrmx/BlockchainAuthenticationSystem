"use strict";

const IdentityRegistryContract = require("./lib/IdentityRegistryContract");
const AccessControlContract = require("./lib/AccessControlContract");
const AuditLogContract = require("./lib/AuditLogContract");

module.exports.contracts = [
    IdentityRegistryContract,
    AccessControlContract,
    AuditLogContract
];
