"use strict";

const IdentityRegistryContract = require("./lib/IdentityRegistryContract");
const AccessControlContract = require("./lib/AccessControlContract");

module.exports.contracts = [
    IdentityRegistryContract,
    AccessControlContract
];
