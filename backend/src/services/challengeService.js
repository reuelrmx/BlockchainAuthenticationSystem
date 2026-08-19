"use strict";

const crypto = require("node:crypto");

const authConfig = require("../config/authConfig");

class InMemoryChallengeStore {
    constructor() {
        this.challenges = new Map();
    }

    save(challenge) {
        this.challenges.set(challenge.challengeId, challenge);
    }

    get(challengeId) {
        return this.challenges.get(challengeId) || null;
    }

    delete(challengeId) {
        return this.challenges.delete(challengeId);
    }

    values() {
        return this.challenges.values();
    }
}

const store = new InMemoryChallengeStore();

function buildChallengePayload({
    did,
    challengeId,
    nonce,
    expiresAt
}) {
    return `${did}|${challengeId}|${nonce}|${expiresAt}`;
}

function isExpired(challenge, now = new Date()) {
    return Date.parse(challenge.expiresAt) <= now.getTime();
}

function purgeExpiredChallenges(now = new Date()) {
    for (const challenge of store.values()) {
        if (isExpired(challenge, now)) {
            store.delete(challenge.challengeId);
        }
    }
}

function cloneChallenge(challenge) {
    return {
        challengeId: challenge.challengeId,
        did: challenge.did,
        nonce: challenge.nonce,
        issuedAt: challenge.issuedAt,
        expiresAt: challenge.expiresAt,
        used: challenge.used
    };
}

function createChallenge(did) {
    purgeExpiredChallenges();

    const ttlSeconds = authConfig.challengeTtlSeconds;
    const issuedAtDate = new Date();
    const expiresAtDate = new Date(
        issuedAtDate.getTime() + ttlSeconds * 1000
    );

    const challenge = {
        challengeId: crypto.randomUUID(),
        did,
        nonce: crypto.randomBytes(32).toString("hex"),
        issuedAt: issuedAtDate.toISOString(),
        expiresAt: expiresAtDate.toISOString(),
        used: false
    };

    store.save(challenge);

    return {
        challengeId: challenge.challengeId,
        challengePayload: buildChallengePayload(challenge),
        expiresAt: challenge.expiresAt,
        expiresInSeconds: ttlSeconds
    };
}

function getChallenge(challengeId) {
    const challenge = store.get(challengeId);

    if (!challenge) {
        return null;
    }

    if (isExpired(challenge)) {
        store.delete(challengeId);
        return null;
    }

    return cloneChallenge(challenge);
}

function consumeChallenge(challengeId) {
    const challenge = store.get(challengeId);

    if (!challenge) {
        return {
            consumed: false,
            reason: "CHALLENGE_NOT_FOUND"
        };
    }

    if (isExpired(challenge)) {
        store.delete(challengeId);

        return {
            consumed: false,
            reason: "CHALLENGE_EXPIRED"
        };
    }

    if (challenge.used) {
        store.delete(challengeId);

        return {
            consumed: false,
            reason: "CHALLENGE_ALREADY_USED"
        };
    }

    challenge.used = true;
    store.delete(challengeId);

    return {
        consumed: true,
        challenge: cloneChallenge(challenge)
    };
}

module.exports = {
    createChallenge,
    getChallenge,
    consumeChallenge,
    buildChallengePayload
};
