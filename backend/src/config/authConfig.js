"use strict";

const DEFAULT_CHALLENGE_TTL_SECONDS = 60;
const MAX_CHALLENGE_TTL_SECONDS = 300;

function parseChallengeTtlSeconds(value) {
    if (value === undefined || value === null || value === "") {
        return DEFAULT_CHALLENGE_TTL_SECONDS;
    }

    const parsed = Number(value);

    if (
        !Number.isSafeInteger(parsed) ||
        parsed < 1 ||
        parsed > MAX_CHALLENGE_TTL_SECONDS
    ) {
        return DEFAULT_CHALLENGE_TTL_SECONDS;
    }

    return parsed;
}

module.exports = {
    challengeTtlSeconds: parseChallengeTtlSeconds(
        process.env.AUTH_CHALLENGE_TTL_SECONDS
    ),
    defaultChallengeTtlSeconds: DEFAULT_CHALLENGE_TTL_SECONDS,
    maxChallengeTtlSeconds: MAX_CHALLENGE_TTL_SECONDS
};
