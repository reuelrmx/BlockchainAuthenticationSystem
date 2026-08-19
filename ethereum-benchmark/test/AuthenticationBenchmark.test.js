import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { keccak256, stringToHex } from "viem";

const STATUS = {
  ACTIVE: 1,
  SUSPENDED: 2,
  REVOKED: 3
};

function bytes32(label) {
  return keccak256(stringToHex(label));
}

async function deployFixture() {
  const { viem } = await network.create({
    network: "hardhatMainnet",
    chainType: "l1"
  });
  const publicClient = await viem.getPublicClient();
  const [administrator, owner, recorder, outsider] =
    await viem.getWalletClients();
  const contract = await viem.deployContract("AuthenticationBenchmark");

  return {
    viem,
    publicClient,
    contract,
    administrator,
    owner,
    recorder,
    outsider
  };
}

describe("AuthenticationBenchmark", async function () {
  it("registers a device and reports ACTIVE status", async function () {
    const { contract, owner } = await deployFixture();
    const did = "did:ethereum:test:active";

    await contract.write.registerDevice([
      did,
      bytes32("public-key-reference"),
      owner.account.address
    ]);

    assert.equal(
      Number(await contract.read.getDeviceStatus([did])),
      STATUS.ACTIVE
    );
    assert.equal(Number(await contract.read.getDeviceCount()), 1);
  });

  it("rejects duplicate registration", async function () {
    const { contract, owner } = await deployFixture();
    const did = "did:ethereum:test:duplicate";

    await contract.write.registerDevice([
      did,
      bytes32("duplicate-key"),
      owner.account.address
    ]);

    await assert.rejects(
      contract.write.registerDevice([
        did,
        bytes32("duplicate-key"),
        owner.account.address
      ]),
      /device exists/
    );
  });

  it("supports suspend, activate, and revoke status transitions", async function () {
    const { contract, owner } = await deployFixture();
    const did = "did:ethereum:test:status";

    await contract.write.registerDevice([
      did,
      bytes32("status-key"),
      owner.account.address
    ]);
    await contract.write.suspendDevice([did]);
    assert.equal(
      Number(await contract.read.getDeviceStatus([did])),
      STATUS.SUSPENDED
    );

    await contract.write.activateDevice([did]);
    assert.equal(
      Number(await contract.read.getDeviceStatus([did])),
      STATUS.ACTIVE
    );

    await contract.write.revokeDevice([did]);
    assert.equal(
      Number(await contract.read.getDeviceStatus([did])),
      STATUS.REVOKED
    );

    await assert.rejects(
      contract.write.activateDevice([did]),
      /device revoked/
    );
  });

  it("records a granted authentication event for an ACTIVE device", async function () {
    const { contract, owner } = await deployFixture();
    const did = "did:ethereum:test:auth";
    const eventId = bytes32("auth-event");

    await contract.write.registerDevice([
      did,
      bytes32("auth-key"),
      owner.account.address
    ]);
    await contract.write.recordAuthenticationDecision([
      eventId,
      did,
      true,
      "VALID_SIGNATURE"
    ]);

    const authEvent = await contract.read.getAuthenticationEvent([eventId]);

    assert.equal(authEvent.granted, true);
    assert.equal(authEvent.reason, "VALID_SIGNATURE");
    assert.equal(Number(await contract.read.getAuthenticationEventCount()), 1);
  });

  it("allows an authorized recorder to record an authentication event", async function () {
    const { viem, publicClient, contract, owner, recorder } =
      await deployFixture();
    const did = "did:ethereum:test:authorized-recorder";
    const eventId = bytes32("authorized-recorder-event");

    await contract.write.registerDevice([
      did,
      bytes32("authorized-recorder-key"),
      owner.account.address
    ]);
    await contract.write.setRecorderAuthorization([
      recorder.account.address,
      true
    ]);

    const recorderContract = await viem.getContractAt(
      "AuthenticationBenchmark",
      contract.address,
      {
        client: {
          public: publicClient,
          wallet: recorder
        }
      }
    );

    await recorderContract.write.recordAuthenticationDecision([
      eventId,
      did,
      true,
      "VALID_SIGNATURE"
    ]);

    const authEvent = await contract.read.getAuthenticationEvent([eventId]);

    assert.equal(authEvent.granted, true);
    assert.equal(authEvent.recordedBy.toLowerCase(), recorder.account.address);
  });

  it("rejects authentication recording from an unauthorized account", async function () {
    const { viem, publicClient, contract, owner, outsider } =
      await deployFixture();
    const did = "did:ethereum:test:unauthorized-recorder";

    await contract.write.registerDevice([
      did,
      bytes32("unauthorized-recorder-key"),
      owner.account.address
    ]);

    const outsiderContract = await viem.getContractAt(
      "AuthenticationBenchmark",
      contract.address,
      {
        client: {
          public: publicClient,
          wallet: outsider
        }
      }
    );

    await assert.rejects(
      outsiderContract.write.recordAuthenticationDecision([
        bytes32("unauthorized-recorder-event"),
        did,
        true,
        "VALID_SIGNATURE"
      ]),
      /only recorder/
    );
  });

  it("denies an authentication event for a non-active device", async function () {
    const { contract, owner } = await deployFixture();
    const did = "did:ethereum:test:suspended-auth";
    const eventId = bytes32("suspended-auth-event");

    await contract.write.registerDevice([
      did,
      bytes32("suspended-auth-key"),
      owner.account.address
    ]);
    await contract.write.suspendDevice([did]);
    await contract.write.recordAuthenticationDecision([
      eventId,
      did,
      true,
      "VALID_SIGNATURE"
    ]);

    const authEvent = await contract.read.getAuthenticationEvent([eventId]);

    assert.equal(authEvent.granted, false);
    assert.equal(authEvent.reason, "DEVICE_NOT_ACTIVE");
  });

  it("rejects authentication recording for an unknown device", async function () {
    const { contract } = await deployFixture();

    await assert.rejects(
      contract.write.recordAuthenticationDecision([
        bytes32("unknown-device-event"),
        "did:ethereum:test:missing",
        true,
        "VALID_SIGNATURE"
      ]),
      /device missing/
    );
  });

  it("prevents duplicate authentication event IDs", async function () {
    const { contract, owner } = await deployFixture();
    const did = "did:ethereum:test:duplicate-event";
    const eventId = bytes32("duplicate-event");

    await contract.write.registerDevice([
      did,
      bytes32("duplicate-event-key"),
      owner.account.address
    ]);
    await contract.write.recordAuthenticationDecision([
      eventId,
      did,
      true,
      "VALID_SIGNATURE"
    ]);

    await assert.rejects(
      contract.write.recordAuthenticationDecision([
        eventId,
        did,
        true,
        "VALID_SIGNATURE"
      ]),
      /event exists/
    );
  });
});
