// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AuthenticationBenchmark {
    enum DeviceStatus {
        NONE,
        ACTIVE,
        SUSPENDED,
        REVOKED
    }

    struct Device {
        string did;
        bytes32 publicKeyReference;
        address owner;
        DeviceStatus status;
        uint256 registeredAt;
        uint256 updatedAt;
    }

    struct AuthenticationEvent {
        bytes32 eventId;
        string did;
        bool granted;
        string reason;
        uint256 timestamp;
        address recordedBy;
    }

    address public immutable administrator;

    mapping(bytes32 => Device) private devices;
    mapping(bytes32 => AuthenticationEvent) private authenticationEvents;
    mapping(address => bool) private authorizedRecorders;
    bytes32[] private deviceKeys;
    bytes32[] private authenticationEventKeys;

    event DeviceRegistered(
        string indexed did,
        bytes32 indexed deviceKey,
        bytes32 publicKeyReference,
        address indexed owner
    );
    event DeviceStatusChanged(
        string indexed did,
        bytes32 indexed deviceKey,
        DeviceStatus status
    );
    event AuthenticationDecisionRecorded(
        bytes32 indexed eventId,
        string indexed did,
        bool granted,
        string reason
    );
    event RecorderAuthorizationChanged(
        address indexed recorder,
        bool authorized
    );

    modifier onlyAdministrator() {
        require(msg.sender == administrator, "only administrator");
        _;
    }

    modifier onlyRecorder() {
        require(
            msg.sender == administrator || authorizedRecorders[msg.sender],
            "only recorder"
        );
        _;
    }

    constructor() {
        administrator = msg.sender;
        authorizedRecorders[msg.sender] = true;
    }

    function setRecorderAuthorization(
        address recorder,
        bool authorized
    ) external onlyAdministrator {
        require(recorder != address(0), "recorder required");

        authorizedRecorders[recorder] = authorized;

        emit RecorderAuthorizationChanged(recorder, authorized);
    }

    function isRecorder(address recorder) external view returns (bool) {
        return recorder == administrator || authorizedRecorders[recorder];
    }

    function registerDevice(
        string calldata did,
        bytes32 publicKeyReference,
        address owner
    ) external onlyAdministrator {
        require(bytes(did).length > 0, "did required");
        require(publicKeyReference != bytes32(0), "public key required");
        require(owner != address(0), "owner required");

        bytes32 deviceKey = _deviceKey(did);

        require(devices[deviceKey].status == DeviceStatus.NONE, "device exists");

        devices[deviceKey] = Device({
            did: did,
            publicKeyReference: publicKeyReference,
            owner: owner,
            status: DeviceStatus.ACTIVE,
            registeredAt: block.timestamp,
            updatedAt: block.timestamp
        });
        deviceKeys.push(deviceKey);

        emit DeviceRegistered(did, deviceKey, publicKeyReference, owner);
    }

    function suspendDevice(string calldata did) external onlyAdministrator {
        _setDeviceStatus(did, DeviceStatus.SUSPENDED);
    }

    function activateDevice(string calldata did) external onlyAdministrator {
        bytes32 deviceKey = _deviceKey(did);
        Device storage device = devices[deviceKey];

        require(device.status != DeviceStatus.NONE, "device missing");
        require(device.status != DeviceStatus.REVOKED, "device revoked");

        device.status = DeviceStatus.ACTIVE;
        device.updatedAt = block.timestamp;

        emit DeviceStatusChanged(did, deviceKey, DeviceStatus.ACTIVE);
    }

    function revokeDevice(string calldata did) external onlyAdministrator {
        _setDeviceStatus(did, DeviceStatus.REVOKED);
    }

    function recordAuthenticationDecision(
        bytes32 eventId,
        string calldata did,
        bool granted,
        string calldata reason
    ) external onlyRecorder {
        require(eventId != bytes32(0), "event id required");
        require(bytes(reason).length > 0, "reason required");
        require(authenticationEvents[eventId].eventId == bytes32(0), "event exists");

        bytes32 deviceKey = _deviceKey(did);
        Device storage device = devices[deviceKey];

        require(device.status != DeviceStatus.NONE, "device missing");

        bool finalGranted = granted;
        string memory finalReason = reason;

        if (device.status != DeviceStatus.ACTIVE) {
            finalGranted = false;
            finalReason = "DEVICE_NOT_ACTIVE";
        }

        authenticationEvents[eventId] = AuthenticationEvent({
            eventId: eventId,
            did: did,
            granted: finalGranted,
            reason: finalReason,
            timestamp: block.timestamp,
            recordedBy: msg.sender
        });
        authenticationEventKeys.push(eventId);

        emit AuthenticationDecisionRecorded(
            eventId,
            did,
            finalGranted,
            finalReason
        );
    }

    function getDevice(
        string calldata did
    ) external view returns (Device memory) {
        bytes32 deviceKey = _deviceKey(did);
        Device memory device = devices[deviceKey];

        require(device.status != DeviceStatus.NONE, "device missing");

        return device;
    }

    function getDeviceStatus(
        string calldata did
    ) external view returns (DeviceStatus) {
        bytes32 deviceKey = _deviceKey(did);
        Device memory device = devices[deviceKey];

        require(device.status != DeviceStatus.NONE, "device missing");

        return device.status;
    }

    function getAuthenticationEvent(
        bytes32 eventId
    ) external view returns (AuthenticationEvent memory) {
        AuthenticationEvent memory authEvent = authenticationEvents[eventId];

        require(authEvent.eventId != bytes32(0), "event missing");

        return authEvent;
    }

    function getDeviceCount() external view returns (uint256) {
        return deviceKeys.length;
    }

    function getAuthenticationEventCount() external view returns (uint256) {
        return authenticationEventKeys.length;
    }

    function _setDeviceStatus(
        string calldata did,
        DeviceStatus status
    ) private {
        bytes32 deviceKey = _deviceKey(did);
        Device storage device = devices[deviceKey];

        require(device.status != DeviceStatus.NONE, "device missing");

        device.status = status;
        device.updatedAt = block.timestamp;

        emit DeviceStatusChanged(did, deviceKey, status);
    }

    function _deviceKey(string calldata did) private pure returns (bytes32) {
        return keccak256(bytes(did));
    }
}
