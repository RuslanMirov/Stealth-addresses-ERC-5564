// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./StealthAnnouncer.sol";

/**
 * @title  StealthSender
 * @notice Sends ETH directly to a stealth address and publishes the ERC-5564 announcement.
 *         No vault, no relayer — the simplest possible stealth payment.
 *
 *  How it works:
 *  ─────────────
 *  1. Alice computes a one-time stealth address off-chain (ECDH + secp256k1)
 *  2. Calls send() — ETH lands on the stealth EOA, announcement event is emitted
 *  3. Bob scans Announcement logs, reconstructs his private key: spendPriv + sharedSecret
 *  4. Bob spends from the stealth address directly — he already has ETH there for gas
 *
 *  Trade-offs vs StealthFactory + StealthVault:
 *  ─────────────────────────────────────────────
 *  + ~67k gas vs ~153k
 *  + No relayer, no fee, no extra contracts
 *  - Stealth address appears as msg.sender when Bob spends
 *    (two on-chain data points instead of zero — minor privacy trade-off)
 */
contract StealthSender {

    StealthAnnouncer public immutable announcer;

    event Sent(
        address indexed stealthAddr,
        address indexed sender,
        uint256 amount
    );

    constructor(address _announcer) {
        announcer = StealthAnnouncer(_announcer);
    }

    /**
     * @notice Send ETH to a stealth address and publish the ERC-5564 announcement.
     *
     * @param stealthAddr     One-time stealth EOA computed off-chain by Alice.
     * @param ephemeralPubKey 33-byte compressed secp256k1 ephemeral public key R.
     * @param viewTag         First byte of sha256(ECDH shared secret) — Bob's fast scan filter.
     */
    function send(
        address payable stealthAddr,
        bytes calldata  ephemeralPubKey,
        bytes1          viewTag
    ) external payable {
        require(stealthAddr != address(0), "StealthSender: zero address");
        require(ephemeralPubKey.length == 33, "StealthSender: bad key length");
        require(msg.value > 0, "StealthSender: must send ETH");

        // Send ETH directly to the stealth address
        (bool ok,) = stealthAddr.call{value: msg.value}("");
        require(ok, "StealthSender: transfer failed");

        // Publish announcement — stealthAddr is indexed in the event,
        // metadata carries only the viewTag (1 byte scan hint for Bob)
        announcer.announce(
            1,                          // schemeId: secp256k1 + sha256
            stealthAddr,
            ephemeralPubKey,
            abi.encodePacked(viewTag)
        );

        emit Sent(stealthAddr, msg.sender, msg.value);
    }
}