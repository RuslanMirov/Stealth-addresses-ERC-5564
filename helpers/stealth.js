/**
 * stealth.js — Off-chain helpers for ERC-5564 stealth payments (scheme 1)
 *
 *  Cryptographic scheme: secp256k1 + sha256
 *  ─────────────────────────────────────────
 *  Sender (Alice):
 *    1. Generate ephemeral key  r  →  R = r·G
 *    2. Compute shared secret   S  = sha256( r·viewPub )
 *    3. viewTag = S[0]          — 1-byte scan filter
 *    4. stealthPub = spendPub + S·G
 *    5. stealthAddr = keccak256(stealthPub[1:])[12:]
 *
 *  Receiver (Bob):
 *    1. For each announcement: compute S = sha256( viewPriv·R )
 *    2. Check viewTag == S[0]   — fast filter, skips 255/256
 *    3. Derive stealthPub, check address matches
 *    4. stealthPriv = spendPriv + S   (mod n)
 *
 *  Dependencies: @noble/curves, @noble/hashes
 */

const { secp256k1 }   = require("@noble/curves/secp256k1");
const { sha256 }      = require("@noble/hashes/sha256");
const { keccak_256 }  = require("@noble/hashes/sha3");
const { bytesToHex, hexToBytes, concatBytes } = require("@noble/hashes/utils");
const { ethers }      = require("ethers");

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** secp256k1 curve order */
const CURVE_N = secp256k1.CURVE.n;

/**
 * Convert an uncompressed or compressed public key to an Ethereum address.
 * @param {Uint8Array} pubKeyBytes — 33 (compressed) or 65 (uncompressed) bytes
 * @returns {string} checksummed Ethereum address
 */
function pubKeyToAddress(pubKeyBytes) {
  // Ensure uncompressed (65 bytes, drop first 0x04 byte)
  let uncompressed;
  if (pubKeyBytes.length === 33) {
    uncompressed = secp256k1.ProjectivePoint.fromHex(pubKeyBytes).toRawBytes(false);
  } else {
    uncompressed = pubKeyBytes;
  }
  // keccak256 of x||y (64 bytes), take last 20 bytes
  const hash = keccak_256(uncompressed.slice(1));
  const addr = "0x" + bytesToHex(hash.slice(12));
  return ethers.getAddress(addr); // checksummed
}

/**
 * Add two BigInt private keys modulo curve order.
 * @param {bigint} a
 * @param {bigint} b
 * @returns {bigint}
 */
function addPrivKeys(a, b) {
  return (a + b) % CURVE_N;
}

/**
 * Convert Uint8Array to BigInt (big-endian).
 * @param {Uint8Array} bytes
 * @returns {bigint}
 */
function bytesToBigInt(bytes) {
  return BigInt("0x" + bytesToHex(bytes));
}

// ─── Bob key generation ───────────────────────────────────────────────────────

/**
 * Generate Bob's stealth meta-address (one-time setup).
 *
 * @returns {{
 *   spendingPrivKey:  Uint8Array,
 *   viewingPrivKey:   Uint8Array,
 *   spendingPubKey:   Uint8Array,  // 33 bytes, compressed
 *   viewingPubKey:    Uint8Array,  // 33 bytes, compressed
 *   metaAddress: { spendingPubKey: Uint8Array, viewingPubKey: Uint8Array }
 * }}
 */
function generateStealthKeys() {
  const spendingPrivKey = secp256k1.utils.randomPrivateKey();
  const viewingPrivKey  = secp256k1.utils.randomPrivateKey();

  const spendingPubKey = secp256k1.getPublicKey(spendingPrivKey, true); // compressed
  const viewingPubKey  = secp256k1.getPublicKey(viewingPrivKey,  true);

  return {
    spendingPrivKey,
    viewingPrivKey,
    spendingPubKey,
    viewingPubKey,
    metaAddress: { spendingPubKey, viewingPubKey },
  };
}

// ─── Alice — compute stealth address ─────────────────────────────────────────

/**
 * Compute a one-time stealth address for Bob, given his meta-address.
 * Called by Alice before every payment.
 *
 * @param {{ spendingPubKey: Uint8Array, viewingPubKey: Uint8Array }} bobMetaAddress
 * @returns {{
 *   stealthAddress:   string,       // Ethereum address (checksummed)
 *   ephemeralPrivKey: Uint8Array,   // keep secret! used only to derive R
 *   ephemeralPubKey:  Uint8Array,   // 33 bytes — publish in announcement
 *   viewTag:          number,       // first byte of shared secret (0-255)
 *   sharedSecret:     Uint8Array,   // full 32-byte sha256 output
 * }}
 */
function computeStealthAddress(bobMetaAddress) {
  const { spendingPubKey, viewingPubKey } = bobMetaAddress;

  // 1. Ephemeral key pair
  const r = secp256k1.utils.randomPrivateKey();
  const R = secp256k1.getPublicKey(r, true); // compressed 33 bytes

  // 2. ECDH: shared point = r · viewPub
  const rScalar = secp256k1.utils.normPrivateKeyToScalar(r);
  const sharedPoint = secp256k1.ProjectivePoint
    .fromHex(viewingPubKey)
    .multiply(rScalar);

  // 3. Shared secret = sha256(compressed shared point)
  const sharedSecret = sha256(sharedPoint.toRawBytes(true)); // 32 bytes

  // 4. viewTag = first byte
  const viewTag = sharedSecret[0];

  // 5. Stealth public key = spendPub + sha256(sharedSecret)·G
  const sScalar = secp256k1.utils.normPrivateKeyToScalar(sharedSecret);
  const tweak   = secp256k1.ProjectivePoint.BASE.multiply(sScalar);

  const stealthPubPoint = secp256k1.ProjectivePoint
    .fromHex(spendingPubKey)
    .add(tweak);

  // 6. Ethereum address from stealth public key
  const stealthAddress = pubKeyToAddress(stealthPubPoint.toRawBytes(false));

  return {
    stealthAddress,
    ephemeralPrivKey: r,
    ephemeralPubKey:  R,
    viewTag,
    sharedSecret,
  };
}

// ─── Bob — scan announcements ─────────────────────────────────────────────────

/**
 * Check a single announcement log against Bob's viewing key.
 * Returns stealth info if the announcement belongs to Bob, null otherwise.
 *
 * @param {{
 *   stealthAddr:     string,        // from event
 *   ephemeralPubKey: Uint8Array,    // 33 bytes from event
 *   viewTagByte:     number,        // metadata[0] from event
 * }} announcement
 *
 * @param {{
 *   viewingPrivKey:  Uint8Array,
 *   spendingPubKey:  Uint8Array,
 *   spendingPrivKey: Uint8Array,   // optional — pass to get stealthPrivKey
 * }} bobKeys
 *
 * @returns {null | {
 *   stealthAddress:  string,
 *   stealthPrivKey:  bigint | null,
 *   sharedSecret:    Uint8Array,
 * }}
 */
function checkAnnouncement(announcement, bobKeys) {
  const { stealthAddr, ephemeralPubKey, viewTagByte } = announcement;
  const { viewingPrivKey, spendingPubKey, spendingPrivKey } = bobKeys;

  // ── Step 1: fast viewTag check (no expensive ECDH yet) ──────────────────
  const vScalar = secp256k1.utils.normPrivateKeyToScalar(viewingPrivKey);
  const sharedPoint = secp256k1.ProjectivePoint
    .fromHex(ephemeralPubKey)
    .multiply(vScalar);

  const sharedSecret = sha256(sharedPoint.toRawBytes(true));
  const myViewTag    = sharedSecret[0];

  // 255/256 announcements are rejected here — very cheap
  if (myViewTag !== viewTagByte) return null;

  // ── Step 2: derive expected stealth address ──────────────────────────────
  const sScalar = secp256k1.utils.normPrivateKeyToScalar(sharedSecret);
  const tweak   = secp256k1.ProjectivePoint.BASE.multiply(sScalar);

  const expectedPubPoint = secp256k1.ProjectivePoint
    .fromHex(spendingPubKey)
    .add(tweak);

  const expectedAddr = pubKeyToAddress(expectedPubPoint.toRawBytes(false));

  if (expectedAddr.toLowerCase() !== stealthAddr.toLowerCase()) return null;

  // ── Step 3: (optional) recover spendable private key ────────────────────
  let stealthPrivKey = null;
  if (spendingPrivKey) {
    const spendScalar = bytesToBigInt(spendingPrivKey);
    const secretScalar = bytesToBigInt(sharedSecret);
    stealthPrivKey = addPrivKeys(spendScalar, secretScalar);
  }

  return {
    stealthAddress: expectedAddr,
    stealthPrivKey,
    sharedSecret,
  };
}

/**
 * Scan a batch of announcement log objects (from ethers.js getLogs).
 * Returns an array of matching vaults.
 *
 * @param {Array}  logs      — raw ethers Log objects from StealthAnnouncer
 * @param {Object} iface     — ethers.Interface for StealthAnnouncer
 * @param {Object} bobKeys   — { viewingPrivKey, spendingPubKey, spendingPrivKey }
 * @returns {Array<{ vault: string, stealthPrivKey: bigint, sharedSecret: Uint8Array }>}
 */
function scanAnnouncementLogs(logs, iface, bobKeys) {
  const results = [];

  for (const log of logs) {
    let decoded;
    try {
      decoded = iface.parseLog(log);
    } catch {
      continue;
    }

    const stealthAddr     = decoded.args.stealthAddr;
    const ephemeralPubRaw = decoded.args.ephemeralPubKey; // Uint8Array in ethers v6
    const metadataRaw     = decoded.args.metadata;        // Uint8Array in ethers v6

    // ethers v6 returns non-indexed bytes event args as Uint8Array.
    // Guard with instanceof before calling string methods.
    let ephemeralPubKey;
    try {
      if (ephemeralPubRaw instanceof Uint8Array) {
        ephemeralPubKey = ephemeralPubRaw;
      } else {
        const hex = ephemeralPubRaw.startsWith("0x")
          ? ephemeralPubRaw.slice(2) : ephemeralPubRaw;
        ephemeralPubKey = hexToBytes(hex);
      }
    } catch { continue; }
    if (ephemeralPubKey.length !== 33) continue;

    // viewTag = first byte of metadata
    let viewTagByte;
    try {
      if (metadataRaw instanceof Uint8Array) {
        if (metadataRaw.length < 1) continue;
        viewTagByte = metadataRaw[0];
      } else {
        const metaHex = metadataRaw.startsWith("0x")
          ? metadataRaw.slice(2) : metadataRaw;
        if (metaHex.length < 2) continue;
        viewTagByte = parseInt(metaHex.slice(0, 2), 16);
      }
    } catch { continue; }

    const result = checkAnnouncement(
      { stealthAddr, ephemeralPubKey, viewTagByte },
      bobKeys
    );

    if (result) {
      // Extract vault address from metadata bytes 1-20 (packed by StealthFactory).
      // If metadata is shorter than 21 bytes the vault field is absent — use stealthAddr.
      let vault = stealthAddr;
      try {
        const metaBytes = metadataRaw instanceof Uint8Array
          ? metadataRaw
          : hexToBytes(metadataRaw.startsWith("0x") ? metadataRaw.slice(2) : metadataRaw);
        if (metaBytes.length >= 21) {
          vault = "0x" + bytesToHex(metaBytes.slice(1, 21));
          // Checksum the address so it compares correctly
          vault = ethers.getAddress(vault);
        }
      } catch { /* leave vault = stealthAddr */ }

      results.push({
        vault,
        stealthAddr,
        stealthPrivKey: result.stealthPrivKey,
        sharedSecret:  result.sharedSecret,
      });
    }
  }

  return results;
}

// ─── EIP-712 signing helpers ──────────────────────────────────────────────────

/**
 * Build the EIP-712 domain and types for StealthVault.
 *
 * @param {number|bigint} chainId
 * @param {string}        vaultAddress
 * @returns {{ domain: Object, types: Object }}
 */
function buildWithdrawDomain(chainId, vaultAddress) {
  return {
    domain: {
      name:              "StealthVault",
      version:           "2",
      chainId:           Number(chainId),
      verifyingContract: vaultAddress,
    },
    types: {
      WithdrawRequest: [
        { name: "to",       type: "address" },
        { name: "amount",   type: "uint256" },
        { name: "fee",      type: "uint256" },
        { name: "nonce",    type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    },
  };
}

/**
 * Sign a withdrawal request off-chain (Bob calls this).
 *
 * @param {bigint}  stealthPrivKey — derived from spendingPrivKey + sharedSecret
 * @param {string}  vaultAddress
 * @param {number|bigint} chainId
 * @param {{
 *   to:       string,
 *   amount:   bigint,
 *   fee:      bigint,
 *   nonce:    bigint,
 *   deadline: number,
 * }} withdrawRequest
 *
 * @returns {Promise<{ sig: string, v: number, r: string, s: string }>}
 */
async function signWithdrawRequest(stealthPrivKey, vaultAddress, chainId, withdrawRequest) {
  // Build an ethers Wallet from the stealth private key
  const privHex = "0x" + stealthPrivKey.toString(16).padStart(64, "0");
  const wallet  = new ethers.Wallet(privHex);

  const { domain, types } = buildWithdrawDomain(chainId, vaultAddress);

  const sig = await wallet.signTypedData(domain, types, withdrawRequest);
  const { v, r, s } = ethers.Signature.from(sig);

  return { sig, v, r, s };
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  generateStealthKeys,
  computeStealthAddress,
  checkAnnouncement,
  scanAnnouncementLogs,
  signWithdrawRequest,
  buildWithdrawDomain,
  pubKeyToAddress,
  bytesToBigInt,
  addPrivKeys,
};