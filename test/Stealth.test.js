/**
 * StealthDirect.test.js — vault-free scheme tests
 *
 *  Alice → StealthSender.send() → ETH lands on stealth EOA
 *  Bob   → scans logs → spends directly from stealth address
 */

const { expect }     = require("chai");
const { ethers }     = require("hardhat");
const { bytesToHex } = require("@noble/hashes/utils");

const {
  generateStealthKeys,
  computeStealthAddress,
  scanAnnouncementLogs,
  bytesToBigInt,
} = require("../helpers/stealth");

const { secp256k1 } = require("@noble/curves/secp256k1");

// ─── helpers ──────────────────────────────────────────────────────────────────

async function deploy() {
  const [deployer, alice, bob] = await ethers.getSigners();

  const Announcer = await ethers.getContractFactory("StealthAnnouncer");
  const announcer = await Announcer.deploy();
  await announcer.waitForDeployment();

  const Sender = await ethers.getContractFactory("StealthSender");
  const sender = await Sender.deploy(await announcer.getAddress());
  await sender.waitForDeployment();

  return { deployer, alice, bob, announcer, sender };
}

// shared helper: Alice pays Bob's stealth address
async function alicePays(sender, alice, bobKeys, amount) {
  const result = computeStealthAddress(bobKeys.metaAddress);
  await sender.connect(alice).send(
    result.stealthAddress,
    "0x" + bytesToHex(result.ephemeralPubKey),
    "0x" + result.viewTag.toString(16).padStart(2, "0"),
    { value: ethers.parseEther(amount) }
  );
  return result;
}

// ─── tests ────────────────────────────────────────────────────────────────────

describe("ERC-5564 vault-free (StealthSender)", function () {

  it("Alice sends ETH directly to the stealth address", async function () {
    const { alice, sender } = await deploy();
    const bobKeys = generateStealthKeys();
    const { stealthAddress, ephemeralPubKey, viewTag } =
      computeStealthAddress(bobKeys.metaAddress);

    const before = await ethers.provider.getBalance(stealthAddress);

    await sender.connect(alice).send(
      stealthAddress,
      "0x" + bytesToHex(ephemeralPubKey),
      "0x" + viewTag.toString(16).padStart(2, "0"),
      { value: ethers.parseEther("1.0") }
    );

    const after = await ethers.provider.getBalance(stealthAddress);
    expect(after - before).to.equal(ethers.parseEther("1.0"));
  });

  it("Alice's send() emits Announcement and Sent events", async function () {
    const { alice, announcer, sender } = await deploy();
    const bobKeys = generateStealthKeys();
    const { stealthAddress, ephemeralPubKey, viewTag } =
      computeStealthAddress(bobKeys.metaAddress);

    const tx = await sender.connect(alice).send(
      stealthAddress,
      "0x" + bytesToHex(ephemeralPubKey),
      "0x" + viewTag.toString(16).padStart(2, "0"),
      { value: ethers.parseEther("1.0") }
    );

    await expect(tx).to.emit(announcer, "Announcement");
    await expect(tx).to.emit(sender, "Sent");
  });

  it("Bob scans logs and finds his stealth address", async function () {
    const { alice, announcer, sender } = await deploy();
    const bobKeys = generateStealthKeys();
    const { stealthAddress } = await alicePays(sender, alice, bobKeys, "0.5");

    const logs  = await announcer.queryFilter(announcer.filters.Announcement());
    const found = scanAnnouncementLogs(logs, announcer.interface, bobKeys);

    expect(found.length).to.be.greaterThan(0);
    // In the vault-free scheme, vault === stealthAddr
    expect(found[0].vault.toLowerCase()).to.equal(stealthAddress.toLowerCase());
  });

  it("Bob reconstructs private key and spends ETH directly", async function () {
    const { alice, announcer, sender } = await deploy();
    const bobKeys = generateStealthKeys();
    const { stealthAddress, sharedSecret } = await alicePays(sender, alice, bobKeys, "1.0");

    // Reconstruct stealth private key: spendPriv + sharedSecret (mod n)
    const stealthPriv =
      (bytesToBigInt(bobKeys.spendingPrivKey) + bytesToBigInt(sharedSecret)) %
      secp256k1.CURVE.n;

    const stealthWallet = new ethers.Wallet(
      "0x" + stealthPriv.toString(16).padStart(64, "0"),
      ethers.provider
    );

    // Wallet address must match the stealth address Alice paid
    expect(stealthWallet.address.toLowerCase()).to.equal(stealthAddress.toLowerCase());

    // The stealth address already has ETH from Alice — Bob can pay gas from it directly
    const [,, dest] = await ethers.getSigners();
    const before = await ethers.provider.getBalance(await dest.getAddress());

    await stealthWallet.sendTransaction({
      to:    await dest.getAddress(),
      value: ethers.parseEther("0.9"),
    });

    const after = await ethers.provider.getBalance(await dest.getAddress());
    expect(after - before).to.equal(ethers.parseEther("0.9"));
  });

  it("Eve cannot find Bob's stealth address in the logs", async function () {
    const { alice, announcer, sender } = await deploy();
    const bobKeys = generateStealthKeys();
    const eveKeys = generateStealthKeys();

    await alicePays(sender, alice, bobKeys, "1.0");

    const logs = await announcer.queryFilter(announcer.filters.Announcement());

    // Eve scans with her own keys — finds nothing
    expect(scanAnnouncementLogs(logs, announcer.interface, eveKeys).length).to.equal(0);

    // Bob scans with his keys — finds exactly one
    expect(scanAnnouncementLogs(logs, announcer.interface, bobKeys).length).to.equal(1);
  });

  it("send() uses < 75 000 gas", async function () {
    const { alice, sender } = await deploy();
    const bobKeys = generateStealthKeys();
    const { stealthAddress, ephemeralPubKey, viewTag } =
      computeStealthAddress(bobKeys.metaAddress);

    const tx = await sender.connect(alice).send(
      stealthAddress,
      "0x" + bytesToHex(ephemeralPubKey),
      "0x" + viewTag.toString(16).padStart(2, "0"),
      { value: ethers.parseEther("0.1") }
    );
    const receipt = await tx.wait();
    expect(receipt.gasUsed).to.be.lessThan(75_000n);
  });
});