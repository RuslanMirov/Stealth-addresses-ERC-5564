/**
 * deploy.js — Deploy StealthAnnouncer + StealthFactory to any network.
 *
 * Usage:
 *   hardhat run scripts/deploy.js --network localhost
 *   hardhat run scripts/deploy.js --network sepolia
 */

const { ethers } = require("hardhat");
const {
  generateStealthKeys,
  computeStealthAddress,
} = require("../helpers/stealth");
const { bytesToHex } = require("@noble/hashes/utils");

async function main() {
  const [deployer] = await ethers.getSigners();
  const network    = await ethers.provider.getNetwork();

  console.log("═══════════════════════════════════════════════════");
  console.log(" ERC-5564 Stealth Address System — Deployment");
  console.log("═══════════════════════════════════════════════════");
  console.log("Network  :", network.name, `(chainId ${network.chainId})`);
  console.log("Deployer :", deployer.address);
  console.log("Balance  :", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");
  console.log();

  // ── 1. Deploy StealthAnnouncer ────────────────────────────────────────────
  console.log("1. Deploying StealthAnnouncer...");
  const Announcer = await ethers.getContractFactory("StealthAnnouncer");
  const announcer = await Announcer.deploy();
  await announcer.waitForDeployment();
  const announcerAddr = await announcer.getAddress();
  console.log("   StealthAnnouncer:", announcerAddr);

  // ── 2. Deploy StealthFactory (also deploys implementation vault) ──────────
  console.log("2. Deploying StealthFactory + vault implementation...");
  const Factory = await ethers.getContractFactory("StealthFactory");
  const factory = await Factory.deploy(announcerAddr);
  await factory.waitForDeployment();
  const factoryAddr = await factory.getAddress();
  const implAddr    = await factory.vaultImplementation();
  console.log("   StealthFactory      :", factoryAddr);
  console.log("   StealthVault (impl) :", implAddr);
  console.log();

  // ── 3. Demo round-trip (on local / testnet) ───────────────────────────────
  console.log("3. Demo: Alice pays Bob 0.01 ETH via stealth address");
  const bobKeys = generateStealthKeys();
  console.log("   Bob spending pubkey :", "0x" + bytesToHex(bobKeys.spendingPubKey));
  console.log("   Bob viewing  pubkey :", "0x" + bytesToHex(bobKeys.viewingPubKey));

  const { stealthAddress, ephemeralPubKey, viewTag } =
    computeStealthAddress(bobKeys.metaAddress);
  console.log("   Alice computed stealth address :", stealthAddress);
  console.log("   Ephemeral pubkey (R)           :", "0x" + bytesToHex(ephemeralPubKey));
  console.log("   viewTag                        :", viewTag);

  const viewTagHex      = "0x" + viewTag.toString(16).padStart(2, "0");
  const ephemeralPubHex = "0x" + bytesToHex(ephemeralPubKey);

  const tx = await factory.deployAndSend(
    stealthAddress,
    ephemeralPubHex,
    viewTagHex,
    { value: ethers.parseEther("0.01") }
  );
  const receipt = await tx.wait();
  console.log("   Tx hash  :", receipt.hash);
  console.log("   Gas used :", receipt.gasUsed.toString());

  const filter = announcer.filters.Announcement();
  const logs   = await announcer.queryFilter(filter, receipt.blockNumber);
  console.log("   Announcement event logged :", logs.length > 0 ? "yes ✓" : "MISSING ✗");
  console.log();

  console.log("═══════════════════════════════════════════════════");
  console.log(" Deployment complete! Save these addresses:");
  console.log("═══════════════════════════════════════════════════");
  console.log(`ANNOUNCER_ADDRESS=${announcerAddr}`);
  console.log(`FACTORY_ADDRESS=${factoryAddr}`);
  console.log(`VAULT_IMPL_ADDRESS=${implAddr}`);
}

main()
  .then(() => process.exit(0))
  .catch(err => {
    console.error(err);
    process.exit(1);
  });