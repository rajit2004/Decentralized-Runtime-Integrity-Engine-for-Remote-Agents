// Deploys Integrity.sol to local Anvil/Hardhat node and wires the engine.
// Usage: npx hardhat node  (t1)  ->  npm run deploy (t2)  ->  engine (t3)
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const C = await hre.ethers.getContractFactory("Integrity");
  const c = await C.deploy();
  await c.waitForDeployment();
  const addr = await c.getAddress();
  const [signer] = await hre.ethers.getSigners();
  const net = await hre.ethers.provider.getNetwork();

  const cfg = {
    rpcUrl: "http://127.0.0.1:8545",
    contractAddr: addr,
    from: await signer.getAddress(),
    gas: "0xf4240",
    chainId: "0x" + net.chainId.toString(16)
  };
  // Local dev chain only: let the engine sign raw txs itself (pure-JDK secp256k1).
  // Never write a privateKey for any other chainId.
  if (net.chainId === 31337n) {
    try {
      const w = hre.ethers.HDNodeWallet.fromPhrase(
        "test test test test test test test test test test test junk");
      if (w.address.toLowerCase() === cfg.from.toLowerCase()) cfg.privateKey = w.privateKey;
      else console.log("skip privateKey: derived address != deployer");
    } catch (e) { console.log("skip privateKey:", e.message); }
  }
  const out = path.join(__dirname, "..", "..", "config", "chain.json");
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(cfg, null, 2) + "\n");

  console.log("Integrity deployed to:", addr);
  console.log("Owner:", cfg.from);
  if (cfg.privateKey) console.log("Local raw signing: privateKey written (chainId 31337 only)");
  console.log("Wrote config/chain.json - restart the engine to anchor on-chain.");
}
main().catch((e) => { console.error(e); process.exit(1); });
