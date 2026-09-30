// Deploys Integrity.sol to local Anvil/Hardhat node.
// Usage: npx hardhat node  (t1)  ->  npm run deploy (t2)
const hre = require("hardhat");
async function main() {
  const C = await hre.ethers.getContractFactory("Integrity");
  const c = await C.deploy();
  await c.waitForDeployment();
  console.log("Integrity deployed to:", await c.getAddress());
  console.log("Save this address into config/baseline.json as contractAddr");
}
main().catch((e) => { console.error(e); process.exit(1); });
