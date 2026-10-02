import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { ethers } from "ethers";

const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");
const artifact = JSON.parse(
  await readFile(new URL("../artifacts/contracts/AgentTrustRegistry.sol/AgentTrustRegistry.json", import.meta.url)),
);
const digest = (value) => ethers.sha256(ethers.toUtf8Bytes(value));
const recordId = (kind, contentHash) => ethers.sha256(ethers.concat([ethers.toBeHex(kind, 1), contentHash]));

test("root administration, scope, delegation, revocation, and duplicate guards", async () => {
  const root = await provider.getSigner(0);
  const alice = await provider.getSigner(1);
  const bob = await provider.getSigner(2);
  const charlie = await provider.getSigner(3);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, root);
  const registry = await factory.deploy();
  await registry.waitForDeployment();

  const rootHash = digest("ROOT_AUTHORIZER");
  const aliceHash = digest("Agent_A");
  const bobHash = digest("Agent_B");
  const charlieHash = digest("Agent_C");
  const permission = digest("CREATE_AGENT");
  for (const [agentHash, signer] of [[rootHash, root], [aliceHash, alice], [bobHash, bob], [charlieHash, charlie]]) {
    await (await registry.registerAgent(agentHash, await signer.getAddress())).wait();
  }
  await assert.rejects(
    registry.connect(alice).registerAgent(digest("Evil"), await alice.getAddress()),
    /ROOT_ONLY/,
  );
  await assert.rejects(registry.registerAgent(aliceHash, await alice.getAddress()), /AGENT_EXISTS/);

  const now = Math.floor(Date.now() / 1000);
  const aliceCredential = digest("alice-credential");
  await (await registry.issueCredential(
    recordId(1, aliceCredential), aliceHash, await alice.getAddress(), await root.getAddress(),
    permission, permission, now, now + 3600, aliceCredential,
  )).wait();
  const aliceStored = await registry.credentials(recordId(1, aliceCredential));
  assert.equal(aliceStored.active, true);
  assert.equal(aliceStored.permissionScope, permission);
  await assert.rejects(
    registry.connect(alice).issueCredential(
      recordId(1, digest("unauthorized")), aliceHash, await alice.getAddress(), await root.getAddress(),
      permission, permission, now, now + 3600, digest("unauthorized"),
    ),
    /ROOT_ONLY/,
  );

  const badDelegation = digest("bad-delegation");
  await assert.rejects(
    registry.anchorDelegation(recordId(2, badDelegation), bobHash, charlieHash, permission, badDelegation),
    /NO_ACTIVE_CREDENTIAL/,
  );
  const delegation = digest("alice-to-bob");
  await (await registry.anchorDelegation(recordId(2, delegation), aliceHash, bobHash, permission, delegation)).wait();
  await assert.rejects(
    registry.anchorDelegation(recordId(2, delegation), aliceHash, bobHash, permission, delegation),
    /RECORD_EXISTS/,
  );
  await assert.rejects(
    registry.anchorDelegation(recordId(2, digest("duplicate-grant")), aliceHash, bobHash, permission, digest("duplicate-grant")),
    /DELEGATION_EXISTS/,
  );

  const bobCredential = digest("bob-credential");
  await (await registry.issueCredential(
    recordId(1, bobCredential), bobHash, await bob.getAddress(), await alice.getAddress(),
    permission, permission, now, now + 3600, bobCredential,
  )).wait();
  const secondDelegation = digest("bob-to-charlie");
  await (await registry.anchorDelegation(recordId(2, secondDelegation), bobHash, charlieHash, permission, secondDelegation)).wait();
  const charlieCredential = digest("charlie-credential");
  await (await registry.issueCredential(
    recordId(1, charlieCredential), charlieHash, await charlie.getAddress(), await bob.getAddress(),
    permission, ethers.ZeroHash, now, now + 3600, charlieCredential,
  )).wait();

  const revocation = digest("charlie-revoked");
  const revokedAt = "2026-09-30T11:37:43.392868+00:00";
  const permissions = ["CREATE_AGENT"];
  await (await registry.anchorRevocationDetailed(
    recordId(3, revocation), charlieHash, [recordId(1, charlieCredential)],
    revocation, revokedAt, "ROOT_AUTHORIZER", permissions,
  )).wait();
  assert.equal(await registry.agentRevoked(charlieHash), true);
  assert.equal((await registry.credentials(recordId(1, charlieCredential))).active, false);
  const details = await registry.getRevocationDetails(charlieHash);
  assert.equal(details.revokedAt, revokedAt);
  assert.equal(details.revokedBy, "ROOT_AUTHORIZER");
  assert.deepEqual([...details.permissions], permissions);
  assert.equal(details.contentHash, revocation);
  assert.equal(details.recordId, recordId(3, revocation));
  assert.ok(details.confirmedAt > 0n);
  await assert.rejects(
    registry.anchorRevocationDetailed(recordId(3, digest("again")), charlieHash, [recordId(1, charlieCredential)],
      digest("again"), revokedAt, "ROOT_AUTHORIZER", permissions),
    /AGENT_REVOKED/,
  );

  const action = digest("action-log-entry");
  await (await registry.anchorActionHash(recordId(4, action), action)).wait();
  assert.equal((await registry.commitments(recordId(4, action))).kind, 4n);
  await assert.rejects(registry.anchorActionHash(recordId(4, action), action), /RECORD_EXISTS/);
});

test("audit batch roots are root-only, immutable, and retrievable", async () => {
  const root = await provider.getSigner(0);
  const other = await provider.getSigner(1);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, root);
  const registry = await factory.deploy();
  await registry.waitForDeployment();

  const batchId = ethers.keccak256(ethers.toUtf8Bytes("batch:demo"));
  const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("merkle-root"));
  const startTimestamp = 1_791_000_000;
  const endTimestamp = startTimestamp + 90;
  await assert.rejects(
    registry.connect(other).anchorAuditBatch(batchId, merkleRoot, 5, startTimestamp, endTimestamp),
    /ROOT_ONLY/,
  );

  const tx = await registry.anchorAuditBatch(batchId, merkleRoot, 5, startTimestamp, endTimestamp);
  const receipt = await tx.wait();
  const event = receipt.logs
    .map((log) => { try { return registry.interface.parseLog(log); } catch { return null; } })
    .find((entry) => entry?.name === "AuditBatchAnchored");
  assert.ok(event);
  assert.equal(event.args.batchId, batchId);
  assert.equal(event.args.merkleRoot, merkleRoot);
  assert.equal(event.args.logCount, 5n);
  assert.equal(event.args.startTimestamp, BigInt(startTimestamp));
  assert.equal(event.args.endTimestamp, BigInt(endTimestamp));
  assert.equal(event.args.anchoredBy, await root.getAddress());

  const stored = await registry.auditBatches(batchId);
  assert.equal(stored.exists, true);
  assert.equal(stored.merkleRoot, merkleRoot);
  assert.equal(stored.logCount, 5n);
  assert.equal(stored.startTimestamp, BigInt(startTimestamp));
  assert.equal(stored.endTimestamp, BigInt(endTimestamp));
  assert.equal(stored.anchoredBy, await root.getAddress());
  assert.ok(stored.anchoredAt > 0n);
  await assert.rejects(
    registry.anchorAuditBatch(batchId, merkleRoot, 5, startTimestamp, endTimestamp),
    /BATCH_EXISTS/,
  );
});
