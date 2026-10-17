import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { ethers } from 'ethers'
const provider = new ethers.JsonRpcProvider('http://127.0.0.1:8545')
const hash = value => ethers.sha256(ethers.toUtf8Bytes(value))
const zero = ethers.ZeroHash
async function fixture() {
  const root = await provider.getSigner(0), attacker = await provider.getSigner(1)
  const registryArtifact = JSON.parse(await readFile(new URL('../artifacts/contracts/AgentTrustRegistry.sol/AgentTrustRegistry.json',import.meta.url)))
  const grantArtifact = JSON.parse(await readFile(new URL('../artifacts/contracts/GrantAuthority.sol/GrantAuthority.json',import.meta.url)))
  const registry = await new ethers.ContractFactory(registryArtifact.abi,registryArtifact.bytecode,root).deploy(); await registry.waitForDeployment()
  for (const [index, name] of ['ROOT_AUTHORIZER','Agent_A','Agent_B','Agent_C','Agent_D'].entries())
    await (await registry.registerAgent(hash(name),await (await provider.getSigner(index)).getAddress())).wait()
  const grants = await new ethers.ContractFactory(grantArtifact.abi,grantArtifact.bytecode,root).deploy(await registry.getAddress()); await grants.waitForDeployment()
  const expiry = Number((await provider.getBlock('latest')).timestamp) + 3600
  const issue = async (id,holder,parent=zero,scope=hash('P'),end=expiry) => (await grants.issueGrant(hash(id),hash(holder),scope,parent,end)).wait()
  await issue('A','Agent_A'); await issue('B','Agent_B',hash('A')); await issue('C','Agent_C',hash('B')); await issue('D','Agent_D',hash('C'))
  return {root,attacker,registry,grants,expiry,issue}
}
test('grant revocation cascades without rewriting descendants and retains historical validity',async()=>{
  const {grants} = await fixture()
  const before = await grants.grants(hash('D'))
  assert.equal(await grants.isValidNow(hash('D')),true)
  await (await grants.revokeGrant(hash('B'))).wait()
  assert.equal(await grants.isValidNow(hash('A')),true)
  for(const name of ['B','C','D']) assert.equal(await grants.isValidNow(hash(name)),false)
  assert.equal(await grants.wasValidAt(hash('D'),before.issuedAt),true)
  assert.equal((await grants.grants(hash('D'))).revokedAt,0n)
})
test('independent same-scope parent survives; repeated IDs and regrant resurrection are rejected',async()=>{
  const {grants,issue} = await fixture()
  await issue('C-independent','Agent_C')
  await (await grants.revokeGrant(hash('B'))).wait()
  assert.equal(await grants.isValidNow(hash('C')),false)
  assert.equal(await grants.isValidNow(hash('C-independent')),true)
  await issue('B-new','Agent_B',hash('A'))
  assert.equal(await grants.isValidNow(hash('D')),false)
  await issue('C-new','Agent_C',hash('B-new'))
  assert.equal(await grants.isValidNow(hash('C-new')),true)
  await assert.rejects(issue('C-new','Agent_C',hash('B-new')),/GRANT_EXISTS_OR_INVALID/)
})
test('root access, unknown parent, scope escalation, self/cycles and expiry extension fail closed',async()=>{
  const {grants,attacker,expiry,issue} = await fixture()
  await assert.rejects(grants.connect(attacker).revokeGrant(hash('A')),/ROOT_ONLY/)
  await assert.rejects(issue('bad','Agent_A',hash('unknown')),/INVALID_PARENT/)
  await assert.rejects(issue('bad','Agent_B',hash('A'),hash('OTHER')),/SCOPE_OR_EXPIRY_ESCALATION/)
  await assert.rejects(issue('bad','Agent_A',hash('A')),/SELF_OR_CYCLIC_DELEGATION/)
  await assert.rejects(issue('bad','Agent_A',hash('D')),/SELF_OR_CYCLIC_DELEGATION/)
  await assert.rejects(issue('bad','Agent_B',hash('A'),hash('P'),expiry+1),/SCOPE_OR_EXPIRY_ESCALATION/)
})
test('issuance inclusive and expiry exclusive for every ancestor',async()=>{
  const {grants,expiry} = await fixture()
  const leaf = await grants.grants(hash('D'))
  assert.equal(await grants.wasValidAt(hash('D'),leaf.issuedAt),true)
  assert.equal(await grants.wasValidAt(hash('D'),leaf.issuedAt-1n),false)
  assert.equal(await grants.wasValidAt(hash('D'),expiry),false)
  assert.equal(await grants.wasValidAt(hash('D'),expiry-1),true)
})
test('legacy full-agent revocation invalidates descendants but preserves independent scope paths',async()=>{
  const {registry,grants,issue} = await fixture()
  await issue('C-independent','Agent_C')
  const content=hash('revoke-B'),id=ethers.sha256(ethers.concat(['0x03',content]))
  await (await registry.anchorRevocationDetailed(id,hash('Agent_B'),[],content,new Date().toISOString(),'ROOT_AUTHORIZER',['P'])).wait()
  assert.equal(await grants.isValidNow(hash('C')),false)
  assert.equal(await grants.isValidNow(hash('D')),false)
  assert.equal(await grants.isValidNow(hash('C-independent')),true)
})
