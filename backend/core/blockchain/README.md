# Module 2: Ethereum anchoring

`AgentTrustRegistry.sol` on a Hardhat local network is the trust anchor. Python
Web3.py deploys the contract, registers five public identities, issues scoped
credentials, and commits Module 1 delegation, revocation, and action hashes.
The complete Module 1 records and readable credential issuance JSON remain
off-chain in `ethereum_state.json` and `credentials.json`.

## Run on Windows PowerShell

From `blockchain`:

```powershell
npm install
npm run compile
npm run node
```

Leave the node running. Its wrapper prints only the RPC address; it suppresses
Hardhat's default display of development account private keys.

From the repository root in another terminal:

```powershell
py -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe -B -m backend.core.blockchain.main
```

Contract and Python backend tests:

```powershell
cd blockchain
npm run test:contract
cd ..
.venv/Scripts/python.exe -B -m unittest backend.core.blockchain.tests.test_backend -v
```

The demo deploys a fresh registry and resets its local index on each run. A
Hardhat node restart also clears the local chain, so rerun the demo to create
new receipts and proofs. The local files hold public addresses, hashes,
receipts, and off-chain records; they do not hold private keys.

## Proofs and IDs

`anchor_delegation`, `anchor_revocation`, and `anchor_action_hash` preserve their
Module 1 input signatures. Each blockchain record ID is `kind:<SHA-256 of the
canonical full record>`. The Solidity `bytes32` ID is a second SHA-256 over the
kind byte and content hash. Domain separation allows a decommission entry to
be committed once as a revocation and once as an action-log hash.

`get_proof` accepts either the original Module 1 `record_id` or the derived
blockchain record ID. `verify_proof(record, proof)` reads the transaction
receipt, block, emitted event, and contract commitment from the RPC endpoint
in the proof; it does not read the local index or Module 1 objects. The
RPC endpoint and chain must be trusted separately. This Hardhat network is a
development chain, not a public consensus network.

Credentials commit immutable issuance content. `status_at_issuance` is part of
that content hash; `current_status` is an off-chain mirror of the contract's
`active` flag and changes to `REVOKED` when Agent_C is decommissioned.
The contract's status is authoritative.
