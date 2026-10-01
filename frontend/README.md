# ChainGuard-AI frontend

Start the API and Hardhat node first. Then:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The app calls `http://127.0.0.1:8000` by default. Set `VITE_API_BASE_URL` before starting Vite to use another API address.

The Dashboard, Agents, Trust Graph, Live Governance, Threat Lab, ML Analytics, Revocation, and Evaluation pages use the API and saved evaluation report. Live Governance replays measured WebSocket stages at presentation speed; it does not delay backend processing. For a fresh Hardhat chain without the saved Module 6 contract, use the disposable server described in `backend/api/README.md` and set `VITE_API_BASE_URL=http://127.0.0.1:8001`.
