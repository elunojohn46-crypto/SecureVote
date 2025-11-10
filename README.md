# 🗳️ SecureVote: Privacy-Preserving Absentee Voting on Blockchain

Welcome to **SecureVote**, a decentralized absentee voting system built on the Stacks blockchain using Clarity smart contracts. This Web3 project tackles the real-world problem of insecure and non-transparent absentee voting processes, which often suffer from fraud, voter intimidation, and privacy breaches. By encrypting votes and leveraging zero-knowledge proofs (ZKPs), SecureVote ensures votes remain private until tallying, allowing verifiable results without revealing individual choices. Perfect for remote elections in DAOs, communities, or even municipal voting pilots.

## ✨ Features
🔒 **End-to-End Encryption**: Votes are encrypted client-side before submission, preventing any party from accessing plaintext votes.
🛡️ **Zero-Knowledge Proofs**: Prove vote validity and eligibility without disclosing the vote itself during tallying.
✅ **Voter Anonymity**: One-time-use tokens and commitments ensure unlinkability between voters and their votes.
📊 **Auditable Tallying**: Aggregated results are computed on-chain with ZK verification for tamper-proof outcomes.
🚫 **Fraud Prevention**: Duplicate voting blocked via unique commitments; eligibility checked against on-chain registry.
⏰ **Time-Bound Elections**: Votes lock during active periods and auto-tally post-deadline.
🔍 **Public Auditability**: Anyone can verify proofs and aggregates without compromising privacy.

## 🛠 Tech Stack
- **Blockchain**: Stacks (Bitcoin L2 for secure, final settlement)
- **Smart Contracts**: 8 Clarity contracts (detailed below)
- **ZKPs**: Integrated via off-chain libraries (e.g., zk-SNARKs) with on-chain verification
- **Frontend**: React + Hiro Wallet for user interactions
- **Encryption**: AES for initial encryption; commitments via SHA-256 hashes

## 📋 Smart Contracts (8 Total)
SecureVote deploys 8 interconnected Clarity smart contracts to handle the full voting lifecycle. Each is modular for easy auditing and upgrades.

1. **VoterRegistry**: Manages voter onboarding with KYC-light proofs (e.g., hash of ID). Functions: `register-voter`, `is-eligible?`, `revoke-voter`.
2. **ElectionManager**: Creates and configures elections (e.g., candidates, duration). Functions: `create-election`, `start-election`, `end-election`.
3. **BallotIssuer**: Generates unique, blinded ballot tokens for eligible voters. Functions: `issue-ballot`, `burn-ballot`.
4. **VoteEncrypter**: Handles vote encryption and commitment storage (hash of encrypted vote + nonce). Functions: `commit-vote`, `validate-commitment`.
5. **VoteSubmitter**: Submits encrypted votes tied to commitments; prevents duplicates. Functions: `submit-vote`, `check-submitted?`.
6. **ZKProofVerifier**: Verifies zero-knowledge proofs for vote validity (e.g., "this vote is for a valid candidate"). Functions: `verify-proof`, `aggregate-proofs`.
7. **TallyAggregator**: Computes encrypted tallies using homomorphic addition on commitments. Functions: `tally-votes`, `publish-aggregate`.
8. **ResultAuditor**: Releases final results post-tally and logs audit trails. Functions: `release-results`, `audit-proof`.

These contracts interact via cross-contract calls (e.g., `VoteSubmitter` queries `VoterRegistry` for eligibility).

## 🔄 How It Works

### **For Voters**
1. **Register**: Connect your Hiro Wallet, submit a hashed proof of eligibility (e.g., SHA-256 of your voter ID) to `VoterRegistry`.
2. **Get Ballot**: During election setup, `BallotIssuer` mints a one-time token to your address.
3. **Encrypt & Vote**: Client-side, encrypt your choice (e.g., "Candidate A") with a random nonce, generate a ZKP, and commit the hash via `VoteEncrypter`.
4. **Submit**: Call `VoteSubmitter` with your encrypted vote and proof. It's locked until tallying—your choice stays secret!
5. **Verify**: Post-election, check `ResultAuditor` for aggregated results without seeing individual votes.

### **For Election Admins**
1. **Setup Election**: Deploy via `ElectionManager` with params like candidates list, start/end times, and voter whitelist.
2. **Monitor**: Query `TallyAggregator` for real-time commitment counts (no peeking at votes).
3. **Tally & Release**: At deadline, trigger `ZKProofVerifier` to batch-validate proofs, then `TallyAggregator` computes sums. Finally, `ResultAuditor` publishes: e.g., "Candidate A: 42 votes".
4. **Audit**: Anyone calls `ResultAuditor` to replay proofs—full transparency without privacy loss.

Boom! Votes are cast privately, tallied verifiably, and fraud is a thing of the past. No central authority needed.

## 🚀 Getting Started
1. Clone the repo: `git clone <your-repo>`
2. Install dependencies: `npm install`
3. Deploy contracts: Use Clarinet for local testing, then push to Stacks mainnet via Hiro.
4. Run frontend: `npm start` and connect to testnet for demos.

## 📝 Future Enhancements
- Multi-chain support (e.g., cross-post to Ethereum for broader audits).
- Mobile app for easier absentee voting.
- Integration with biometric ZKPs for stronger eligibility.

Join the revolution in secure democracy—fork, contribute, or vote with SecureVote today! 🇺🇸✨

License: MIT.