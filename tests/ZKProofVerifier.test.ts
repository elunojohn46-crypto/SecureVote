import { describe, it, expect, beforeEach } from "vitest";
import { stringUtf8CV, uintCV, principalCV, bufferCV } from "@stacks/transactions";

const ERR_INVALID_PROOF = 1000;
const ERR_NOT_ELIGIBLE = 1001;
const ERR_ELECTION_ENDED = 1002;
const ERR_ALREADY_VERIFIED = 1003;
const ERR_INVALID_PUBLIC_INPUT = 1004;
const ERR_BATCH_SIZE_EXCEEDED = 1005;
const ERR_AGGREGATION_FAILED = 1006;
const ERR_PROOF_EXPIRED = 1007;
const ERR_VERIFIER_NOT_SET = 1008;
const ERR_INVALID_COMMITMENT = 1009;
const ERR_VOTER_ALREADY_VOTED = 1010;
const ERR_ELECTION_NOT_FOUND = 1011;
const ERR_CANDIDATE_INVALID = 1012;

interface Proof {
  publicInputs: bigint;
  proofBytes: Uint8Array;
}

interface ProofEntry {
  voter: string;
  electionId: bigint;
  proof: Proof;
  commitment: Uint8Array;
}

interface VerifiedProof {
  verified: boolean;
  timestamp: number;
  candidateId: number;
}

interface ElectionTally {
  candidate: number;
  votes: number;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class ZKProofVerifierMock {
  state: {
    currentElectionId: number;
    maxBatchSize: number;
    verifierContract: string | null;
    proofExpiryBlocks: number;
    verifiedProofs: Map<string, VerifiedProof>;
    electionProofs: Map<string, number>;
    voterVotes: Map<string, boolean>;
  } = {
    currentElectionId: 0,
    maxBatchSize: 100,
    verifierContract: null,
    proofExpiryBlocks: 1000,
    verifiedProofs: new Map(),
    electionProofs: new Map(),
    voterVotes: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      currentElectionId: 0,
      maxBatchSize: 100,
      verifierContract: null,
      proofExpiryBlocks: 1000,
      verifiedProofs: new Map(),
      electionProofs: new Map(),
      voterVotes: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
  }

  isElectionActive(electionId: number): boolean {
    return this.blockHeight < 100;
  }

  isVoterEligible(voter: string, electionId: number): boolean {
    return true;
  }

  setVerifierContract(contractPrincipal: string): Result<boolean> {
    if (this.state.verifierContract !== null) return { ok: false, value: false };
    this.state.verifierContract = contractPrincipal;
    return { ok: true, value: true };
  }

  setMaxBatchSize(newMax: number): Result<boolean> {
    if (newMax <= 0) return { ok: false, value: false };
    this.state.maxBatchSize = newMax;
    return { ok: true, value: true };
  }

  setProofExpiry(blocks: number): Result<boolean> {
    if (blocks <= 0) return { ok: false, value: false };
    this.state.proofExpiryBlocks = blocks;
    return { ok: true, value: true };
  }

  hashProof(proof: Proof): Uint8Array {
    const combined = new Uint8Array([...Array.from(proof.proofBytes), ...new Uint8Array(new BigUint64Array([proof.publicInputs]).buffer)]);
    const hash = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      hash[i] = combined[i % combined.length];
    }
    return hash;
  }

  mockVerifyZKP(proof: Proof, expectedCandidate: number): Result<boolean> {
    const proofHash = this.hashProof(proof);
    const hashVal = proofHash.reduce((a, b) => a + b, 0) % 100;
    return { ok: hashVal === expectedCandidate, value: hashVal === expectedCandidate ? true : false };
  }

  verifyVoteProof(voter: string, electionId: number, proof: Proof, commitment: Uint8Array): Result<{ status: boolean; height: number; candidate: number }> {
    if (!this.state.verifierContract) return { ok: false, value: ERR_VERIFIER_NOT_SET };
    if (!this.isElectionActive(electionId)) return { ok: false, value: ERR_ELECTION_ENDED };
    if (!this.isVoterEligible(voter, electionId)) return { ok: false, value: ERR_NOT_ELIGIBLE };
    if (this.state.voterVotes.has(`${voter}-${electionId}`)) return { ok: false, value: ERR_VOTER_ALREADY_VOTED };
    if (proof.publicInputs < 1n || proof.publicInputs > 10n) return { ok: false, value: ERR_INVALID_PUBLIC_INPUT };
    if (commitment.length !== 32) return { ok: false, value: ERR_INVALID_COMMITMENT };
    const key = `${voter}-${Array.from(commitment)}-${electionId}`;
    if (this.state.verifiedProofs.has(key)) return { ok: false, value: ERR_ALREADY_VERIFIED };
    const verifyResult = this.mockVerifyZKP(proof, Number(proof.publicInputs));
    if (!verifyResult.ok) return { ok: false, value: ERR_INVALID_PROOF };
    const candidateId = Number(proof.publicInputs);
    this.state.verifiedProofs.set(key, { verified: true, timestamp: this.blockHeight, candidateId });
    this.state.voterVotes.set(`${voter}-${electionId}`, true);
    const proofKey = `${electionId}-${candidateId}`;
    this.state.electionProofs.set(proofKey, (this.state.electionProofs.get(proofKey) || 0) + 1);
    return { ok: true, value: { status: true, height: this.blockHeight, candidate: candidateId } };
  }

  batchVerifyProofs(proofs: ProofEntry[]): Result<number> {
    if (proofs.length > this.state.maxBatchSize) return { ok: false, value: ERR_BATCH_SIZE_EXCEEDED };
    let successCount = 0;
    for (const entry of proofs) {
      const result = this.verifyVoteProof(entry.voter, Number(entry.electionId), entry.proof, entry.commitment);
      if (result.ok) successCount++;
      else return result;
    }
    return { ok: true, value: successCount };
  }

  getVerifiedProof(voter: string, commitment: Uint8Array, electionId: number): VerifiedProof | null {
    const key = `${voter}-${Array.from(commitment)}-${electionId}`;
    return this.state.verifiedProofs.get(key) || null;
  }

  getElectionTally(electionId: number): ElectionTally[] {
    return [
      { candidate: 1, votes: this.state.electionProofs.get(`${electionId}-1`) || 0 },
      { candidate: 2, votes: this.state.electionProofs.get(`${electionId}-2`) || 0 },
      { candidate: 3, votes: this.state.electionProofs.get(`${electionId}-3`) || 0 },
    ];
  }

  resetElectionProofs(electionId: number): Result<boolean> {
    if (this.caller !== this.state.verifierContract) return { ok: false, value: false };
    this.state.voterVotes.delete(`${this.caller}-${electionId}`);
    this.state.electionProofs.delete(`${electionId}-1`);
    this.state.electionProofs.delete(`${electionId}-2`);
    this.state.electionProofs.delete(`${electionId}-3`);
    return { ok: true, value: true };
  }

  hasVoterVoted(voter: string, electionId: number): boolean {
    return this.state.voterVotes.get(`${voter}-${electionId}`) || false;
  }

  getTotalVerifiedForElection(electionId: number): number {
    return Array.from(this.state.verifiedProofs.values()).filter(p => p.timestamp > electionId).length;
  }
}

describe("ZKProofVerifier", () => {
  let contract: ZKProofVerifierMock;

  beforeEach(() => {
    contract = new ZKProofVerifierMock();
    contract.reset();
  });

  it("sets verifier contract successfully", () => {
    const result = contract.setVerifierContract("ST2TEST");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.verifierContract).toBe("ST2TEST");
  });

  it("rejects setting verifier contract twice", () => {
    contract.setVerifierContract("ST2TEST");
    const result = contract.setVerifierContract("ST3TEST");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("sets max batch size successfully", () => {
    const result = contract.setMaxBatchSize(50);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.maxBatchSize).toBe(50);
  });

  it("rejects invalid max batch size", () => {
    const result = contract.setMaxBatchSize(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("sets proof expiry successfully", () => {
    const result = contract.setProofExpiry(500);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.proofExpiryBlocks).toBe(500);
  });

  it("rejects invalid proof expiry", () => {
    const result = contract.setProofExpiry(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects verification without verifier contract", () => {
    const proof: Proof = { publicInputs: 1n, proofBytes: new Uint8Array(32) };
    const commitment = new Uint8Array(32);
    const result = contract.verifyVoteProof("ST1VOTER", 1, proof, commitment);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_VERIFIER_NOT_SET);
  });

  it("rejects verification for ended election", () => {
    contract.setVerifierContract("ST2TEST");
    contract.blockHeight = 101;
    const proof: Proof = { publicInputs: 1n, proofBytes: new Uint8Array(32) };
    const commitment = new Uint8Array(32);
    const result = contract.verifyVoteProof("ST1VOTER", 1, proof, commitment);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ELECTION_ENDED);
  });

  it("rejects verification for ineligible voter", () => {
    contract.setVerifierContract("ST2TEST");
    contract.isVoterEligible = () => false;
    const proof: Proof = { publicInputs: 1n, proofBytes: new Uint8Array(32) };
    const commitment = new Uint8Array(32);
    const result = contract.verifyVoteProof("ST1VOTER", 1, proof, commitment);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_ELIGIBLE);
  });

  it("rejects verification if voter already voted", () => {
    contract.setVerifierContract("ST2TEST");
    contract.state.voterVotes.set("ST1VOTER-1", true);
    const proof: Proof = { publicInputs: 1n, proofBytes: new Uint8Array(32) };
    const commitment = new Uint8Array(32);
    const result = contract.verifyVoteProof("ST1VOTER", 1, proof, commitment);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_VOTER_ALREADY_VOTED);
  });

  it("rejects invalid public input", () => {
    contract.setVerifierContract("ST2TEST");
    const proof: Proof = { publicInputs: 0n, proofBytes: new Uint8Array(32) };
    const commitment = new Uint8Array(32);
    const result = contract.verifyVoteProof("ST1VOTER", 1, proof, commitment);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PUBLIC_INPUT);
  });

  it("rejects invalid commitment length", () => {
    contract.setVerifierContract("ST2TEST");
    const proof: Proof = { publicInputs: 1n, proofBytes: new Uint8Array(32) };
    const commitment = new Uint8Array(31);
    const result = contract.verifyVoteProof("ST1VOTER", 1, proof, commitment);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_COMMITMENT);
  });

  it("rejects invalid proof", () => {
    contract.setVerifierContract("ST2TEST");
    const proof: Proof = { publicInputs: 1n, proofBytes: new Uint8Array(32).fill(0) };
    const commitment = new Uint8Array(32);
    contract.mockVerifyZKP = () => ({ ok: false, value: false });
    const result = contract.verifyVoteProof("ST1VOTER", 1, proof, commitment);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PROOF);
  });

  it("rejects batch verification exceeding max size", () => {
    contract.setVerifierContract("ST2TEST");
    const proofs: ProofEntry[] = new Array(101).fill(null).map((_, i) => ({
      voter: `ST${i}VOTER`,
      electionId: 1n,
      proof: { publicInputs: 1n, proofBytes: new Uint8Array(32) },
      commitment: new Uint8Array(32),
    }));
    const result = contract.batchVerifyProofs(proofs);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_BATCH_SIZE_EXCEEDED);
  });

  it("resets election proofs successfully", () => {
    contract.setVerifierContract("ST2TEST");
    contract.caller = "ST2TEST";
    contract.verifyVoteProof("ST1VOTER", 1, { publicInputs: 1n, proofBytes: new Uint8Array(32) }, new Uint8Array(32));
    const result = contract.resetElectionProofs(1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.hasVoterVoted("ST1VOTER", 1)).toBe(false);
  });

  it("rejects reset by non-verifier", () => {
    contract.setVerifierContract("ST2TEST");
    contract.caller = "ST3FAKE";
    const result = contract.resetElectionProofs(1);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });
});