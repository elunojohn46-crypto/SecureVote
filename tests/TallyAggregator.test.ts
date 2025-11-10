import { describe, it, expect, beforeEach } from "vitest";
import { uintCV, listCV, bufferCV, principalCV } from "@stacks/transactions";

const ERR_TALLY_NOT_AUTHORIZED = 2000;
const ERR_ELECTION_NOT_ACTIVE = 2001;
const ERR_INVALID_CANDIDATE = 2002;
const ERR_TALLY_ALREADY_PUBLISHED = 2003;
const ERR_INSUFFICIENT_PROOFS = 2004;
const ERR_HOMOMORPHIC_FAILURE = 2005;
const ERR_AGGREGATE_OVERFLOW = 2006;
const ERR_TALLY_PERIOD_EXPIRED = 2007;
const ERR_VERIFICATION_FAILED = 2008;
const ERR_CANDIDATE_LIST_EMPTY = 2009;
const ERR_TALLY_RESET_NOT_ALLOWED = 2010;
const ERR_INVALID_TALLY_INPUT = 2011;

interface ElectionTally {
  candidates: number[];
  encryptedTallies: Uint8Array[];
  published: boolean;
  timestamp: number;
}

interface ProofAggregate {
  count: number;
  hashSum: Uint8Array;
  verified: boolean;
}

interface TallyLog {
  action: string;
  details: Uint8Array;
  timestamp: number;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class TallyAggregatorMock {
  state: {
    currentElectionId: number;
    tallyAdmin: string | null;
    maxCandidates: number;
    tallyPrecision: number;
    electionTallies: Map<string, ElectionTally>;
    proofAggregates: Map<string, ProofAggregate>;
    tallyLogs: Map<string, TallyLog>;
  } = {
    currentElectionId: 0,
    tallyAdmin: null,
    maxCandidates: 10,
    tallyPrecision: 1000000,
    electionTallies: new Map(),
    proofAggregates: new Map(),
    tallyLogs: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      currentElectionId: 0,
      tallyAdmin: null,
      maxCandidates: 10,
      tallyPrecision: 1000000,
      electionTallies: new Map(),
      proofAggregates: new Map(),
      tallyLogs: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
  }

  isElectionActive(electionId: number): boolean {
    return this.blockHeight < 100;
  }

  verifyAggregate(electionId: number, candidateId: number): boolean {
    return true;
  }

  checkTallyAdmin(caller: string): boolean {
    return caller === this.state.tallyAdmin;
  }

  setTallyAdmin(admin: string): Result<boolean> {
    if (this.state.tallyAdmin !== null) return { ok: false, value: false };
    this.state.tallyAdmin = admin;
    return { ok: true, value: true };
  }

  setMaxCandidates(newMax: number): Result<boolean> {
    if (!this.checkTallyAdmin(this.caller)) return { ok: false, value: false };
    if (newMax <= 0) return { ok: false, value: ERR_INVALID_CANDIDATE };
    this.state.maxCandidates = newMax;
    return { ok: true, value: true };
  }

  setTallyPrecision(precision: number): Result<boolean> {
    if (!this.checkTallyAdmin(this.caller)) return { ok: false, value: false };
    if (precision <= 0) return { ok: false, value: ERR_INVALID_TALLY_INPUT };
    this.state.tallyPrecision = precision;
    return { ok: true, value: true };
  }

  hashAggregate(
    candidateId: number,
    count: number,
    prevHash: Uint8Array
  ): Uint8Array {
    const combined = new Uint8Array([
      ...new Uint8Array(new BigInt64Array([BigInt(count)])),
      ...new Uint8Array(new BigInt64Array([BigInt(candidateId)])),
      ...prevHash,
    ]);
    const hash = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      hash[i] = combined[i % combined.length];
    }
    return hash;
  }

  homomorphicAdd(enc1: Uint8Array, enc2: Uint8Array): Result<Uint8Array> {
    if (enc1.length !== 32 || enc2.length !== 32)
      return { ok: false, value: ERR_HOMOMORPHIC_FAILURE };
    const xorResult = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      xorResult[i] = enc1[i] ^ enc2[i];
    }
    const hash = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      hash[i] = xorResult[i % 32];
    }
    return { ok: true, value: hash };
  }

  validateCandidateList(candidates: number[]): boolean {
    const count = candidates.length;
    return count > 0 && count <= this.state.maxCandidates;
  }

  initializeElectionTally(
    electionId: number,
    candidates: number[]
  ): Result<boolean> {
    if (!this.checkTallyAdmin(this.caller))
      return { ok: false, value: ERR_TALLY_NOT_AUTHORIZED };
    if (!this.isElectionActive(electionId))
      return { ok: false, value: ERR_ELECTION_NOT_ACTIVE };
    if (!this.validateCandidateList(candidates))
      return { ok: false, value: ERR_CANDIDATE_LIST_EMPTY };
    const key = `${electionId}`;
    if (
      this.state.electionTallies.has(key) &&
      this.state.electionTallies.get(key)!.published
    )
      return { ok: false, value: ERR_TALLY_ALREADY_PUBLISHED };
    const initialEnc = new Uint8Array(32).fill(0);
    const encryptedTallies = candidates.map(() => initialEnc);
    this.state.electionTallies.set(key, {
      candidates,
      encryptedTallies,
      published: false,
      timestamp: this.blockHeight,
    });
    this.tallyLogs.set(`${electionId}-0`, {
      action: "init",
      details: new Uint8Array(new BigInt64Array([BigInt(electionId)])),
      timestamp: this.blockHeight,
    });
    return { ok: true, value: true };
  }

  aggregateCandidateProofs(
    electionId: number,
    candidateId: number,
    proofCount: number
  ): Result<{ updatedCount: number; hash: Uint8Array }> {
    if (!this.checkTallyAdmin(this.caller))
      return { ok: false, value: ERR_TALLY_NOT_AUTHORIZED };
    if (!this.isElectionActive(electionId))
      return { ok: false, value: ERR_ELECTION_NOT_ACTIVE };
    if (proofCount < this.state.tallyPrecision)
      return { ok: false, value: ERR_INSUFFICIENT_PROOFS };
    if (!this.verifyAggregate(electionId, candidateId))
      return { ok: false, value: ERR_VERIFICATION_FAILED };
    const key = `${electionId}-${candidateId}`;
    const prevAgg = this.state.proofAggregates.get(key) || {
      count: 0,
      hashSum: new Uint8Array(32).fill(0),
      verified: false,
    };
    const newCount = prevAgg.count + proofCount;
    if (newCount > 1000000) return { ok: false, value: ERR_AGGREGATE_OVERFLOW };
    const newHash = this.hashAggregate(candidateId, newCount, prevAgg.hashSum);
    this.state.proofAggregates.set(key, {
      count: newCount,
      hashSum: newHash,
      verified: true,
    });
    this.tallyLogs.set(`${electionId}-1`, {
      action: "agg",
      details: new Uint8Array(new BigInt64Array([BigInt(candidateId)])),
      timestamp: this.blockHeight,
    });
    return { ok: true, value: { updatedCount: newCount, hash: newHash } };
  }

  publishEncryptedTally(
    electionId: number
  ): Result<{ published: boolean; finalEncrypted: Uint8Array }> {
    if (!this.checkTallyAdmin(this.caller))
      return { ok: false, value: ERR_TALLY_NOT_AUTHORIZED };
    const key = `${electionId}`;
    const tallyData = this.state.electionTallies.get(key);
    if (!tallyData) return { ok: false, value: ERR_ELECTION_NOT_ACTIVE };
    let currentEnc = new Uint8Array(32).fill(0);
    for (const candId of tallyData.candidates) {
      const aggKey = `${electionId}-${candId}`;
      const agg = this.state.proofAggregates.get(aggKey) || {
        count: 0,
        hashSum: new Uint8Array(32).fill(0),
        verified: false,
      };
      if (agg.count === 0) return { ok: false, value: ERR_INSUFFICIENT_PROOFS };
      const addResult = this.homomorphicAdd(currentEnc, agg.hashSum);
      if (!addResult.ok) return addResult;
      currentEnc = addResult.value;
    }
    const finalEncResult = this.homomorphicAdd(
      tallyData.encryptedTallies[0],
      currentEnc
    );
    if (!finalEncResult.ok) return finalEncResult;
    const finalEnc = finalEncResult.value;
    this.state.electionTallies.set(key, {
      ...tallyData,
      encryptedTallies: [finalEnc],
      published: true,
      timestamp: this.blockHeight,
    });
    this.tallyLogs.set(`${electionId}-2`, {
      action: "publish",
      details: finalEnc,
      timestamp: this.blockHeight,
    });
    return { ok: true, value: { published: true, finalEncrypted: finalEnc } };
  }

  getElectionTally(electionId: number): ElectionTally | null {
    return this.state.electionTallies.get(`${electionId}`) || null;
  }

  getProofAggregate(
    electionId: number,
    candidateId: number
  ): ProofAggregate | null {
    return (
      this.state.proofAggregates.get(`${electionId}-${candidateId}`) || null
    );
  }

  getTallyLogs(electionId: number): TallyLog[] {
    return [
      this.tallyLogs.get(`${electionId}-0`) || {
        action: "",
        details: new Uint8Array(0),
        timestamp: 0,
      },
      this.tallyLogs.get(`${electionId}-1`) || {
        action: "",
        details: new Uint8Array(0),
        timestamp: 0,
      },
      this.tallyLogs.get(`${electionId}-2`) || {
        action: "",
        details: new Uint8Array(0),
        timestamp: 0,
      },
    ];
  }

  resetElectionTally(electionId: number): Result<boolean> {
    if (!this.checkTallyAdmin(this.caller))
      return { ok: false, value: ERR_TALLY_NOT_AUTHORIZED };
    const key = `${electionId}`;
    const tally = this.state.electionTallies.get(key);
    if (tally && tally.published)
      return { ok: false, value: ERR_TALLY_ALREADY_PUBLISHED };
    this.state.electionTallies.delete(key);
    [1, 2, 3].forEach((c) =>
      this.state.proofAggregates.delete(`${electionId}-${c}`)
    );
    [0, 1, 2].forEach((l) => this.tallyLogs.delete(`${electionId}-${l}`));
    return { ok: true, value: true };
  }

  validateTallyIntegrity(
    electionId: number
  ): Result<{ integrity: boolean; totalVotes: number }> {
    if (!this.checkTallyAdmin(this.caller))
      return { ok: false, value: ERR_TALLY_NOT_AUTHORIZED };
    const tally = this.state.electionTallies.get(`${electionId}`);
    if (!tally) return { ok: false, value: ERR_ELECTION_NOT_ACTIVE };
    let totalProofs = 0;
    for (const cand of tally.candidates) {
      const agg = this.state.proofAggregates.get(`${electionId}-${cand}`) || {
        count: 0,
      };
      totalProofs += agg.count;
    }
    if (totalProofs >= this.state.tallyPrecision) {
      return { ok: true, value: { integrity: true, totalVotes: totalProofs } };
    }
    return { ok: false, value: ERR_INSUFFICIENT_PROOFS };
  }
}

describe("TallyAggregator", () => {
  let contract: TallyAggregatorMock;

  beforeEach(() => {
    contract = new TallyAggregatorMock();
    contract.reset();
  });

  it("sets tally admin successfully", () => {
    const result = contract.setTallyAdmin("ST2ADMIN");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.tallyAdmin).toBe("ST2ADMIN");
  });

  it("rejects setting tally admin twice", () => {
    contract.setTallyAdmin("ST2ADMIN");
    const result = contract.setTallyAdmin("ST3ADMIN");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("sets max candidates successfully", () => {
    contract.setTallyAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.setMaxCandidates(5);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.maxCandidates).toBe(5);
  });

  it("rejects invalid max candidates", () => {
    contract.setTallyAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.setMaxCandidates(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_CANDIDATE);
  });

  it("sets tally precision successfully", () => {
    contract.setTallyAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.setTallyPrecision(500000);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.tallyPrecision).toBe(500000);
  });

  it("rejects invalid tally precision", () => {
    contract.setTallyAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.setTallyPrecision(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_TALLY_INPUT);
  });

  it("rejects initialization without admin", () => {
    const candidates = [1, 2, 3];
    const result = contract.initializeElectionTally(1, candidates);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_TALLY_NOT_AUTHORIZED);
  });

  it("rejects initialization for inactive election", () => {
    contract.setTallyAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    contract.blockHeight = 101;
    const candidates = [1, 2, 3];
    const result = contract.initializeElectionTally(1, candidates);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ELECTION_NOT_ACTIVE);
  });

  it("rejects empty candidate list", () => {
    contract.setTallyAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const candidates: number[] = [];
    const result = contract.initializeElectionTally(1, candidates);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_CANDIDATE_LIST_EMPTY);
  });

  it("rejects aggregate without admin", () => {
    const result = contract.aggregateCandidateProofs(1, 1, 1000001);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_TALLY_NOT_AUTHORIZED);
  });

  it("rejects aggregate for inactive election", () => {
    contract.setTallyAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    contract.blockHeight = 101;
    const result = contract.aggregateCandidateProofs(1, 1, 1000001);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ELECTION_NOT_ACTIVE);
  });

  it("rejects insufficient proofs aggregate", () => {
    contract.setTallyAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.aggregateCandidateProofs(1, 1, 999999);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INSUFFICIENT_PROOFS);
  });

  it("rejects aggregate verification failure", () => {
    contract.setTallyAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    contract.verifyAggregate = () => false;
    const result = contract.aggregateCandidateProofs(1, 1, 1000001);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_VERIFICATION_FAILED);
  });

  it("rejects publish without admin", () => {
    const result = contract.publishEncryptedTally(1);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_TALLY_NOT_AUTHORIZED);
  });

  it("rejects integrity validation without admin", () => {
    const result = contract.validateTallyIntegrity(1);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_TALLY_NOT_AUTHORIZED);
  });
});
