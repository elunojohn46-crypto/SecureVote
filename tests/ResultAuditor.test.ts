import { describe, it, expect, beforeEach } from "vitest";
import {
  uintCV,
  listCV,
  bufferCV,
  principalCV,
  stringAsciiCV,
} from "@stacks/transactions";

const ERR_AUDIT_NOT_AUTHORIZED = 3000;
const ERR_ELECTION_NOT_FOUND = 3001;
const ERR_RESULTS_NOT_PUBLISHED = 3002;
const ERR_INVALID_AUDIT_REQUEST = 3003;
const ERR_PROOF_REPLAY_FAILED = 3004;
const ERR_ANOMALY_DETECTED = 3005;
const ERR_AUDIT_LOG_FULL = 3006;
const ERR_VERIFICATION_MISMATCH = 3007;
const ERR_DISPUTE_NOT_ELIGIBLE = 3008;
const ERR_DISPUTE_ALREADY_RESOLVED = 3009;
const ERR_INVALID_TIMESTAMP = 3010;
const ERR_AUDIT_TIMEOUT = 3011;

interface ElectionAudit {
  audited: boolean;
  disputes: number;
  finalResults: bigint[];
  timestamp: number;
}

interface AuditLog {
  auditType: string;
  details: Uint8Array;
  resolved: boolean;
  timestamp: number;
}

interface DisputeRecord {
  disputer: string;
  reason: string;
  evidence: Uint8Array;
  status: string;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class ResultAuditorMock {
  state: {
    auditAdmin: string | null;
    maxAuditLogs: number;
    auditTimeoutBlocks: number;
    electionAudits: Map<string, ElectionAudit>;
    auditLogs: Map<string, AuditLog>;
    disputeRecords: Map<string, DisputeRecord>;
  } = {
    auditAdmin: null,
    maxAuditLogs: 50,
    auditTimeoutBlocks: 100,
    electionAudits: new Map(),
    auditLogs: new Map(),
    disputeRecords: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      auditAdmin: null,
      maxAuditLogs: 50,
      auditTimeoutBlocks: 100,
      electionAudits: new Map(),
      auditLogs: new Map(),
      disputeRecords: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
  }

  isResultsPublished(electionId: number): boolean {
    return true;
  }

  replayProofVerification(
    electionId: number,
    proofHash: Uint8Array
  ): AuditLog | null {
    return {
      auditType: "replayed",
      details: proofHash,
      resolved: true,
      timestamp: this.blockHeight,
    };
  }

  detectAnomaly(
    tallyCount: number,
    expectedRange: { min: number; max: number }
  ): boolean {
    return tallyCount < expectedRange.min || tallyCount > expectedRange.max;
  }

  validateTimestamp(ts: number): boolean {
    return ts <= this.blockHeight && this.blockHeight - ts >= 1;
  }

  getNextLogId(electionId: number): number {
    let id = 0;
    while (this.state.auditLogs.has(`${electionId}-${id}`)) id++;
    return id;
  }

  checkAuditAdmin(caller: string): boolean {
    return caller === this.state.auditAdmin;
  }

  setAuditAdmin(admin: string): Result<boolean> {
    if (this.state.auditAdmin !== null) return { ok: false, value: false };
    this.state.auditAdmin = admin;
    return { ok: true, value: true };
  }

  setMaxAuditLogs(newMax: number): Result<boolean> {
    if (!this.checkAuditAdmin(this.caller)) return { ok: false, value: false };
    if (newMax <= 0) return { ok: false, value: ERR_INVALID_AUDIT_REQUEST };
    this.state.maxAuditLogs = newMax;
    return { ok: true, value: true };
  }

  setAuditTimeout(blocks: number): Result<boolean> {
    if (!this.checkAuditAdmin(this.caller)) return { ok: false, value: false };
    if (blocks <= 0) return { ok: false, value: ERR_AUDIT_TIMEOUT };
    this.state.auditTimeoutBlocks = blocks;
    return { ok: true, value: true };
  }

  performAudit(
    electionId: number,
    proofHashes: Uint8Array[]
  ): Result<{ matchRate: number; audited: boolean }> {
    if (!this.checkAuditAdmin(this.caller))
      return { ok: false, value: ERR_AUDIT_NOT_AUTHORIZED };
    if (this.state.electionAudits.has(`${electionId}`))
      return { ok: false, value: ERR_ELECTION_NOT_FOUND };
    if (!this.isResultsPublished(electionId))
      return { ok: false, value: ERR_RESULTS_NOT_PUBLISHED };
    const hashCount = proofHashes.length;
    let replayedCount = 0;
    for (const hash of proofHashes) {
      if (this.replayProofVerification(electionId, hash)) replayedCount++;
    }
    const matchRate = (replayedCount * 100) / (hashCount || 1);
    if (matchRate < 95) return { ok: false, value: ERR_VERIFICATION_MISMATCH };
    this.state.electionAudits.set(`${electionId}`, {
      audited: true,
      disputes: 0,
      finalResults: [42n, 58n, 0n],
      timestamp: this.blockHeight,
    });
    this.logAuditAction(electionId, "full-audit", new Uint8Array(32).fill(0));
    return { ok: true, value: { matchRate, audited: true } };
  }

  raiseDispute(
    electionId: number,
    reason: string,
    evidence: Uint8Array
  ): Result<{ disputeId: number; status: string }> {
    if (!this.validateTimestamp(this.blockHeight))
      return { ok: false, value: ERR_INVALID_TIMESTAMP };
    const key = `${electionId}`;
    const auditData = this.state.electionAudits.get(key) || {
      audited: false,
      disputes: 0,
      finalResults: [],
      timestamp: 0,
    };
    const totalTally = auditData.finalResults.reduce(
      (a, b) => a + Number(b),
      0
    );
    if (this.detectAnomaly(totalTally, { min: 50, max: 150 }))
      return { ok: false, value: ERR_ANOMALY_DETECTED };
    const nextDispute = auditData.disputes + 1;
    this.state.disputeRecords.set(`${electionId}-${nextDispute}`, {
      disputer: this.caller,
      reason,
      evidence,
      status: "pending",
    });
    this.state.electionAudits.set(key, {
      ...auditData,
      disputes: nextDispute,
    });
    this.logAuditAction(electionId, "dispute", evidence);
    return { ok: true, value: { disputeId: nextDispute, status: "raised" } };
  }

  logAuditAction(
    electionId: number,
    auditType: string,
    details: Uint8Array
  ): Result<boolean> {
    const nextId = this.getNextLogId(electionId);
    const logCount = nextId + 1;
    if (logCount > this.state.maxAuditLogs)
      return { ok: false, value: ERR_AUDIT_LOG_FULL };
    this.state.auditLogs.set(`${electionId}-${nextId}`, {
      auditType,
      details,
      resolved: false,
      timestamp: this.blockHeight,
    });
    return { ok: true, value: true };
  }

  resolveDispute(
    electionId: number,
    disputeId: number,
    resolution: string
  ): Result<{ resolved: boolean; newStatus: string }> {
    if (!this.checkAuditAdmin(this.caller))
      return { ok: false, value: ERR_AUDIT_NOT_AUTHORIZED };
    if (resolution !== "accepted")
      return { ok: false, value: ERR_INVALID_AUDIT_REQUEST };
    const key = `${electionId}-${disputeId}`;
    const dispute = this.state.disputeRecords.get(key);
    if (!dispute) return { ok: false, value: ERR_DISPUTE_NOT_ELIGIBLE };
    if (dispute.status !== "pending")
      return { ok: false, value: ERR_DISPUTE_ALREADY_RESOLVED };
    this.state.disputeRecords.set(key, { ...dispute, status: resolution });
    this.logAuditAction(
      electionId,
      "resolve",
      new Uint8Array(new BigInt64Array([BigInt(disputeId)]))
    );
    return { ok: true, value: { resolved: true, newStatus: resolution } };
  }

  getElectionAudit(electionId: number): ElectionAudit | null {
    return this.state.electionAudits.get(`${electionId}`) || null;
  }

  getDisputeRecord(
    electionId: number,
    disputeId: number
  ): DisputeRecord | null {
    return this.state.disputeRecords.get(`${electionId}-${disputeId}`) || null;
  }

  getAuditLogs(electionId: number): AuditLog[] {
    const logs: AuditLog[] = [];
    for (let i = 0; i < this.state.maxAuditLogs; i++) {
      const log = this.state.auditLogs.get(`${electionId}-${i}`);
      if (log) logs.push(log);
    }
    return logs;
  }

  releaseFinalResults(
    electionId: number,
    results: bigint[]
  ): Result<{ released: boolean; results: bigint[] }> {
    if (!this.checkAuditAdmin(this.caller))
      return { ok: false, value: ERR_AUDIT_NOT_AUTHORIZED };
    if (!this.isResultsPublished(electionId))
      return { ok: false, value: ERR_RESULTS_NOT_PUBLISHED };
    const currentAudit = this.state.electionAudits.get(`${electionId}`);
    if (!currentAudit) return { ok: false, value: ERR_ELECTION_NOT_FOUND };
    this.state.electionAudits.set(`${electionId}`, {
      ...currentAudit,
      finalResults: results,
      timestamp: this.blockHeight,
    });
    this.logAuditAction(electionId, "release", new Uint8Array(32).fill(0));
    return { ok: true, value: { released: true, results } };
  }

  checkAuditEligibility(voter: string, electionId: number): boolean {
    const audit = this.state.electionAudits.get(`${electionId}`) || {
      timestamp: 0,
    };
    return this.blockHeight < audit.timestamp + this.state.auditTimeoutBlocks;
  }
}

describe("ResultAuditor", () => {
  let contract: ResultAuditorMock;

  beforeEach(() => {
    contract = new ResultAuditorMock();
    contract.reset();
  });

  it("sets audit admin successfully", () => {
    const result = contract.setAuditAdmin("ST2ADMIN");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.auditAdmin).toBe("ST2ADMIN");
  });

  it("rejects setting audit admin twice", () => {
    contract.setAuditAdmin("ST2ADMIN");
    const result = contract.setAuditAdmin("ST3ADMIN");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("sets max audit logs successfully", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.setMaxAuditLogs(25);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.maxAuditLogs).toBe(25);
  });

  it("rejects invalid max audit logs", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.setMaxAuditLogs(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_AUDIT_REQUEST);
  });

  it("sets audit timeout successfully", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.setAuditTimeout(50);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.auditTimeoutBlocks).toBe(50);
  });

  it("rejects invalid audit timeout", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.setAuditTimeout(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_AUDIT_TIMEOUT);
  });

  it("rejects audit without admin", () => {
    const proofHashes = [new Uint8Array(32)];
    const result = contract.performAudit(1, proofHashes);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_AUDIT_NOT_AUTHORIZED);
  });

  it("rejects audit with low match rate", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    contract.replayProofVerification = () => null;
    const proofHashes = [new Uint8Array(32), new Uint8Array(32)];
    const result = contract.performAudit(1, proofHashes);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_VERIFICATION_MISMATCH);
  });

  it("rejects dispute with invalid timestamp", () => {
    contract.blockHeight = 0;
    const result = contract.raiseDispute(1, "Fraud", new Uint8Array(32));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_TIMESTAMP);
  });

  it("rejects resolve without admin", () => {
    const result = contract.resolveDispute(1, 1, "accepted");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_AUDIT_NOT_AUTHORIZED);
  });

  it("rejects invalid resolution", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.resolveDispute(1, 1, "rejected");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_AUDIT_REQUEST);
  });

  it("rejects resolve for non-existent dispute", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const result = contract.resolveDispute(1, 1, "accepted");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_DISPUTE_NOT_ELIGIBLE);
  });

  it("rejects resolve for already resolved dispute", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    contract.state.disputeRecords.set("1-1", {
      disputer: "ST1",
      reason: "Fraud",
      evidence: new Uint8Array(32),
      status: "accepted",
    });
    const result = contract.resolveDispute(1, 1, "accepted");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_DISPUTE_ALREADY_RESOLVED);
  });

  it("gets election audit correctly", () => {
    contract.state.electionAudits.set("1", {
      audited: true,
      disputes: 1,
      finalResults: [42n],
      timestamp: 10,
    });
    const audit = contract.getElectionAudit(1);
    expect(audit).not.toBeNull();
    expect(audit!.audited).toBe(true);
  });

  it("gets dispute record correctly", () => {
    contract.state.disputeRecords.set("1-1", {
      disputer: "ST1",
      reason: "Fraud",
      evidence: new Uint8Array(32),
      status: "pending",
    });
    const dispute = contract.getDisputeRecord(1, 1);
    expect(dispute).not.toBeNull();
    expect(dispute!.status).toBe("pending");
  });

  it("gets audit logs correctly", () => {
    contract.logAuditAction(1, "test", new Uint8Array(32));
    const logs = contract.getAuditLogs(1);
    expect(logs.length).toBeGreaterThan(0);
    expect(logs[0].auditType).toBe("test");
  });

  it("releases final results successfully", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    contract.state.electionAudits.set("1", {
      audited: true,
      disputes: 0,
      finalResults: [],
      timestamp: 0,
    });
    const results = [42n, 58n];
    const result = contract.releaseFinalResults(1, results);
    expect(result.ok).toBe(true);
    expect(result.value.results).toEqual(results);
    const audit = contract.getElectionAudit(1);
    expect(audit!.finalResults).toEqual(results);
  });

  it("rejects release without admin", () => {
    const results = [42n];
    const result = contract.releaseFinalResults(1, results);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_AUDIT_NOT_AUTHORIZED);
  });

  it("rejects release without published results", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    contract.isResultsPublished = () => false;
    const results = [42n];
    const result = contract.releaseFinalResults(1, results);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_RESULTS_NOT_PUBLISHED);
  });

  it("rejects release for non-existent election", () => {
    contract.setAuditAdmin("ST2ADMIN");
    contract.caller = "ST2ADMIN";
    const results = [42n];
    const result = contract.releaseFinalResults(1, results);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ELECTION_NOT_FOUND);
  });

  it("rejects audit eligibility timeout", () => {
    contract.state.electionAudits.set("1", {
      audited: true,
      disputes: 0,
      finalResults: [],
      timestamp: this.blockHeight - 150,
    });
    expect(contract.checkAuditEligibility("ST1VOTER", 1)).toBe(false);
  });
});
