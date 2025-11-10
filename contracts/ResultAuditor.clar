(define-constant ERR_AUDIT_NOT_AUTHORIZED u3000)
(define-constant ERR_ELECTION_NOT_FOUND u3001)
(define-constant ERR_RESULTS_NOT_PUBLISHED u3002)
(define-constant ERR_INVALID_AUDIT_REQUEST u3003)
(define-constant ERR_PROOF_REPLAY_FAILED u3004)
(define-constant ERR_ANOMALY_DETECTED u3005)
(define-constant ERR_AUDIT_LOG_FULL u3006)
(define-constant ERR_VERIFICATION_MISMATCH u3007)
(define-constant ERR_DISPUTE_NOT_ELIGIBLE u3008)
(define-constant ERR_DISPUTE_ALREADY_RESOLVED u3009)
(define-constant ERR_INVALID_TIMESTAMP u3010)
(define-constant ERR_AUDIT_TIMEOUT u3011)
(define-data-var audit-admin (optional principal) none)
(define-data-var max-audit-logs uint u50)
(define-data-var audit-timeout-blocks uint u100)
(define-map election-audits
  {election-id: uint}
  {
    audited: bool,
    disputes: uint,
    final-results: (list 10 uint),
    timestamp: uint
  }
)
(define-map audit-logs
  {election-id: uint, log-id: uint}
  {audit-type: (string-ascii 20), details: (buff 64), resolved: bool, timestamp: uint}
)
(define-map dispute-records
  {election-id: uint, dispute-id: uint}
  {disputer: principal, reason: (string-ascii 50), evidence: (buff 32), status: (string-ascii 10)}
)
(define-private (check-audit-admin (caller principal))
  (is-eq caller (unwrap! (var-get audit-admin) (err ERR_AUDIT_NOT_AUTHORIZED)))
)
(define-private (is-results-published (election-id uint))
  (contract-call? .tally-aggregator get-election-tally election-id)
)
(define-private (replay-proof-verification (election-id uint) (proof-hash (buff 32)))
  (contract-call? .zk-proof-verifier get-verified-proof tx-sender proof-hash election-id)
)
(define-private (detect-anomaly (tally-count uint) (expected-range {min: uint, max: uint}))
  (or (< tally-count (get min expected-range)) (> tally-count (get max expected-range)))
)
(define-private (validate-timestamp (ts uint))
  (and (<= ts block-height) (>= (- block-height ts) u1) (ok true))
)
(define-private (get-next-log-id (election-id uint))
  (fold
    (lambda (id acc) (if (is-some (map-get? audit-logs {election-id: election-id, log-id: id})) (+ acc u1) acc))
    u0
    (range u0 (var-get max-audit-logs))
  )
)
(define-public (set-audit-admin (admin principal))
  (begin
    (asserts! (is-none (var-get audit-admin)) (err ERR_AUDIT_NOT_AUTHORIZED))
    (var-set audit-admin (some admin))
    (ok true)
  )
)
(define-public (set-max-audit-logs (new-max uint))
  (begin
    (try! (check-audit-admin tx-sender))
    (asserts! (> new-max u0) (err ERR_INVALID_AUDIT_REQUEST))
    (var-set max-audit-logs new-max)
    (ok true)
  )
)
(define-public (set-audit-timeout (blocks uint))
  (begin
    (try! (check-audit-admin tx-sender))
    (asserts! (> blocks u0) (err ERR_AUDIT_TIMEOUT))
    (var-set audit-timeout-blocks blocks)
    (ok true)
  )
)
(define-public (perform-audit (election-id uint) (proof-hashes (list 50 (buff 32))))
  (begin
    (try! (check-audit-admin tx-sender))
    (asserts! (some (contract-call? .election-manager get-election election-id)) (err ERR_ELECTION_NOT_FOUND))
    (asserts! (is-ok (is-results-published election-id)) (err ERR_RESULTS_NOT_PUBLISHED))
    (let (
      (hash-count (len proof-hashes))
      (replayed-count (fold
        (lambda (hash acc)
          (match (replay-proof-verification election-id hash)
            some-proof (+ acc u1)
            none acc
          )
        )
        u0
        proof-hashes
      ))
      (match-rate (/ (* replayed-count u100) (if (> hash-count u0) hash-count u1)))
    )
      (if (< match-rate u95)
        (err ERR_VERIFICATION_MISMATCH)
        (begin
          (map-set election-audits {election-id: election-id}
            {
              audited: true,
              disputes: u0,
              final-results: (list u42 u58 u0),
              timestamp: block-height
            }
          )
          (try! (log-audit-action election-id "full-audit" 0x00))
          (ok {match-rate: match-rate, audited: true})
        )
      )
    )
  )
)
(define-public (raise-dispute (election-id uint) (reason (string-ascii 50)) (evidence (buff 32)))
  (begin
    (asserts! (is-ok (validate-timestamp block-height)) (err ERR_INVALID_TIMESTAMP))
    (let (
      (next-dispute (default-to u0 (+ (default-to u0 (get disputes (map-get? election-audits {election-id: election-id}))) u1)))
      (audit-data (unwrap! (map-get? election-audits {election-id: election-id}) (err ERR_ELECTION_NOT_FOUND)))
    )
      (asserts! (not (detect-anomaly (fold + u0 (get final-results audit-data)) {min: u50, max: u150}))) (err ERR_ANOMALY_DETECTED))
      (map-set dispute-records {election-id: election-id, dispute-id: next-dispute}
        {disputer: tx-sender, reason: reason, evidence: evidence, status: "pending"}
      )
      (map-set election-audits {election-id: election-id}
        {audited: (get audited audit-data), disputes: next-dispute, final-results: (get final-results audit-data), timestamp: (get timestamp audit-data)}
      )
      (try! (log-audit-action election-id "dispute" evidence))
      (ok {dispute-id: next-dispute, status: "raised"})
    )
  )
  
(define-private (log-audit-action (election-id uint) (audit-type (string-ascii 20)) (details (buff 64)))
  (let (
    (next-id (get-next-log-id election-id))
    (log-count (+ next-id u1))
  )
    (asserts! (<= log-count (var-get max-audit-logs)) (err ERR_AUDIT_LOG_FULL))
    (map-set audit-logs {election-id: election-id, log-id: next-id}
      {audit-type: audit-type, details: details, resolved: false, timestamp: block-height}
    )
    (ok true)
  )
)
(define-public (resolve-dispute (election-id uint) (dispute-id uint) (resolution (string-ascii 10)))
  (begin
    (try! (check-audit-admin tx-sender))
    (asserts! (is-eq resolution "accepted") (err ERR_INVALID_AUDIT_REQUEST))
    (let ((dispute (unwrap! (map-get? dispute-records {election-id: election-id, dispute-id: dispute-id}) (err ERR_DISPUTE_NOT_ELIGIBLE))))
      (asserts! (is-eq (get status dispute) "pending") (err ERR_DISPUTE_ALREADY_RESOLVED))
      (map-set dispute-records {election-id: election-id, dispute-id: dispute-id}
        {disputer: (get disputer dispute), reason: (get reason dispute), evidence: (get evidence dispute), status: resolution}
      )
      (try! (log-audit-action election-id "resolve" (uint-to-buff dispute-id)))
      (ok {resolved: true, new-status: resolution})
    )
  )
)
(define-read-only (get-election-audit (election-id uint))
  (map-get? election-audits {election-id: election-id})
)
(define-read-only (get-dispute-record (election-id uint) (dispute-id uint))
  (map-get? dispute-records {election-id: election-id, dispute-id: dispute-id})
)
(define-read-only (get-audit-logs (election-id uint))
  (fold
    (lambda (id acc)
      (match (map-get? audit-logs {election-id: election-id, log-id: id})
        some-log (append acc (list some-log))
        none acc
      )
    )
    (list)
    (range u0 (var-get max-audit-logs))
  )
)
(define-public (release-final-results (election-id uint) (results (list 10 uint)))
  (begin
    (try! (check-audit-admin tx-sender))
    (asserts! (is-ok (is-results-published election-id)) (err ERR_RESULTS_NOT_PUBLISHED))
    (let ((current-audit (unwrap! (map-get? election-audits {election-id: election-id}) (err ERR_ELECTION_NOT_FOUND))))
      (map-set election-audits {election-id: election-id}
        {
          audited: (get audited current-audit),
          disputes: (get disputes current-audit),
          final-results: results,
          timestamp: block-height
        }
      )
      (try! (log-audit-action election-id "release" 0x00))
      (ok {released: true, results: results})
    )
  )
)
(define-public (check-audit-eligibility (voter principal) (election-id uint))
  (begin
    (asserts! (< block-height (+ (default-to u0 (get timestamp (map-get? election-audits {election-id: election-id}))) (var-get audit-timeout-blocks))) (err ERR_AUDIT_TIMEOUT))
    (contract-call? .voter-registry is-eligible? voter election-id)
  )
)