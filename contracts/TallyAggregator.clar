(define-constant ERR_TALLY_NOT_AUTHORIZED u2000)
(define-constant ERR_ELECTION_NOT_ACTIVE u2001)
(define-constant ERR_INVALID_CANDIDATE u2002)
(define-constant ERR_TALLY_ALREADY_PUBLISHED u2003)
(define-constant ERR_INSUFFICIENT_PROOFS u2004)
(define-constant ERR_HOMOMORPHIC_FAILURE u2005)
(define-constant ERR_AGGREGATE_OVERFLOW u2006)
(define-constant ERR_TALLY_PERIOD_EXPIRED u2007)
(define-constant ERR_VERIFICATION_FAILED u2008)
(define-constant ERR_CANDIDATE_LIST_EMPTY u2009)
(define-constant ERR_TALLY_RESET_NOT_ALLOWED u2010)
(define-constant ERR_INVALID_TALLY_INPUT u2011)
(define-data-var current-election-id uint u0)
(define-data-var tally-admin (optional principal) none)
(define-data-var max-candidates uint u10)
(define-data-var tally-precision uint u1000000)
(define-map election-tallies
  {election-id: uint}
  {
    candidates: (list 10 uint),
    encrypted-tallies: (list 10 (buff 32)),
    published: bool,
    timestamp: uint
  }
)
(define-map proof-aggregates
  {election-id: uint, candidate-id: uint}
  {count: uint, hash-sum: (buff 32), verified: bool}
)
(define-map tally-logs
  {election-id: uint, log-id: uint}
  {action: (string-ascii 20), details: (buff 64), timestamp: uint}
)
(define-private (hash-aggregate (candidate-id uint) (count uint) (prev-hash (buff 32)))
  (hash-pk .sha256 (concat (uint-to-buff count) (concat (uint-to-buff candidate-id) prev-hash)))
)
(define-private (homomorphic-add (enc1 (buff 32)) (enc2 (buff 32)))
  (if (and (is-eq (len enc1) u32) (is-eq (len enc2) u32))
    (ok (hash-pk .sha256 (xor enc1 enc2)))
    ERR_HOMOMORPHIC_FAILURE
  )
)
(define-private (validate-candidate-list (candidates (list 10 uint)))
  (let ((cand-count (len candidates)))
    (and (> cand-count u0) (<= cand-count (var-get max-candidates)) (ok true))
  )
)
(define-private (is-election-active (election-id uint))
  (contract-call? .election-manager is-election-active election-id)
)
(define-private (verify-aggregate (election-id uint) (candidate-id uint))
  (contract-call? .zk-proof-verifier aggregate-verified-proofs election-id)
)
(define-private (check-tally-admin (caller principal))
  (is-eq caller (unwrap! (var-get tally-admin) (err ERR_TALLY_NOT_AUTHORIZED)))
)
(define-private (log-action (election-id uint) (action (string-ascii 20)) (details (buff 64)))
  (let ((next-log (default-to u0 (map-get? tally-logs {election-id: election-id, log-id: u0}))))
    (map-set tally-logs {election-id: election-id, log-id: next-log}
      {action: action, details: details, timestamp: block-height}
    )
  )
)
(define-public (set-tally-admin (admin principal))
  (begin
    (asserts! (is-none (var-get tally-admin)) (err ERR_TALLY_NOT_AUTHORIZED))
    (var-set tally-admin (some admin))
    (ok true)
  )
)
(define-public (set-max-candidates (new-max uint))
  (begin
    (try! (check-tally-admin tx-sender))
    (asserts! (> new-max u0) (err ERR_INVALID_CANDIDATE))
    (var-set max-candidates new-max)
    (ok true)
  )
)
(define-public (set-tally-precision (precision uint))
  (begin
    (try! (check-tally-admin tx-sender))
    (asserts! (> precision u0) (err ERR_INVALID_TALLY_INPUT))
    (var-set tally-precision precision)
    (ok true)
  )
)
(define-public (initialize-election-tally (election-id uint) (candidates (list 10 uint)))
  (begin
    (try! (check-tally-admin tx-sender))
    (asserts! (is-ok (is-election-active election-id)) (err ERR_ELECTION_NOT_ACTIVE))
    (try! (validate-candidate-list candidates))
    (asserts! (not (default-to true (get published (map-get? election-tallies {election-id: election-id})))) (err ERR_TALLY_ALREADY_PUBLISHED))
    (let ((initial-enc (fold homomorphic-add (ok 0x00) (map (lambda (c) 0x00) candidates))))
      (map-set election-tallies {election-id: election-id}
        {
          candidates: candidates,
          encrypted-tallies: (unwrap-panic initial-enc),
          published: false,
          timestamp: block-height
        }
      )
      (try! (log-action election-id "init" (uint-to-buff election-id)))
      (ok true)
    )
  )
)
(define-public (aggregate-candidate-proofs (election-id uint) (candidate-id uint) (proof-count uint))
  (begin
    (try! (check-tally-admin tx-sender))
    (asserts! (is-ok (is-election-active election-id)) (err ERR_ELECTION_NOT_ACTIVE))
    (asserts! (>= proof-count (var-get tally-precision)) (err ERR_INSUFFICIENT_PROOFS))
    (asserts! (is-ok (verify-aggregate election-id candidate-id)) (err ERR_VERIFICATION_FAILED))
    (let (
      (prev-agg (default-to {count: u0, hash-sum: 0x00, verified: false} (map-get? proof-aggregates {election-id: election-id, candidate-id: candidate-id})))
      (new-count (+ (get count prev-agg) proof-count))
      (new-hash (hash-aggregate candidate-id new-count (get hash-sum prev-agg)))
    )
      (if (> new-count u1000000)
        (err ERR_AGGREGATE_OVERFLOW)
        (begin
          (map-set proof-aggregates {election-id: election-id, candidate-id: candidate-id}
            {count: new-count, hash-sum: new-hash, verified: true}
          )
          (try! (log-action election-id "agg" (uint-to-buff candidate-id)))
          (ok {updated-count: new-count, hash: new-hash})
        )
      )
    )
  )
)
(define-public (publish-encrypted-tally (election-id uint))
  (begin
    (try! (check-tally-admin tx-sender))
    (let (
      (tally-data (unwrap! (map-get? election-tallies {election-id: election-id}) (err ERR_ELECTION_NOT_ACTIVE)))
      (candidates (get candidates tally-data))
    )
      (fold
        (lambda (cand-id prev-enc)
          (match prev-enc
            enc-ok
              (let (
                (agg (unwrap! (map-get? proof-aggregates {election-id: election-id, candidate-id: cand-id}) (err ERR_INSUFFICIENT_PROOFS)))
                (enc-update (homomorphic-add enc-ok (get hash-sum agg)))
              )
                (match enc-update
                  update-ok update-ok
                  err ERR_HOMOMORPHIC_FAILURE
                )
              )
            err err
          )
        )
        (ok 0x00)
        candidates
      )
      (match (homomorphic-add (get encrypted-tallies tally-data) (ok 0x00))
        final-enc
          (begin
            (map-set election-tallies {election-id: election-id}
              {
                candidates: candidates,
                encrypted-tallies: final-enc,
                published: true,
                timestamp: block-height
              }
            )
            (try! (log-action election-id "publish" final-enc))
            (ok {published: true, final-encrypted: final-enc})
          )
        err ERR_HOMOMORPHIC_FAILURE
      )
    )
  )
)
(define-read-only (get-election-tally (election-id uint))
  (map-get? election-tallies {election-id: election-id})
)
(define-read-only (get-proof-aggregate (election-id uint) (candidate-id uint))
  (map-get? proof-aggregates {election-id: election-id, candidate-id: candidate-id})
)
(define-read-only (get-tally-logs (election-id uint))
  (list
    (default-to {action: "", details: 0x00, timestamp: u0} (map-get? tally-logs {election-id: election-id, log-id: u0}))
    (default-to {action: "", details: 0x00, timestamp: u0} (map-get? tally-logs {election-id: election-id, log-id: u1}))
    (default-to {action: "", details: 0x00, timestamp: u0} (map-get? tally-logs {election-id: election-id, log-id: u2}))
  )
)
(define-public (reset-election-tally (election-id uint))
  (begin
    (try! (check-tally-admin tx-sender))
    (asserts! (not (default-to true (get published (map-get? election-tallies {election-id: election-id})))) (err ERR_TALLY_ALREADY_PUBLISHED))
    (map-delete election-tallies {election-id: election-id})
    (map-delete proof-aggregates {election-id: election-id, candidate-id: u1})
    (map-delete proof-aggregates {election-id: election-id, candidate-id: u2})
    (map-delete proof-aggregates {election-id: election-id, candidate-id: u3})
    (map-delete tally-logs {election-id: election-id, log-id: u0})
    (map-delete tally-logs {election-id: election-id, log-id: u1})
    (map-delete tally-logs {election-id: election-id, log-id: u2})
    (ok true)
  )
)
(define-public (validate-tally-integrity (election-id uint))
  (begin
    (try! (check-tally-admin tx-sender))
    (let (
      (tally (unwrap! (map-get? election-tallies {election-id: election-id}) (err ERR_ELECTION_NOT_ACTIVE)))
      (total-proofs (fold + u0 (map (lambda (cand) (default-to u0 (get count (map-get? proof-aggregates {election-id: election-id, candidate-id: cand})))) (get candidates tally))))
    )
      (if (>= total-proofs (var-get tally-precision))
        (ok {integrity: true, total-votes: total-proofs})
        ERR_INSUFFICIENT_PROOFS
      )
    )
  )
)