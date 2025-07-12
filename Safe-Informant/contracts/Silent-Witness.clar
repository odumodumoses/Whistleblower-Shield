;; Whistleblower Protection Smart Contract
;; This contract provides secure reporting mechanisms with identity protection
;; and incentive structures for whistleblowers

;; Error constants
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-INVALID-REPORT (err u101))
(define-constant ERR-REPORT-NOT-FOUND (err u102))
(define-constant ERR-ALREADY-VERIFIED (err u103))
(define-constant ERR-INSUFFICIENT-STAKE (err u104))
(define-constant ERR-ALREADY-VOTED (err u105))
(define-constant ERR-VOTING-PERIOD-ENDED (err u106))
(define-constant ERR-NOT-VERIFIED (err u107))
(define-constant ERR-REWARD-ALREADY-CLAIMED (err u108))
(define-constant ERR-INVALID-EVIDENCE (err u109))
(define-constant ERR-CASE-CLOSED (err u110))
(define-constant ERR-INVALID-AMOUNT (err u111))
(define-constant ERR-INVALID-PRINCIPAL (err u112))

;; Contract constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant MIN-STAKE u1000000) ;; 1 STX minimum stake
(define-constant VOTING-PERIOD u144) ;; ~24 hours in blocks
(define-constant VERIFICATION-THRESHOLD u3) ;; Minimum votes needed
(define-constant REWARD-PERCENTAGE u10) ;; 10% of recovery amount
(define-constant MAX-FUND-AMOUNT u1000000000) ;; Maximum funding amount per transaction

;; Data variables
(define-data-var next-report-id uint u1)
(define-data-var contract-balance uint u0)
(define-data-var total-reports uint u0)
(define-data-var total-verified-reports uint u0)

;; Report status enum
(define-constant STATUS-PENDING u0)
(define-constant STATUS-UNDER-REVIEW u1)
(define-constant STATUS-VERIFIED u2)
(define-constant STATUS-REJECTED u3)
(define-constant STATUS-CLOSED u4)

;; Report severity levels
(define-constant SEVERITY-LOW u1)
(define-constant SEVERITY-MEDIUM u2)
(define-constant SEVERITY-HIGH u3)
(define-constant SEVERITY-CRITICAL u4)

;; Data structures
(define-map reports
  uint
  {
    reporter: principal,
    anonymous-id: (buff 64),
    target-entity: (string-ascii 100),
    category: (string-ascii 50),
    severity: uint,
    evidence-hash: (buff 64),
    description-hash: (buff 64),
    status: uint,
    timestamp: uint,
    verification-votes: uint,
    rejection-votes: uint,
    voting-deadline: uint,
    reward-amount: uint,
    reward-claimed: bool,
    recovery-amount: uint
  })

(define-map report-evidence
  uint
  {
    evidence-count: uint,
    evidence-hashes: (list 10 (buff 64)),
    last-updated: uint
  })

(define-map verifiers
  principal
  {
    stake-amount: uint,
    reputation-score: uint,
    total-votes: uint,
    successful-verifications: uint,
    is-active: bool,
    registration-block: uint
  })

(define-map verifier-votes
  {verifier: principal, report-id: uint}
  {
    vote: bool, ;; true = verify, false = reject
    stake-used: uint,
    timestamp: uint
  })

(define-map anonymous-reporters
  (buff 64)
  {
    report-count: uint,
    total-rewards: uint,
    last-report-block: uint
  })

(define-map case-tracking
  uint
  {
    case-officer: principal,
    investigation-status: (string-ascii 50),
    last-update: uint,
    notes-hash: (buff 64)
  })

;; Authorization maps
(define-map authorized-investigators principal bool)
(define-map authorized-admins principal bool)

;; Initialize contract
(begin
  (map-set authorized-admins CONTRACT-OWNER true)
  (map-set authorized-investigators CONTRACT-OWNER true)
)

;; Read-only functions
(define-read-only (get-report (report-id uint))
  (map-get? reports report-id))

(define-read-only (get-report-evidence (report-id uint))
  (map-get? report-evidence report-id))

(define-read-only (get-verifier-info (verifier principal))
  (map-get? verifiers verifier))

(define-read-only (get-verifier-vote (verifier principal) (report-id uint))
  (map-get? verifier-votes {verifier: verifier, report-id: report-id}))

(define-read-only (get-anonymous-reporter-stats (anonymous-id (buff 64)))
  (map-get? anonymous-reporters anonymous-id))

(define-read-only (get-case-info (report-id uint))
  (map-get? case-tracking report-id))

(define-read-only (get-contract-stats)
  {
    total-reports: (var-get total-reports),
    total-verified: (var-get total-verified-reports),
    contract-balance: (var-get contract-balance),
    next-report-id: (var-get next-report-id)
  })

(define-read-only (is-authorized-investigator (user principal))
  (default-to false (map-get? authorized-investigators user)))

(define-read-only (is-authorized-admin (user principal))
  (default-to false (map-get? authorized-admins user)))

(define-read-only (calculate-reward (recovery-amount uint))
  (/ (* recovery-amount REWARD-PERCENTAGE) u100))

(define-read-only (get-voting-power (verifier principal))
  (let ((verifier-info (map-get? verifiers verifier)))
    (match verifier-info
      info (get stake-amount info)
      u0)))

;; Private functions
(define-private (generate-anonymous-id (reporter principal) (nonce uint))
  (let ((reporter-buff (unwrap-panic (to-consensus-buff? reporter)))
        (nonce-buff (unwrap-panic (to-consensus-buff? nonce)))
        (block-buff (unwrap-panic (to-consensus-buff? block-height))))
    (sha512 (concat (concat reporter-buff nonce-buff) block-buff))))

(define-private (update-verifier-reputation (verifier principal) (successful bool))
  (let ((current-info (default-to 
    {stake-amount: u0, reputation-score: u0, total-votes: u0, 
     successful-verifications: u0, is-active: false, registration-block: u0}
    (map-get? verifiers verifier))))
    (map-set verifiers verifier
      (merge current-info {
        total-votes: (+ (get total-votes current-info) u1),
        successful-verifications: (if successful 
          (+ (get successful-verifications current-info) u1)
          (get successful-verifications current-info)),
        reputation-score: (if successful
          (+ (get reputation-score current-info) u10)
          (if (> (get reputation-score current-info) u5)
            (- (get reputation-score current-info) u5)
            u0))
      }))))

(define-private (validate-evidence-hash (evidence-hash (buff 64)))
  (> (len evidence-hash) u0))

(define-private (validate-report-data (target-entity (string-ascii 100)) 
                                    (category (string-ascii 50))
                                    (severity uint))
  (and 
    (> (len target-entity) u0)
    (> (len category) u0)
    (>= severity SEVERITY-LOW)
    (<= severity SEVERITY-CRITICAL)))

(define-private (validate-principal (principal-to-check principal))
  (not (is-eq principal-to-check 'ST000000000000000000002AMW42H)))

(define-private (validate-amount (amount uint))
  (and (> amount u0) (<= amount MAX-FUND-AMOUNT)))

(define-private (validate-report-id (report-id uint))
  (and (> report-id u0) (< report-id (var-get next-report-id))))

;; Public functions

;; Submit a whistleblower report
(define-public (submit-report 
  (target-entity (string-ascii 100))
  (category (string-ascii 50))
  (severity uint)
  (evidence-hash (buff 64))
  (description-hash (buff 64))
  (is-anonymous bool))
  (let ((report-id (var-get next-report-id))
        (anonymous-id (if is-anonymous 
          (generate-anonymous-id tx-sender report-id)
          (sha512 (unwrap-panic (to-consensus-buff? tx-sender))))))
    (asserts! (validate-report-data target-entity category severity) ERR-INVALID-REPORT)
    (asserts! (validate-evidence-hash evidence-hash) ERR-INVALID-EVIDENCE)
    (asserts! (validate-evidence-hash description-hash) ERR-INVALID-EVIDENCE)
    
    ;; Create the report
    (map-set reports report-id {
      reporter: tx-sender,
      anonymous-id: anonymous-id,
      target-entity: target-entity,
      category: category,
      severity: severity,
      evidence-hash: evidence-hash,
      description-hash: description-hash,
      status: STATUS-PENDING,
      timestamp: block-height,
      verification-votes: u0,
      rejection-votes: u0,
      voting-deadline: (+ block-height VOTING-PERIOD),
      reward-amount: u0,
      reward-claimed: false,
      recovery-amount: u0
    })
    
    ;; Initialize evidence tracking
    (map-set report-evidence report-id {
      evidence-count: u1,
      evidence-hashes: (list evidence-hash),
      last-updated: block-height
    })
    
    ;; Update anonymous reporter stats if applicable
    (if is-anonymous
      (let ((current-stats (default-to 
        {report-count: u0, total-rewards: u0, last-report-block: u0}
        (map-get? anonymous-reporters anonymous-id))))
        (map-set anonymous-reporters anonymous-id
          (merge current-stats {
            report-count: (+ (get report-count current-stats) u1),
            last-report-block: block-height
          })))
      true)
    
    ;; Update contract state
    (var-set next-report-id (+ report-id u1))
    (var-set total-reports (+ (var-get total-reports) u1))
    
    (ok report-id)))

;; Add additional evidence to existing report
(define-public (add-evidence (report-id uint) (evidence-hash (buff 64)))
  (let ((report (unwrap! (map-get? reports report-id) ERR-REPORT-NOT-FOUND))
        (evidence-info (unwrap! (map-get? report-evidence report-id) ERR-REPORT-NOT-FOUND)))
    (asserts! (validate-report-id report-id) ERR-INVALID-REPORT)
    (asserts! (is-eq (get reporter report) tx-sender) ERR-UNAUTHORIZED)
    (asserts! (not (is-eq (get status report) STATUS-CLOSED)) ERR-CASE-CLOSED)
    (asserts! (validate-evidence-hash evidence-hash) ERR-INVALID-EVIDENCE)
    (asserts! (< (get evidence-count evidence-info) u10) ERR-INVALID-EVIDENCE)
    
    (map-set report-evidence report-id {
      evidence-count: (+ (get evidence-count evidence-info) u1),
      evidence-hashes: (unwrap-panic (as-max-len? 
        (append (get evidence-hashes evidence-info) evidence-hash) u10)),
      last-updated: block-height
    })
    
    (ok true)))

;; Register as a verifier
(define-public (register-verifier)
  (let ((stake-amount (stx-get-balance tx-sender)))
    (asserts! (>= stake-amount MIN-STAKE) ERR-INSUFFICIENT-STAKE)
    
    (try! (stx-transfer? MIN-STAKE tx-sender (as-contract tx-sender)))
    
    (map-set verifiers tx-sender {
      stake-amount: MIN-STAKE,
      reputation-score: u100,
      total-votes: u0,
      successful-verifications: u0,
      is-active: true,
      registration-block: block-height
    })
    
    (var-set contract-balance (+ (var-get contract-balance) MIN-STAKE))
    (ok true)))

;; Vote on report verification
(define-public (vote-on-report (report-id uint) (vote bool))
  (let ((report (unwrap! (map-get? reports report-id) ERR-REPORT-NOT-FOUND))
        (verifier-info (unwrap! (map-get? verifiers tx-sender) ERR-UNAUTHORIZED))
        (voting-power (get stake-amount verifier-info)))
    (asserts! (validate-report-id report-id) ERR-INVALID-REPORT)
    (asserts! (get is-active verifier-info) ERR-UNAUTHORIZED)
    (asserts! (<= block-height (get voting-deadline report)) ERR-VOTING-PERIOD-ENDED)
    (asserts! (is-none (map-get? verifier-votes 
      {verifier: tx-sender, report-id: report-id})) ERR-ALREADY-VOTED)
    (asserts! (not (is-eq (get status report) STATUS-VERIFIED)) ERR-ALREADY-VERIFIED)
    
    ;; Record the vote
    (map-set verifier-votes {verifier: tx-sender, report-id: report-id} {
      vote: vote,
      stake-used: voting-power,
      timestamp: block-height
    })
    
    ;; Update report vote counts
    (map-set reports report-id
      (merge report {
        verification-votes: (if vote 
          (+ (get verification-votes report) u1)
          (get verification-votes report)),
        rejection-votes: (if vote
          (get rejection-votes report)
          (+ (get rejection-votes report) u1)),
        status: STATUS-UNDER-REVIEW
      }))
    
    ;; Check if verification threshold is met
    (let ((updated-report (unwrap-panic (map-get? reports report-id))))
      (if (>= (get verification-votes updated-report) VERIFICATION-THRESHOLD)
        (begin
          (map-set reports report-id
            (merge updated-report {status: STATUS-VERIFIED}))
          (var-set total-verified-reports (+ (var-get total-verified-reports) u1))
          (update-verifier-reputation tx-sender true))
        (if (>= (get rejection-votes updated-report) VERIFICATION-THRESHOLD)
          (begin
            (map-set reports report-id
              (merge updated-report {status: STATUS-REJECTED}))
            (update-verifier-reputation tx-sender false))
          true)))
    
    (ok true)))

;; Assign case to investigator
(define-public (assign-case (report-id uint) (case-officer principal))
  (let ((report (unwrap! (map-get? reports report-id) ERR-REPORT-NOT-FOUND)))
    (asserts! (validate-report-id report-id) ERR-INVALID-REPORT)
    (asserts! (validate-principal case-officer) ERR-INVALID-PRINCIPAL)
    (asserts! (is-authorized-admin tx-sender) ERR-UNAUTHORIZED)
    (asserts! (is-authorized-investigator case-officer) ERR-UNAUTHORIZED)
    (asserts! (is-eq (get status report) STATUS-VERIFIED) ERR-NOT-VERIFIED)
    
    (map-set case-tracking report-id {
      case-officer: case-officer,
      investigation-status: "assigned",
      last-update: block-height,
      notes-hash: 0x00
    })
    
    (ok true)))

;; Update investigation status
(define-public (update-investigation-status 
  (report-id uint) 
  (status (string-ascii 50))
  (notes-hash (buff 64)))
  (let ((case-info (unwrap! (map-get? case-tracking report-id) ERR-REPORT-NOT-FOUND)))
    (asserts! (validate-report-id report-id) ERR-INVALID-REPORT)
    (asserts! (> (len status) u0) ERR-INVALID-REPORT)
    (asserts! (validate-evidence-hash notes-hash) ERR-INVALID-EVIDENCE)
    (asserts! (or (is-eq (get case-officer case-info) tx-sender)
                  (is-authorized-admin tx-sender)) ERR-UNAUTHORIZED)
    
    (map-set case-tracking report-id
      (merge case-info {
        investigation-status: status,
        last-update: block-height,
        notes-hash: notes-hash
      }))
    
    (ok true)))

;; Set reward amount for verified report
(define-public (set-reward-amount (report-id uint) (recovery-amount uint))
  (let ((report (unwrap! (map-get? reports report-id) ERR-REPORT-NOT-FOUND)))
    (asserts! (validate-report-id report-id) ERR-INVALID-REPORT)
    (asserts! (validate-amount recovery-amount) ERR-INVALID-AMOUNT)
    (asserts! (is-authorized-admin tx-sender) ERR-UNAUTHORIZED)
    (asserts! (is-eq (get status report) STATUS-VERIFIED) ERR-NOT-VERIFIED)
    
    (let ((reward-amount (calculate-reward recovery-amount)))
      (map-set reports report-id
        (merge report {
          reward-amount: reward-amount,
          recovery-amount: recovery-amount
        })))
    
    (ok true)))

;; Claim reward for verified report
(define-public (claim-reward (report-id uint))
  (let ((report (unwrap! (map-get? reports report-id) ERR-REPORT-NOT-FOUND)))
    (asserts! (validate-report-id report-id) ERR-INVALID-REPORT)
    (asserts! (is-eq (get reporter report) tx-sender) ERR-UNAUTHORIZED)
    (asserts! (is-eq (get status report) STATUS-VERIFIED) ERR-NOT-VERIFIED)
    (asserts! (> (get reward-amount report) u0) ERR-INVALID-REPORT)
    (asserts! (not (get reward-claimed report)) ERR-REWARD-ALREADY-CLAIMED)
    
    (try! (as-contract (stx-transfer? (get reward-amount report) tx-sender tx-sender)))
    
    (map-set reports report-id
      (merge report {reward-claimed: true}))
    
    ;; Update anonymous reporter stats
    (let ((anonymous-stats (map-get? anonymous-reporters (get anonymous-id report))))
      (match anonymous-stats
        stats (map-set anonymous-reporters (get anonymous-id report)
          (merge stats {
            total-rewards: (+ (get total-rewards stats) (get reward-amount report))
          }))
        true))
    
    (ok true)))

;; Close case
(define-public (close-case (report-id uint))
  (let ((report (unwrap! (map-get? reports report-id) ERR-REPORT-NOT-FOUND)))
    (asserts! (validate-report-id report-id) ERR-INVALID-REPORT)
    (asserts! (is-authorized-admin tx-sender) ERR-UNAUTHORIZED)
    
    (map-set reports report-id
      (merge report {status: STATUS-CLOSED}))
    
    (ok true)))

;; Admin functions
(define-public (add-investigator (investigator principal))
  (begin
    (asserts! (validate-principal investigator) ERR-INVALID-PRINCIPAL)
    (asserts! (is-authorized-admin tx-sender) ERR-UNAUTHORIZED)
    (map-set authorized-investigators investigator true)
    (ok true)))

(define-public (remove-investigator (investigator principal))
  (begin
    (asserts! (validate-principal investigator) ERR-INVALID-PRINCIPAL)
    (asserts! (is-authorized-admin tx-sender) ERR-UNAUTHORIZED)
    (map-delete authorized-investigators investigator)
    (ok true)))

(define-public (add-admin (admin principal))
  (begin
    (asserts! (validate-principal admin) ERR-INVALID-PRINCIPAL)
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    (map-set authorized-admins admin true)
    (ok true)))

;; Fund contract for rewards
(define-public (fund-contract (amount uint))
  (begin
    (asserts! (validate-amount amount) ERR-INVALID-AMOUNT)
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (var-set contract-balance (+ (var-get contract-balance) amount))
    (ok true)))

;; Withdraw verifier stake (admin only for dispute resolution)
(define-public (withdraw-verifier-stake (verifier principal))
  (let ((verifier-info (unwrap! (map-get? verifiers verifier) ERR-UNAUTHORIZED)))
    (asserts! (validate-principal verifier) ERR-INVALID-PRINCIPAL)
    (asserts! (is-authorized-admin tx-sender) ERR-UNAUTHORIZED)
    (asserts! (> (get stake-amount verifier-info) u0) ERR-INVALID-AMOUNT)
    
    (try! (as-contract (stx-transfer? (get stake-amount verifier-info) tx-sender verifier)))
    
    (map-delete verifiers verifier)
    (var-set contract-balance (- (var-get contract-balance) (get stake-amount verifier-info)))
    
    (ok true)))