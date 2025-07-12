# Whistleblower Protection Smart Contract

## Overview

This Clarity smart contract provides a secure, decentralized platform for whistleblower reporting with built-in identity protection, verification mechanisms, and incentive structures. The contract enables anonymous reporting of wrongdoing while maintaining transparency and accountability through a community-driven verification system.

## Features

### **Anonymous Reporting**
- Secure anonymous report submission with cryptographic identity protection
- Anonymous ID generation using SHA-512 hashing
- Protection of reporter identity while maintaining report integrity

### **Verification System**
- Community-driven verification through registered verifiers
- Stake-based voting mechanism to ensure quality control
- Reputation scoring system for verifiers
- Configurable verification thresholds

### **Incentive Structure**
- Reward system for verified reports (10% of recovery amount)
- Stake requirements for verifiers to prevent spam
- Reputation-based verifier rewards

### **Case Management**
- Professional case assignment to authorized investigators
- Investigation status tracking
- Evidence management with multiple evidence submissions
- Case closure mechanisms

### **Security Features**
- Role-based access control (Admin, Investigator, Verifier)
- Evidence integrity through cryptographic hashing
- Time-bound voting periods
- Anti-fraud mechanisms

## Contract Architecture

### Data Structures

#### Reports
Each report contains:
- Reporter information (protected for anonymous reports)
- Target entity and category
- Severity level (Low, Medium, High, Critical)
- Evidence and description hashes
- Status tracking
- Voting information
- Reward details

#### Verifiers
Registered verifiers have:
- Stake amount (minimum 1 STX)
- Reputation score
- Voting history
- Active status

#### Case Tracking
Investigation management includes:
- Assigned case officer
- Investigation status
- Update timestamps
- Encrypted notes

### Status Flow

```
PENDING → UNDER_REVIEW → VERIFIED/REJECTED → CLOSED
```

## Usage Guide

### For Whistleblowers

#### 1. Submit a Report
```clarity
(submit-report 
  "Target Organization"     ;; target-entity
  "Fraud"                  ;; category
  u3                       ;; severity (1-4)
  evidence-hash            ;; evidence hash
  description-hash         ;; description hash
  true)                    ;; is-anonymous
```

#### 2. Add Additional Evidence
```clarity
(add-evidence report-id additional-evidence-hash)
```

#### 3. Claim Rewards
```clarity
(claim-reward report-id)
```

### For Verifiers

#### 1. Register as Verifier
```clarity
(register-verifier)
```
*Requires minimum stake of 1 STX*

#### 2. Vote on Reports
```clarity
(vote-on-report report-id true)  ;; true = verify, false = reject
```

### For Investigators

#### 1. Update Investigation Status
```clarity
(update-investigation-status 
  report-id 
  "investigating" 
  encrypted-notes-hash)
```

### For Administrators

#### 1. Assign Cases
```clarity
(assign-case report-id investigator-principal)
```

#### 2. Set Reward Amounts
```clarity
(set-reward-amount report-id recovery-amount)
```

#### 3. Manage Permissions
```clarity
(add-investigator investigator-principal)
(add-admin admin-principal)
```

## Configuration

### Constants
- **MIN-STAKE**: 1,000,000 microSTX (1 STX minimum for verifiers)
- **VOTING-PERIOD**: 144 blocks (~24 hours)
- **VERIFICATION-THRESHOLD**: 3 votes required for verification
- **REWARD-PERCENTAGE**: 10% of recovery amount

### Severity Levels
1. **Low** (u1): Minor policy violations
2. **Medium** (u2): Moderate misconduct
3. **High** (u3): Serious violations
4. **Critical** (u4): Severe wrongdoing with major impact

## Security Considerations

### Identity Protection
- Anonymous IDs generated using SHA-512 with multiple entropy sources
- No direct linking between reporter identity and anonymous reports
- Evidence hashing prevents tampering

### Economic Security
- Stake requirements prevent spam and ensure verifier commitment
- Reputation system incentivizes honest behavior
- Reward percentage limits prevent excessive incentives

### Access Control
- Multi-tier authorization system
- Contract owner controls admin permissions
- Role-based function restrictions

## Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| u100 | ERR-UNAUTHORIZED | Insufficient permissions |
| u101 | ERR-INVALID-REPORT | Invalid report data |
| u102 | ERR-REPORT-NOT-FOUND | Report does not exist |
| u103 | ERR-ALREADY-VERIFIED | Report already verified |
| u104 | ERR-INSUFFICIENT-STAKE | Insufficient stake amount |
| u105 | ERR-ALREADY-VOTED | Verifier already voted |
| u106 | ERR-VOTING-PERIOD-ENDED | Voting period expired |
| u107 | ERR-NOT-VERIFIED | Report not verified |
| u108 | ERR-REWARD-ALREADY-CLAIMED | Reward already claimed |
| u109 | ERR-INVALID-EVIDENCE | Invalid evidence format |
| u110 | ERR-CASE-CLOSED | Case is closed |

## Read-Only Functions

### Query Functions
- `get-report(report-id)`: Retrieve report details
- `get-verifier-info(verifier)`: Get verifier information
- `get-contract-stats()`: Get contract statistics
- `calculate-reward(recovery-amount)`: Calculate reward amount

### Status Check Functions
- `is-authorized-investigator(user)`: Check investigator status
- `is-authorized-admin(user)`: Check admin status
- `get-voting-power(verifier)`: Get verifier voting power

## Deployment

### Prerequisites
- Stacks blockchain testnet/mainnet access
- Clarity CLI or compatible deployment tool
- STX tokens for contract deployment and testing

### Deployment Steps
1. Compile the contract using Clarity CLI
2. Deploy to desired network
3. Initialize with contract owner
4. Configure initial administrators and investigators
5. Fund contract for reward payments

## Testing

### Unit Tests
Test coverage should include:
- Report submission (anonymous and identified)
- Verifier registration and voting
- Case assignment and management
- Reward calculation and distribution
- Access control mechanisms
- Error handling

### Integration Tests
- End-to-end reporting workflows
- Multi-verifier scenarios
- Investigation lifecycle
- Reward claim processes

## Governance

### Contract Upgrades
- Contract owner can add/remove admins
- Admin consensus required for major parameter changes
- Verifier stake adjustments through governance

### Dispute Resolution
- Admin override capabilities for dispute resolution
- Verifier stake withdrawal for misconduct
- Case reassignment mechanisms

## Legal Considerations

### Compliance
- Ensure compliance with local whistleblower protection laws
- Consider data protection regulations
- Implement appropriate record-keeping requirements

### Liability
- Smart contract code is provided as-is
- Users responsible for legal compliance
- Consider professional legal review before deployment