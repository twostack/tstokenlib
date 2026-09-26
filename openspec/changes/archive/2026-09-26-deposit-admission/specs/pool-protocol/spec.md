## MODIFIED Requirements

### Requirement: No secrets in a message
A submission SHALL carry nothing a transfer does not already carry, plus a deposit transaction, which the coordinator or the depositor publishes on the chain. The submission id SHALL be random, not derived from any key or note. A reply SHALL name nothing about the transfer beyond the outcome. A descriptor and an announcement SHALL carry only what the chain publishes.

#### Scenario: Submission holds no key material
- **WHEN** a wallet's submission is encoded
- **THEN** the encoding contains no run of bytes equal to the wallet's spending key, viewing keys, nullifier key, the spent notes' rho or rcm, or the diversifier it used
