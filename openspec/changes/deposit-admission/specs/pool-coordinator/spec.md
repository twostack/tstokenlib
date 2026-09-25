## MODIFIED Requirements

### Requirement: Deposits by covenant
A deposit SHALL reach a round as a transfer of the deposit shape together with the transaction holding the depositor's covenant. The coordinator SHALL accept the deposit only if the covenant names the pool's live PP3 (the tip round's output 3), its receipt equals the transfer's receipt (first commitment and value), and its refund height is at least the configured margin ahead; SHALL refuse it, naming the reason, otherwise; SHALL take at most the plan's receipt slots (8) into a round; and SHALL refuse a deposit whose covenant names a PP3 the pending or an in-flight round spends, telling the wallet to deposit against the new tip.

When the caller admits deposits (for instance by broadcasting the covenant), a deposit that passes every check, the spend proof last, SHALL hold its place in the pending round (capacity, a receipt slot, its covenant and its nullifiers) while the caller admits it. It SHALL be accepted when the caller admits it and refused, naming the caller's reason, when the caller does not, its place then released. A round closed while one of its deposits is being admitted SHALL be built only once that admission has ended, without the deposit if it was refused. The caller SHALL NOT be asked to admit a deposit that failed any check.

#### Scenario: The fixture's deposit
- **WHEN** the fixture's deposit transfer arrives with its covenant transaction
- **THEN** it is accepted, and the round carries its receipt at output 5 and the covenant at input 5

#### Scenario: A deposit for the previous round
- **WHEN** a covenant naming the PP3 of a round already closed arrives
- **THEN** it is refused as targeting a spent round

#### Scenario: A receipt that is not the transfer's
- **WHEN** a covenant's commitment differs from the transfer's first output commitment
- **THEN** it is refused as not matching the transfer

#### Scenario: Held while admitted
- **WHEN** the fixture's deposit is being admitted and the pending round's receipt slots are full
- **THEN** another deposit is refused for want of a slot, and the same covenant again is refused as a pending deposit; neither is admitted

#### Scenario: Admission refused
- **WHEN** the caller refuses to admit the fixture's deposit
- **THEN** the reply refuses it naming the caller's reason, nothing is pending, and the same deposit can be submitted again

#### Scenario: The deadline during an admission
- **WHEN** the round's deadline passes while its deposit is being admitted
- **THEN** the round is built once the admission ends: with the deposit when admitted, with padding in its place when refused

#### Scenario: A failing check is never admitted
- **WHEN** a deposit with a bad proof, a covenant for another PP3, a refund too soon, or no receipt slot left arrives
- **THEN** it is refused and the caller is never asked to admit it

#### Scenario: No admitting caller
- **WHEN** the coordinator is built without an admission hook
- **THEN** a deposit is accepted or refused at once, exactly as before
