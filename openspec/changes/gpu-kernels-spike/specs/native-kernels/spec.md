## ADDED Requirements

### Requirement: GPU backend
The library MAY run the Poseidon2 commitment (leaves and tree) and the circle FFT (interpolation, evaluation and low-degree extension) on a GPU. When the backend is enabled and a device is present the results SHALL be identical to the CPU kernels' and therefore to the Dart implementation's, so a proof made with the backend on is byte for byte the proof made with it off. When no device is present, the shaders fail to compile, or the library was built without the backend, enabling it SHALL be refused, the refusal SHALL be reported to the caller, and the CPU kernels SHALL run. Evaluations committed on the GPU SHALL be readable in place by the kernels that follow, with no copy of the column set.

#### Scenario: Identical proofs with the GPU on
- **WHEN** the same node is proved with the backend enabled and with it disabled
- **THEN** the two proofs are byte-identical, and both equal the Dart prover's

#### Scenario: No device
- **WHEN** the backend is requested on a machine without a usable GPU or with a library built without it
- **THEN** the request is refused with a reason, the backend name reports the CPU path, and proving proceeds on the CPU

#### Scenario: Enabled by the environment
- **WHEN** the Dart side is started with the GPU switch set and a device is present
- **THEN** the kernels report the GPU backend by name and the commitment and FFT stages run on it

## MODIFIED Requirements

### Requirement: ABI versioning
The library SHALL export its ABI version and the Dart side SHALL refuse to load a mismatching version.

#### Scenario: Stale build
- **WHEN** the Dart code expects ABI 5 and the library reports 4
- **THEN** loading fails with a message naming both versions
