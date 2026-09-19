# native-kernels Specification

## Purpose
The Rust crate that makes the prover fast: circle FFTs, commitments, the composition and LogUp evaluators, DEEP quotients, FRI folds, Poseidon2, SHA256 and ML-KEM, called from Dart over FFI. It is an exact port of the Dart code, so its only effect is speed and memory.

## Requirements

### Requirement: Exact port with fallback
Every kernel SHALL compute exactly what the Dart implementation computes, and the Dart side SHALL fall back to pure Dart when the library is not built, except for ML-KEM, which has no Dart fallback and SHALL fail loudly when the library is absent.

#### Scenario: Library absent
- **WHEN** the shared library cannot be found
- **THEN** proofs are still produced (slower) and note encryption with the hybrid KEM throws a state error

### Requirement: ABI versioning
The library SHALL export its ABI version and the Dart side SHALL refuse to load a mismatching version.

#### Scenario: Stale build
- **WHEN** the Dart code expects ABI 5 and the library reports 4
- **THEN** loading fails with a message naming both versions

### Requirement: Column store
Committed value columns SHALL stay in native memory: a commit returns an id, later kernels (composition, DEEP quotients, openings) read the columns by id, and the caller frees them. Reading a freed id SHALL be an error.

#### Scenario: Node memory
- **WHEN** a 2^20-row verifier node is proved at blowup 8
- **THEN** the Dart heap holds no committed evaluations and peak process memory stays under 9 GB

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

### Requirement: Vectorised Poseidon2
Poseidon2 leaves and tree levels SHALL be hashed sixteen states at a time and produce the same digests as the scalar permutation.

#### Scenario: Wide equals scalar
- **WHEN** leaves are hashed sixteen at a time and one at a time
- **THEN** every digest matches

### Requirement: Composition from a recorded program
The composition kernel SHALL evaluate an AIR's constraints from its straight-line program (main over M31, aux over QM31) on the composition domain, weighted by the composition challenge's powers and divided by each constraint's group divisor, either from coefficient columns it extends itself or from committed value columns when the composition domain equals the commitment domain.

#### Scenario: Both inputs give one answer
- **WHEN** the same node is proved at blowup 4 (coefficients extended in the kernel) and blowup 8 (committed values reused)
- **THEN** each proof matches the Dart prover's byte for byte

### Requirement: Post-quantum KEM
The crate SHALL expose ML-KEM-768 key generation from a 64-byte seed, encapsulation with caller-supplied randomness, and decapsulation with implicit rejection; keys are regenerated from the seed on every call and never stored.

#### Scenario: Tampered ciphertext
- **WHEN** a ciphertext byte is flipped before decapsulation
- **THEN** the shared secret differs and no error reveals which
