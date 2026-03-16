# Tech Stack Feasibility Assessment

A speculative assessment of how existing technology components can be composed to deliver the [end-to-end system architecture](SYSTEM_ARCHITECTURE_ROADMAP.md) defined in the TSL1 roadmap.

---

## Components Under Evaluation

| Component | Language | What It Is |
|---|---|---|
| **tstokenlib** | Dart | TSL1 protocol library — script generators, lock/unlock builders, lifecycle APIs |
| **TSL1 Script Templates** | Language-agnostic (JSON) | Pre-compiled script templates with `{{param}}` substitution — enables any language to construct valid token scripts |
| **Bitcoin4J** | Java | BSV library — transaction building, HD wallets, script interpreter (owned, being aligned with dartsv) |
| **Jmix** | Java (Spring Boot) | RAD platform for business applications — JPA, Vaadin UI, REST APIs, security, audit |
| **go-spiffy** | Go | BSV SPV wallet sidecar — libp2p, protobuf, PostgreSQL, BEEF/SPV, payment-gated access |
| **BSV TS-SDK** | TypeScript | Zero-dependency BSV SDK — transaction building, script interpreter, key management, browser-native |
| **spiffynode** | Dart | BSV P2P networking library — wire protocol, peer management, SPV chain tracking |
| **spiffywallet** | Dart | Wallet sidecar service — libp2p, actor-based, xpub/xpriv modes, PostgreSQL |
| **wallet-toolbox** | TypeScript | BSV wallet toolkit — BRC-100 compliant, persistent storage, key derivation |

---

## Component Profiles

### tstokenlib (Dart)

The foundation of the entire system. Provides:

- Hand-optimized locking scripts for PP1_NFT and PP1_FT (implemented)
- Script generators, lock builders, unlock builders for all token archetypes
- Full SHA256-in-script generator (~37.5 KB PP3 witness scripts)
- Token lifecycle APIs (`TokenTool`, `FungibleTokenTool`)
- Local test coverage via dartsv script interpreter (`Interpreter.correctlySpends()`)
- **Language-agnostic script templates** (`templates/`) — see below

**Role in architecture:** Phase 1 (protocol layer) — already serves this role. The Dart codebase is the canonical source; the JSON templates are generated from it and enable other languages to construct token scripts without Dart.

### TSL1 Script Templates (Language-Agnostic)

Pre-compiled JSON template files generated from the Dart source code via `dart run tool/export_templates.dart`. Each template contains the complete hex-encoded script with `{{paramName}}` placeholders for variable substitution.

**What's available today:**

```
templates/
  nft/
    pp1_nft.json         — NFT inductive proof locking script (~18 KB)
    pp2.json             — NFT witness bridge
    pp3_witness.json     — NFT partial SHA256 witness (~124 KB)
  ft/
    pp1_ft.json          — Fungible token proof locking script
    pp2_ft.json          — FT witness bridge
    pp3_ft_witness.json  — FT partial SHA256 witness (~124 KB)
  utility/
    mod_p2pkh.json       — Modified P2PKH (token value output)
    hodl.json            — Time-lock script
```

**How they work:**

Templates use two parameter categories:
- **Category A** (PP1, PP3, ModP2PKH): Fixed-size hex parameters. Pushdata prefixes are baked into the static hex. Substitute raw hex bytes only.
- **Category B** (PP2, HODL): Variable-size parameters. Values must include their Bitcoin pushdata or script_number encoding prefix.

```python
# Any language can construct a valid PP1_NFT locking script:
tpl = load_json("templates/nft/pp1_nft.json")
script = tpl["hex"]
    .replace("{{ownerPKH}}", owner_pkh_hex)       # 40 hex chars
    .replace("{{tokenId}}", token_id_hex)          # 64 hex chars
    .replace("{{rabinPubKeyHash}}", rabin_hash)    # 40 hex chars
raw_bytes = hex_decode(script)
```

**Impact on architecture:** This is a game-changer for the language bridge problem. Java/Jmix can construct token locking scripts directly from templates using Bitcoin4J for standard transaction building and simple string substitution for token scripts. **No Dart microservice is needed for script generation.**

**What templates do NOT cover:**
- Unlock script (scriptSig) construction — requires assembling signatures, sighash preimages, parent raw transactions, and event data in the correct stack order
- Sighash preimage computation for checkPreimageOCS — requires understanding the BSV sighash algorithm
- Token state parsing — extracting mutable fields from an existing script requires knowing the byte offsets
- Commitment hash chain computation — rolling SHA256 logic

These operations are algorithmically straightforward and can be implemented in any language using the byte layout specifications in the archetype documents. They do not require the ~37.5 KB script generation logic — they operate on the parameters that go *into* and come *out of* the scripts.

### Bitcoin4J (Java) — Owned

A BSV-aligned Java library forked from BitcoinJ. **We own this library** and are actively aligning it with the latest dartsv changes. The two libraries historically had parity; dartsv has pulled ahead slightly and Bitcoin4J is being updated to match.

Provides:

- Transaction building with a clean fluent API
- Multiple locking script builders (P2PKH, P2MS, P2PK, P2SH, P2PKHDataLock)
- HD key derivation (BIP32) and mnemonic seeds (BIP39)
- Built-in script interpreter for transaction validation
- Original Bitcoin address format (no SegWit, no Schnorr — BSV-aligned)
- Maven Central distribution (v1.6.6)

**Parity roadmap:** Once aligned with dartsv, Bitcoin4J's script interpreter will match dartsv's behaviour, enabling Java-side script validation of TSL1 token scripts — not just template substitution, but full interpreter-verified testing in Java. This makes the Java token service layer self-sufficient for both construction and validation.

**Role in architecture:** Enables the Java/Jmix layer to construct complete BSV transactions. With the language-agnostic templates, Bitcoin4J can now handle **both** the standard BSV parts (funding inputs, P2PKH outputs, fee estimation) **and** the token-specific parts (PP1/PP2/PP3 locking scripts via template substitution). The token locking scripts are just byte arrays from Bitcoin4J's perspective — loaded from JSON templates and parameterised via string replacement.

**What Bitcoin4J provides natively:** Transaction building, input/output assembly, P2PKH scripts, HD wallets, signature generation, script interpreter.

**What must be built on top of Bitcoin4J (using templates + archetype specs):**
- Template loader and parameter substitution (trivial — JSON parse + string replace)
- Token transaction topologies (5-output, 7-output assembly — follows the archetype specs)
- Sighash preimage computation for checkPreimageOCS (Bitcoin4J already computes sighash; the preimage serialisation follows BIP-143 format)
- Unlock script (scriptSig) assembly (stack ordering per operation — follows the archetype specs)
- Token state extraction (byte offset parsing from raw script — follows header layouts)

### Jmix (Java / Spring Boot)

An open-source RAD platform for line-of-business applications. Provides:

- **Data model:** JPA entities with soft deletion, audit logging (tracks all changes), many-to-many relationship tracking
- **Security:** Screen/menu authorization, entity/attribute-level restrictions, row-level security (criteria-based filtering), API key management
- **UI:** Vaadin 24.9-based enterprise web UI with data grids, forms, card layouts, CSS Grid, user menus, grouping, filtering
- **REST API:** Auto-generated REST endpoints with controlled access to entities
- **Add-ons:** 40+ add-ons including BPM engine, reports (annotated Java classes), notifications, email
- **Deployment:** Local to public cloud, containerized
- **Dev tooling:** IntelliJ IDEA Studio plugin, AI assistant, code generation
- **Language:** Java or Kotlin, full-stack

**Role in architecture:** Phase 4 (Token Lifecycle Service) and Phase 5 (Business Integration). Jmix is purpose-built for exactly the kind of business application these phases describe — a service with entities, roles, REST APIs, dashboards, batch operations, and event hooks.

### go-spiffy (Go) — Sidecar Configuration

A production-grade BSV SPV wallet service designed to run as a sidecar process. Provides:

- **Wallet management:** HD wallets (BIP32), UTXO tracking, balance queries
- **Transaction building:** Standard BSV transaction construction and broadcasting
- **Invoice system:** Create invoices, track payment status, payment-gated access control
- **P2P networking:** libp2p-based peer protocol (`/spiffy/wallet/1.0.0`, `/spiffy/payment/1.0.0`)
- **SPV validation:** BEEF transaction verification, Merkle proof validation
- **Storage:** PostgreSQL with structured schema for wallets, UTXOs, transactions, invoices
- **Subscription plans:** Rate limiting and access tiers for service consumers
- **API:** Protobuf-defined service interface, suitable for gRPC or REST gateway
- **Testing:** 135+ tests across wallet, SPV, and protocol modules

**Role in architecture:** Phase 2 (Wallet Infrastructure) — provides the standard wallet plumbing (HD keys, UTXO management, transaction broadcasting, SPV validation). In sidecar configuration, it runs alongside the Jmix application server and handles all blockchain I/O.

**Gap:** No awareness of TSL1 token triplets (PP1+PP2+PP3 as a logical unit). Tracks UTXOs generically — needs token-aware indexing on top.

### spiffynode (Dart)

A complete BSV P2P networking library. Provides:

- Full wire protocol implementation (version, verack, inv, getdata, tx, block, headers, ping/pong, reject, etc.)
- Peer discovery and management (DNS seeds, manual peers, connection pooling)
- SPV header chain tracking and validation
- Block and transaction relay
- 303+ tests

**Role in architecture:** Phase 3 (Coordination Layer) — provides the network transport layer for peer-to-peer communication. Could serve as the foundation for direct P2P transaction proposal delivery between wallets.

**Alternative role:** Could replace go-spiffy's networking layer if a pure-Dart stack is preferred, but go-spiffy's wallet management features would still be needed.

### spiffywallet (Dart)

A wallet sidecar service with a libp2p-based protocol. Provides:

- **Two modes:** Receive-only (xpub — watch addresses, no signing) and Full (xpriv — sign and broadcast)
- **Actor-based architecture:** Isolated actors for wallet operations, message-driven concurrency
- **libp2p protocol:** Peer-to-peer communication for wallet coordination
- **Invoice creation:** Payment request generation and tracking
- **BEEF/SPV validation:** Transaction verification without full node
- **Storage:** PostgreSQL-backed persistent state

**Role in architecture:** Phase 2/3 overlap — wallet operations (Phase 2) with built-in peer coordination (Phase 3). The xpub/xpriv split maps well to the merchant (full mode) vs. customer (receive-only mode for lightweight mobile wallets) distinction.

**Relationship to go-spiffy:** Functional overlap in wallet management. spiffywallet is Dart-native (shares language with tstokenlib), while go-spiffy is Go (shares language with nothing else in the stack but offers production maturity and sidecar isolation).

### BSV TS-SDK (TypeScript)

The official BSV Blockchain TypeScript SDK. Built from scratch with **zero dependencies**, designed for both browser and Node.js environments. Provides:

- **Transaction building:** Construction, signing, verification, serialisation, fee computation, change output generation
- **Script interpreter:** Network-compliant script execution and validation
- **Script templates:** Pluggable locking/unlocking script templates (P2PKH built-in, custom templates supported)
- **Cryptography:** Key generation, ECDSA signatures, hash functions — all pure TypeScript, no native modules
- **Key management:** PrivateKey, PublicKey, Address, HD key derivation
- **SPV structures:** Serialisable SPV verification, Merkle proof handling
- **Broadcasting:** Transaction broadcast to miners and overlay networks
- **Browser-native:** Compiles to JavaScript, runs in any browser without polyfills or WASM

**Role in architecture:** Client-side token **transaction construction** for web-based use cases. With TSL1 templates, the TS-SDK can build complete token transactions in the browser — the same JSON template substitution that works in Java works identically in TypeScript. This enables:

- **E-commerce checkout widgets** — construct token transactions (voucher redemption, loyalty stamp, RFT payment) in the browser, then request signing from the customer's mobile wallet
- **Token explorer** — browser-based script parsing and state display without server round-trips
- **POS web terminals** — browser-based POS that constructs token transactions, customer signs via QR code scan on their mobile app
- **Customer dashboard (web)** — view tokens, review proposals — signing delegated to mobile wallet via backchannel or QR

**Important distinction:** The TS-SDK handles transaction *construction* and *verification* in the browser. Customer *signing* is biased toward the mobile wallet app (see [Signing Architecture](#signing-architecture)). The browser constructs the unsigned transaction and presents it for mobile signing — it does not hold private keys.

**Key advantage over wallet-toolbox:** The TS-SDK is a full BSV primitives library (transactions, scripts, keys, verification), not just a wallet abstraction. Combined with TSL1 templates, it provides everything needed to construct token transactions client-side and verify signatures returned from the mobile wallet.

### wallet-toolbox (TypeScript)

A BRC-100 compliant wallet toolkit from the BSV Blockchain team. Provides:

- Persistent storage for wallet state
- Protocol-based key derivation
- Wallet signer components
- Modular architecture (client, mobile, core)

**Role in architecture:** Optional layer on top of the BSV TS-SDK for applications that need persistent browser-side wallet state (key storage, UTXO caching, transaction history). Most TSL1 use cases can operate without it — the Jmix REST API manages wallet state server-side, and the browser only needs the TS-SDK for transaction construction and signing.

---

## Architecture Mapping

### Phase 1: Protocol Completion

| Need | Component | Fit |
|---|---|---|
| Script generators for RNFT, RFT, AT, SM | **tstokenlib** | Direct — extend existing patterns |
| Lock/unlock builders | **tstokenlib** | Direct — extend existing patterns |
| Transaction tool APIs | **tstokenlib** | Direct — extend `TokenTool`/`FungibleTokenTool` |
| Script interpreter testing | **dartsv** (dependency of tstokenlib) | Direct — `Interpreter.correctlySpends()` |

**Assessment:** No external components needed. Phase 1 is purely tstokenlib work in Dart.

### Phase 2: Wallet Infrastructure

| Need | Component | Fit |
|---|---|---|
| HD key management | **go-spiffy** or **spiffywallet** | Both provide BIP32 HD wallets |
| UTXO tracking | **go-spiffy** | PostgreSQL-backed UTXO management |
| Token triplet discovery | **Custom** (on top of go-spiffy) | go-spiffy tracks generic UTXOs; token-aware indexing is new |
| Sighash preimage computation | **Bitcoin4J** | BIP-143 sighash serialisation is standard BSV — Bitcoin4J already computes this |
| Transaction building (standard BSV parts) | **go-spiffy** + **Bitcoin4J** | go-spiffy for sidecar ops, Bitcoin4J for Jmix-side construction |
| Transaction building (token scripts) | **Bitcoin4J** + **TSL1 Templates** | Template substitution produces the locking scripts; Bitcoin4J assembles the transaction |
| Unlock script assembly | **Custom** (Java, on Bitcoin4J) | Stack ordering per operation spec — straightforward implementation |
| Co-signing support | **Custom** | Partial signature assembly is token-specific |
| SPV validation | **go-spiffy** | BEEF/SPV validation built in |

**Assessment:** go-spiffy provides ~60% of the wallet infrastructure. The remaining 40% — token triplet tracking, co-signing, token-specific transaction assembly — is now implementable **directly in Java** using the TSL1 templates and Bitcoin4J. No cross-language bridge needed for script construction.

**Key insight:** The language-agnostic templates eliminate the Dart dependency for script generation. The Jmix/Java layer can construct complete token transactions by combining Bitcoin4J (standard BSV primitives) with template substitution (token locking scripts). go-spiffy remains the blockchain I/O layer (UTXO tracking, broadcasting, SPV).

### Phase 3: Coordination Layer

| Need | Component | Fit |
|---|---|---|
| Transaction proposal protocol | **Custom** (new protobuf messages) | Define proposal/response/completion message types |
| Messaging transport (relay) | **go-spiffy** libp2p | Already has peer-to-peer messaging infrastructure |
| Async store-and-forward | **go-spiffy** invoice system (partial) | Invoice model is close to a proposal model — extend it |
| Discovery & addressing | **Custom** | QR codes, deep links, payment handles — application-layer concern |
| Push notifications | **Jmix** (notification add-on) | Jmix has built-in notification support |

**Assessment:** go-spiffy's libp2p transport and invoice system provide the messaging backbone. The transaction proposal protocol is a new message type layered on top of the existing protobuf definitions. spiffynode could serve as an alternative transport for direct P2P delivery, but the relay model (go-spiffy sidecar) is more practical for async workflows.

### Phase 4: Token Lifecycle Service

| Need | Component | Fit |
|---|---|---|
| Template library (12 pre-configured token templates) | **Jmix** entities + **TSL1 Templates** | Jmix stores business configs; TSL1 JSON templates produce the scripts via substitution |
| Token registry (indexed, queryable) | **Jmix** JPA entities | Purpose-built for this — entities, data grids, filtering, row-level security |
| Batch operations (mint, settle, timeout) | **Jmix** + **go-spiffy** | Jmix orchestrates batches; go-spiffy broadcasts transactions |
| Webhook & event system | **Jmix** (BPM/events add-on) | Jmix supports event-driven architecture and webhooks |
| Audit logging | **Jmix** (built-in) | Entity audit with change tracking is a core Jmix feature |

**Assessment:** This is Jmix's sweet spot. The Token Lifecycle Service is a classic line-of-business application — entities with CRUD, role-based access, batch processing, event hooks, and audit trails. Jmix delivers 80%+ of this out of the box. The remaining work is connecting Jmix to the blockchain layer via go-spiffy's API and the TSL1 templates for script construction — both accessible directly from Java without cross-language dependencies.

### Phase 5: Business Integration

| Need | Component | Fit |
|---|---|---|
| REST API | **Jmix** (auto-generated) | REST endpoints with authentication, rate limiting — built in |
| Admin dashboard | **Jmix** (Vaadin UI) | Data grids, forms, role-based screens — built in |
| POS SDK | **Custom** (Android/iOS) | Thin client calling the Jmix REST API |
| E-commerce plugins (Shopify, WooCommerce) | **Custom** (JavaScript) | Thin wrappers calling the Jmix REST API |
| Accounting & compliance export | **Jmix** (reports add-on) | Report generation from JPA entities — built in |

**Assessment:** Jmix again covers the core. The REST API, admin dashboard, and reporting are standard Jmix deliverables. POS and e-commerce integrations are thin clients that consume the REST API — they don't depend on Jmix's framework, only its API contract.

### Phase 5.5: Client-Side Web Integration

| Need | Component | Fit |
|---|---|---|
| Browser transaction construction | **BSV TS-SDK** + **TSL1 Templates** | TS-SDK builds transactions; templates provide token scripts via substitution |
| E-commerce checkout widget | **BSV TS-SDK** + **TSL1 Templates** | Construct token transaction in browser, request mobile signing |
| POS web terminal | **BSV TS-SDK** + **TSL1 Templates** | Build tx in browser, customer approves via QR on mobile |
| Co-sign approval | **Mobile wallet app** | Customer reviews proposal on mobile, signs, returns signature |
| Signing protocol library | **Custom** (TypeScript + Dart) | Published as npm + pub package for third-party integrators |

**Assessment:** The BSV TS-SDK + TSL1 templates handle transaction *construction* in the browser. Customer *signing* is delegated to the mobile wallet app via the signing protocol (see [Signing Architecture](#signing-architecture)). This separation means web integrations never handle private keys — they construct unsigned transactions and present them for mobile approval.

### Phase 6: Explorer & Audit Tools

| Need | Component | Fit |
|---|---|---|
| Token explorer (web) | **BSV TS-SDK** + **TSL1 Templates** | Browser-based script parsing and state display; TS-SDK's script interpreter can validate scripts client-side |
| Customer dashboard (web) | **BSV TS-SDK** + Jmix REST API | TS-SDK for wallet operations; Jmix API for token state queries |
| Customer dashboard (mobile) | **Flutter** + **tstokenlib** | Dart-native, full protocol access |
| Verification tool (CLI/web) | **tstokenlib** (Dart CLI) or **BSV TS-SDK** (web) | Commitment hash reconstruction — standard SHA256 in any language |
| Analytics dashboard (merchant) | **Jmix** (Vaadin UI + reports) | Aggregate views, charts, filtering — Jmix data grids with analytics |

**Assessment:** The TS-SDK replaces wallet-toolbox as the browser-side foundation. Combined with TSL1 templates, it provides full token script construction and validation in the browser. Jmix handles server-side state and analytics. Flutter handles mobile.

---

## Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Business Layer (Jmix)                        │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  Template     │  │   Token      │  │   Batch      │              │
│  │  Library      │  │   Registry   │  │   Operations │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  REST API    │  │   Webhooks   │  │   Reports &  │              │
│  │  (auto-gen)  │  │   & Events   │  │   Audit      │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│                                                                     │
│  Vaadin UI: Admin Dashboard, Merchant Analytics, Template Config    │
│  Security: Roles, Row-Level, API Keys                               │
│                                                                     │
│  ┌──────────────────────────────────────────────────┐               │
│  │  Token Service (Java)                             │              │
│  │  Bitcoin4J for tx building + signing              │              │
│  │  TSL1 Templates (JSON) for token script assembly  │              │
│  │  No external Dart dependency at runtime           │              │
│  └──────────────────────────────────────────────────┘               │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ protobuf / gRPC
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Wallet Sidecar (go-spiffy)                       │
│                                                                     │
│  HD Wallets │ UTXO Management │ Invoice/Proposals │ SPV Validation  │
│  libp2p Transport │ PostgreSQL │ Payment-Gated Access               │
│  Transaction Broadcasting │ BEEF Verification                       │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ BSV P2P
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      BSV Network                                    │
└─────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────┐
│                  Development / Build Environment                    │
│                                                                     │
│  ┌──────────────────────────────────────────────────┐               │
│  │  tstokenlib (Dart)                                │              │
│  │  Canonical protocol source + script interpreter   │              │
│  │                                                   │              │
│  │  dart run tool/export_templates.dart               │              │
│  │       │                                           │              │
│  │       ▼                                           │              │
│  │  templates/*.json  ──► published as build artifact │              │
│  │                        consumed by Jmix at deploy  │              │
│  └──────────────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────┐
│              Consumer-Facing Layer (Browser — No Keys)               │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  Token       │  │  POS / Web / │  │  Customer    │              │
│  │  Explorer    │  │  E-Commerce  │  │  Dashboard   │              │
│  │  (Web)       │  │  Plugins     │  │  (Web)       │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│                                                                     │
│  BSV TS-SDK + TSL1 Templates for tx construction & verification     │
│  tsl1-signing (npm) for signing request construction & QR encoding  │
│  Jmix REST API for coordination and state queries                   │
│  CONSTRUCTS unsigned transactions — NEVER holds private keys        │
└───────────────────────┬────────────────────┬────────────────────────┘
                        │                    │
            backchannel │                    │ front-channel
          (push + REST) │                    │ (QR code)
                        ▼                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Mobile Wallet (Flutter — Keys Live Here)                │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  Key Mgmt    │  │  Approval    │  │  Token       │              │
│  │  (Keychain/  │  │  UX          │  │  Portfolio   │              │
│  │   Keystore)  │  │  (review +   │  │  (state,     │              │
│  │              │  │   sign)      │  │   history)   │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│                                                                     │
│  tstokenlib (Dart-native, full protocol access)                     │
│  spiffywallet (HD wallets, UTXO tracking)                           │
│  tsl1_signing (pub.dev) for signing request parsing & approval      │
│  Push notifications (FCM/APNs) + QR scanner for signing requests    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Language Bridge Analysis

### The Problem (Revisited)

The original challenge was that tstokenlib (Dart) is the only component that can construct token scripts, while the business platform (Jmix) is Java. This appeared to force either a Dart microservice, a Java port, or abandoning Jmix.

### The Solution: Language-Agnostic Templates

The TSL1 script templates in `templates/` fundamentally resolve this tension. The templates contain **pre-compiled, hex-encoded Bitcoin scripts** with simple `{{param}}` placeholders. Any language that can parse JSON and do string replacement can construct valid token locking scripts.

This means the Dart → Java bridge is **not a runtime dependency** — it's a **build-time artifact**. The Dart codebase generates the templates once (`dart run tool/export_templates.dart`). Java consumes them as static resources. No Dart process needs to run in production.

### What Remains Language-Specific

The templates handle **locking script construction** (the hardest part — ~37.5 KB PP3 scripts, ~18 KB PP1 scripts). The remaining token operations are algorithmically straightforward and can be implemented in any language from the archetype specifications:

| Operation | Complexity | Implementation Approach |
|---|---|---|
| **Locking script construction** | High (solved by templates) | JSON load + string substitution |
| **Unlock script (scriptSig) assembly** | Medium | Stack items in specified order per operation — follows spec |
| **Sighash preimage computation** | Medium | BIP-143 serialisation — Bitcoin4J already handles this |
| **Token state extraction** | Low | Read bytes at known offsets from raw script hex |
| **Commitment hash chain** | Low | `SHA256(prevHash \|\| SHA256(sig \|\| eventData))` — standard SHA256 |
| **Transaction topology assembly** | Medium | 5/6/7-output construction — follows spec, uses Bitcoin4J |

### Recommended Architecture (Option E: Jmix + Templates — No Dart in Production)

```
Jmix (Java) ──direct──► TSL1 Templates (JSON) + Bitcoin4J ──produces──► complete token transactions
Jmix (Java) ──gRPC────► go-spiffy (Go)                     ──broadcasts──► transactions, manages UTXOs
```

- **Jmix** owns everything above the blockchain: business logic, templates, registry, REST API, admin UI, and **token script construction** (via templates + a thin Java service layer using Bitcoin4J)
- **go-spiffy** owns blockchain I/O: UTXO management, transaction broadcasting, SPV validation
- **tstokenlib** remains the canonical source and **test environment** — protocol development, script optimisation, and interpreter-verified testing happen in Dart. Templates are regenerated and published as a build artifact whenever the protocol changes.
- **Flutter/spiffywallet** owns the consumer mobile experience (shares Dart with tstokenlib for full protocol access)

**Two services in production instead of three.** The Dart microservice is eliminated entirely. Jmix + go-spiffy is the complete server-side stack.

### What This Changes

| Previous Assessment | Revised Assessment |
|---|---|
| tstokenlib microservice required (Dart) | **Eliminated** — templates replace runtime Dart dependency |
| 3 services to deploy (Jmix + Dart + go-spiffy) | **2 services** (Jmix + go-spiffy) |
| Cross-language bridge = high risk | **Low risk** — bridge is a static JSON file, not a network call |
| Protocol changes require microservice API update | Protocol changes require template regeneration (one command) |
| Co-signing spans 3 languages | Co-signing spans **2 languages** (Java + Go) |
| Script generation is a runtime bottleneck | Script generation is a **string replacement** — microseconds |
| Browser apps need server for script construction | **Browser-native** — BSV TS-SDK + templates build token tx client-side |
| Bitcoin4J is a third-party dependency | **Owned** — being aligned to dartsv parity, full control over roadmap |
| Browser holds keys (XSS risk) | **Mobile-only keys** — browser constructs, mobile signs |

---

## Signing Architecture

### Design Principle: Keys Live on Mobile

The architecture biases toward **client-side key management within a mobile wallet app**. Browser-based surfaces (e-commerce widgets, POS web terminals, customer dashboards) construct unsigned transactions but **never hold private keys**. Signing is always performed on the customer's mobile device, where keys are protected by platform-native secure storage (iOS Keychain, Android Keystore).

This creates a clean separation of concerns:

| Environment | Responsibility | Keys? |
|---|---|---|
| **Jmix server** | Business logic, token registry, coordination, merchant signing | Merchant keys (server-managed) |
| **Browser** (TS-SDK) | Transaction construction, proposal display, verification | No keys — constructs unsigned tx |
| **Mobile app** (Flutter) | Customer key management, signing, approval UX | Customer keys (device-managed) |

### Signing Protocol

Two channels for engaging the mobile wallet:

#### Backchannel (Push-Based)

For asynchronous or remote interactions where the customer is not physically present:

```
1. Browser/Server constructs unsigned transaction
2. Server stores proposal (Jmix) and sends push notification to customer's mobile
3. Mobile app retrieves proposal, displays human-readable summary:
   "Merchant XYZ is confirming milestone 3 of your funnel"
   "Redeem voucher at Store ABC — value: 50 tokens"
4. Customer reviews and approves on mobile → app signs with device-held key
5. Signed transaction (or partial signature for co-sign) returned to server
6. Server assembles final transaction and broadcasts via go-spiffy
```

**Transport:** Push notification (FCM/APNs) for the alert, Jmix REST API for proposal retrieval and signature submission. Alternatively, go-spiffy's libp2p for direct mobile-to-server P2P delivery.

**Use cases:** E-commerce checkout (customer on laptop, signs on phone), settlement approval, batch co-sign operations, any scenario where the customer is not at the same physical location as the merchant's device.

#### Front-Channel (QR-Based)

For in-person interactions where the customer is physically present:

```
1. POS/terminal constructs unsigned transaction
2. POS displays QR code encoding the signing request:
   - Transaction hash (or full unsigned tx for small transactions)
   - Proposal metadata (human-readable description)
   - Callback URL or relay endpoint for signature return
3. Customer scans QR with mobile wallet app
4. App displays approval screen with transaction details
5. Customer approves → app signs and submits signature to callback/relay
6. POS receives signature, assembles final transaction, broadcasts
```

**Transport:** QR code for the request, HTTP callback or relay for the response. For NFC-capable devices, the QR scan step can be replaced with a tap.

**Use cases:** POS loyalty stamp, in-store voucher redemption, event check-in, face-to-face co-signing.

### Signing Request Format

A standardised signing request message that both channels use:

```json
{
  "version": 1,
  "type": "sign_request",
  "proposal_id": "uuid",
  "operation": "confirm_milestone",
  "token_id": "hex",
  "description": "Confirm milestone 3 of 5 — Campaign: Summer Loyalty",
  "unsigned_tx": "hex (serialised unsigned transaction)",
  "sighash_preimage": "hex (for the input requiring customer signature)",
  "input_index": 0,
  "callback": "https://merchant.example.com/api/sign/callback/{proposal_id}",
  "expires": "2026-03-15T12:00:00Z"
}
```

The mobile wallet app verifies the sighash preimage matches the unsigned transaction, displays the human-readable `description` and `operation`, and produces the ECDSA signature over the sighash.

### Signing Protocol Library

The signing protocol is expressed as a **library for third-party development**, published in two forms:

| Package | Language | Contents |
|---|---|---|
| **tsl1-signing** (npm) | TypeScript | Signing request construction, QR encoding, callback handling, transaction assembly after signature receipt |
| **tsl1_signing** (pub.dev) | Dart | Signing request parsing, approval UX helpers, signature production, sighash verification |

**The TypeScript package** is used by third-party web integrators (e-commerce plugins, POS terminals, custom web apps). It handles the "requester" side — constructing signing requests, encoding them as QR codes, and assembling the final transaction after receiving the signature.

**The Dart package** is used by the mobile wallet app (and any third-party wallet that wants to support TSL1 tokens). It handles the "signer" side — parsing signing requests, verifying sighash preimages, presenting approval UX, and producing signatures.

### Reference Mobile App

A **Flutter reference implementation** demonstrates the complete signer experience:

- Key generation and secure storage (iOS Keychain / Android Keystore)
- Token portfolio view (via Jmix REST API for state, go-spiffy for UTXO data)
- Push notification handling for backchannel signing requests
- QR scanner for front-channel signing requests
- Approval screen with human-readable transaction summary
- Signature production and submission
- Transaction history and audit trail

The reference app uses **tstokenlib** directly (Dart-native) for full protocol access — token state parsing, commitment hash verification, script validation. It also uses **spiffywallet** for wallet management (HD keys, UTXO tracking).

Third-party wallet developers can integrate TSL1 token support by importing the `tsl1_signing` Dart package without depending on the full tstokenlib — the signing protocol is self-contained.

---

## Component Gap Analysis

### What the Components Provide

| Architecture Layer | Coverage | Primary Component |
|---|---|---|
| Protocol (scripts, builders, lifecycle APIs) | **95%** | tstokenlib (Dart, build-time) |
| Token script construction (any language) | **90%** | TSL1 Templates (JSON) |
| Standard wallet (HD keys, UTXOs, SPV, broadcast) | **90%** | go-spiffy |
| P2P networking (wire protocol, peer management) | **85%** | spiffynode / go-spiffy libp2p |
| Business application (entities, REST, UI, security) | **80%** | Jmix |
| BSV transaction building (Java-side) | **90%** | Bitcoin4J (owned, dartsv-aligned) + TSL1 Templates |
| BSV transaction building (browser) | **90%** | BSV TS-SDK + TSL1 Templates |

### What Must Be Built

| Gap | Effort | Description |
|---|---|---|
| **Token-aware UTXO indexing** | Medium | Extend go-spiffy's UTXO model to recognise PP1 script headers, link triplets (PP1+PP2+PP3), and extract token state. This is the highest-value custom work. |
| **Java token service layer** | Medium | Java classes that load TSL1 templates, substitute parameters, assemble unlock scripts, and build token transaction topologies using Bitcoin4J. This replaces the Dart microservice. |
| **Jmix token entities** | Medium | JPA entities for Token, Template, Campaign, TokenEvent. Jmix scaffolding accelerates this. |
| **Transaction proposal protocol** | Medium | New protobuf message types for propose/accept/reject/complete. Layered on go-spiffy's libp2p. |
| **Signing protocol library** | Medium | TypeScript (npm) + Dart (pub.dev) packages. Request construction, QR encoding, sighash verification, signature assembly. The glue between web surfaces and mobile wallet. |
| **Co-signing flow** | Medium | Built on the signing protocol. Backchannel (push + REST) and front-channel (QR) paths. Sighash preimage via Bitcoin4J (server) or TS-SDK (browser). |
| **Settlement transaction builder** | Medium | 7-output topology construction. Bitcoin4J builds all outputs (P2PKH from native API, token scripts from templates). Single-language assembly. |
| **Reference mobile wallet app** | High | Flutter app with tstokenlib + spiffywallet + tsl1_signing. Key management, approval UX, QR scanner, push notification handling. |
| **Token explorer** | Medium | Web frontend reading from a blockchain indexer. Standard web development. |
| **POS SDK** | Low-Medium | Thin client calling Jmix REST API. QR scanning, NFC — platform-standard. |
| **E-commerce plugins** | Low | JavaScript wrappers calling Jmix REST API. Shopify/WooCommerce boilerplate. |

---

## Risk Assessment

### Medium Risk

**Template-to-production correctness.** The templates are generated from Dart and consumed by Java. If the Java token service layer misinterprets a parameter encoding (e.g., Category B pushdata prefixes, le_uint56 encoding), the resulting scripts will be invalid. **Mitigation:** Build a cross-language test suite: generate test vectors in Dart (known-good scripts with specific parameters), verify that the Java template substitution produces byte-identical output. This is a one-time effort per archetype.

**go-spiffy token awareness.** go-spiffy is a general-purpose BSV wallet. Making it token-aware (triplet tracking, state extraction) requires modifications to a Go codebase while the token byte layouts are specified in the archetype docs. **Recommendation:** Keep go-spiffy generic for UTXO management. Build token interpretation (triplet linking, state extraction) in the Jmix/Java layer, which queries go-spiffy for raw UTXOs and applies token-aware filtering in Java where the template parameter offsets are already known.

**Signing protocol UX friction.** The mobile-signing model adds a step compared to browser-native signing: the customer must switch to their mobile app (or scan a QR code) to approve. For high-frequency, low-value operations (loyalty stamps at every purchase), this friction could reduce adoption. **Mitigation:** The mobile app can support "trusted merchant" mode — pre-approve a merchant for specific operations (e.g., "auto-approve loyalty stamps from Store ABC for the next 30 days"). This preserves the security model (keys on mobile, approval on mobile) while reducing friction for routine interactions. The signing protocol library exposes a `trust_grant` message type for this pattern.

### Low Risk

**Protocol-business bridge complexity (downgraded from High).** With templates, the Dart-Java bridge is a static JSON file, not a network call. Protocol changes require running `dart run tool/export_templates.dart` and redeploying the templates — the same workflow as updating any static configuration. The Java-Go bridge (Jmix → go-spiffy) remains, but this is a standard protobuf/gRPC boundary with well-understood operational characteristics.

**Jmix fit for purpose.** Jmix is well-suited for the Token Lifecycle Service and Business Integration layers. The main risk is over-reliance on Jmix's code generation for domain logic that needs careful hand-tuning (e.g., batch settlement with atomic guarantees). **Mitigation:** Use Jmix for CRUD, security, UI, and REST. Write critical business logic (batch operations, settlement orchestration) as plain Spring services within the Jmix application.

**Bitcoin4J maturity (downgraded from previous assessment).** Bitcoin4J is owned and actively maintained with a clear roadmap to reach dartsv parity. Once aligned, Bitcoin4J's script interpreter will match dartsv's behaviour, enabling full Java-side script validation — not just template-based construction. This eliminates the risk of interpreter divergence and makes the Java token service layer self-sufficient for both construction and validation. Token script construction comes from templates; validation can be cross-checked against both Bitcoin4J (Java) and dartsv (Dart) interpreters.

---

## Deployment Topology

```
┌─────────────────────────────────────────┐
│            Application Server           │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Jmix App (Java/JVM)             │  │
│  │  Port 8080                        │  │
│  │                                   │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  Token Service Layer        │  │  │
│  │  │  Bitcoin4J + TSL1 Templates │  │  │
│  │  │  (in-process, no network)   │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────┬───────────────────────┘  │
│              │ protobuf / gRPC           │
│  ┌───────────┴───────────────────────┐  │
│  │  go-spiffy sidecar (Go binary)    │  │
│  │  Port 9000                        │  │
│  └───────────┬───────────────────────┘  │
│              │                           │
│  ┌───────────┴───────────────────────┐  │
│  │  PostgreSQL                       │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

Two services in production. The token service layer runs inside the Jmix JVM — it's a set of Spring beans that load JSON templates from the classpath and use Bitcoin4J for transaction construction. No separate process, no network hop for script generation. go-spiffy manages wallet state in PostgreSQL. Jmix manages business state in its own database (or a separate schema in the same PostgreSQL instance).

---

## Development Sequence

Given the component dependencies, the recommended build order:

```
Quarter 1                    Quarter 2                    Quarter 3
─────────────────────────    ─────────────────────────    ─────────────────────────
Phase 1: Protocol            Phase 2: Wallet              Phase 4: Lifecycle Service
(tstokenlib, Dart)           (go-spiffy integration,      (Jmix application,
                              token UTXO indexing)          template library,
Template export for new                                     token registry)
archetypes (RNFT, RFT,      Phase 3: Coordination
AT, SM)                      (signing protocol lib,        Phase 5: Business Integration
                              proposal protocol,           (REST API, POS SDK,
Java token service layer      co-signing flow)              e-commerce plugins,
(Bitcoin4J + templates,                                     tsl1-signing npm package)
cross-language test vectors) Reference mobile wallet
                             (Flutter, tsl1_signing)
Bitcoin4J dartsv alignment
                                                          Quarter 4
                                                          ─────────────────────────
                                                          Phase 6: Explorer & Audit
                                                          (web frontend, analytics)
```

Phase 1 and template export can proceed immediately. The Java token service layer can start in parallel once the first templates are available. The signing protocol library and reference mobile wallet are Q2 deliverables — they depend on the wallet infrastructure (Phase 2) but can be designed in Q1 alongside protocol work. Bitcoin4J alignment with dartsv is continuous Q1-Q2 work.

---

## Verdict

The proposed component mix is **feasible and architecturally clean**. The language-agnostic templates resolve the central tension (Dart protocol library vs. Java business platform) by turning the Dart-Java bridge from a runtime dependency into a build-time artifact.

**What works well:**
- **TSL1 templates eliminate the Dart microservice** — Java constructs token scripts directly via JSON substitution. Two production services instead of three.
- **The same templates work in the browser** — BSV TS-SDK + TSL1 templates enable client-side token transaction construction for e-commerce, POS, and customer-facing web apps. No server round-trip for script generation.
- **Bitcoin4J is owned and being aligned with dartsv** — once at parity, Java gets full script interpreter validation, making the server-side token service layer self-sufficient for both construction and validation.
- **Three BSV libraries with shared DNA** — dartsv (Dart), Bitcoin4J (Java), and BSV TS-SDK (TypeScript) cover all three runtime environments. TSL1 templates are the common contract that ensures all three produce identical scripts.
- **Jmix** dramatically accelerates the business application layers (Phases 4-5) — this is exactly what it's built for
- **go-spiffy** provides production-grade wallet infrastructure without building from scratch
- **tstokenlib** remains the canonical source and test environment — protocol changes flow through template regeneration
- **Flutter** (Dart) enables code sharing between protocol library and mobile app, with full tstokenlib access

**What requires care:**
- **Cross-language test vectors** are essential — Dart generates known-good scripts; Java and TypeScript must produce byte-identical output from template substitution. This is the correctness guarantee across three languages.
- **Token-aware UTXO indexing** is the single most important piece of custom infrastructure
- **Unlock script assembly** must be implemented in both Java (server) and TypeScript (browser), following the archetype specs — the templates handle locking scripts, but scriptSig construction is hand-coded per operation
- **Signing protocol UX** — the mobile-signing model must be low-friction for routine operations. "Trusted merchant" auto-approval mode is critical for high-frequency use cases like loyalty stamps.

**What could be dropped:**
- **wallet-toolbox** — the BSV TS-SDK provides the full primitives layer; wallet-toolbox is optional for persistent browser wallet state
- **spiffynode** — go-spiffy's libp2p handles server-side P2P. spiffynode may be useful for the Flutter mobile app's direct BSV peer connectivity, but this is a later concern

**The simplest viable path:** Jmix (with in-process token service layer using Bitcoin4J + TSL1 templates) + go-spiffy sidecar for the server. BSV TS-SDK + TSL1 templates + tsl1-signing for the browser. Flutter + tstokenlib + tsl1_signing for the mobile wallet. Two server-side services, two client-side libraries (npm + pub.dev), templates as the universal contract, mobile app as the signing authority.
