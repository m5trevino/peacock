ACT AS FALCON, a Senior Solution Architect with deep expertise in Localhost-First Web Applications.

YOUR MISSION: Transform the provided FUNCTIONAL SPECIFICATIONS (Spark) into a concrete, production-ready TECHNICAL ARCHITECTURE.

SOURCE SPECIFICATIONS:
"""
### REQUIREMENTS SPECIFICATION: PEACOCK | THE STRIKE ORCHESTRATOR (V21.3 OMEGA)

#### 1. EXECUTIVE SUMMARY
A localhost-first, Matrix-themed React SPA that turns a static dashboard into a state-aware “Neural Journey,” orchestrating single-shot or 500-file batch AI strikes through a six-state branching machine while guaranteeing sub-200 ms UI feedback and crash-proof browser storage.

#### 2. SYSTEM CLASSIFICATION
*   **Type:** Web App (SPA)
*   **Complexity:** High
*   **Primary Constraint:** Must run offline-first on MX Linux localhost with zero server-side dependencies

#### 3. FUNCTIONAL REQUIREMENTS (The "Must-Haves")
**FR-01 Identity Node**
*   *Input:* None (auto-load)
*   *Process:* Randomly pick 1 of 7 peacock*.png assets; render in top-left
*   *Output:* 128×128 px avatar + “Support the Mission” donation link + GitHub repo link

**FR-02 Command HUD**
*   *Input:* User clicks “Start Over”, “Settings”, or “About”
*   *Process:* “Start Over” wipes IndexedDB vaults and returns to IDLE; “Settings” opens modal for API-key entry; “About” opens static markdown overlay
*   *Output:* Modal or confirmation toast

**FR-03 Stage Button Bar**
*   *Input:* User clicks one of five stage buttons (N, S, F, E, H)
*   *Process:* State machine transitions to MODE_SELECTION; SVG neural path grows from button to split-node
*   *Output:* Active button glows; neural line animated (≤300 ms)

**FR-04 Mode Split Node**
*   *Input:* User clicks MANUAL or BATCH
*   *Process:* State machine transitions to CONSOLE_SETUP or FACTORY_FLOOR
*   *Output:* Dual-console dropzone or batch ingest perimeter appears

**FR-05 Manual Console**
*   *Input:* File drop or browse; optional text paste
*   *Process:* Validate MIME (txt, md, json, pdf, docx); compute SHA-256 hash; stream to nexusIn store
*   *Output:* Immutable “Master Protocol” pane + editable “Phase Payload” pane

**FR-06 Wrap Prompt**
*   *Input:* User clicks WRAP
*   *Process:* Merge Master + Payload; inject header “### NEXUS RESPONSE ###”; compress to Blob
*   *Output:* Strategic Review Editor in full-width mode; state = STRATEGIC_REVIEW

**FR-07 Strike Authorization**
*   *Input:* User clicks STRIKE
*   *Process:* POST to API Gateway with retry/back-off; stream response to Live CLI flare; update card status
*   *Output:* SUCCESS | FAILURE badge; audio ping; state = HOMING_RETRACTION

**FR-08 Homing Retraction**
*   *Input:* Strike completes
*   *Process:* Animate card scale 1→0 and translate back into parent button; button turns Matrix Green
*   *Output:* State = AUTO-HANDSHAKE; neural line auto-extends to next stage

**FR-09 Auto-Handshake**
*   *Process:* Copy output payload to next stage’s input store; auto-focus next button
*   *Output:* Toast: “Handed off to SPARK”

**FR-10 Batch Ingest**
*   *Input:* 1–500 files dragged
*   *Process:* Throttle to 25 concurrent; queue remainder; render sliding window
*   *Output:* Progress cards with QUEUED → STRIKING → SUCCESS; overall ETA timer

**FR-11 Dossier Export**
*   *Input:* Batch completes
*   *Process:* Stream all result blobs into JSZip; name files <original>.<stage>.json
*   *Output:* Single .zip download via native Blob URL

**FR-12 Archive Rail**
*   *Input:* User clicks rail tab (N|S|F|E|H)
*   *Process:* Drawer slides 40 % width; query IndexedDB for stage records; sort desc timestamp
*   *Output:* Paginated list; click to preview; red-lock edit requires typing “modify this data”

**FR-13 Live CLI Flare**
*   *Input:* Any stdout/stderr from API calls
*   *Process:* Append to 30 vh terminal; auto-scroll; limit buffer to 10 000 lines
*   *Output:* Monospace JetBrains Mono; Matrix green; 1 Hz blinking cursor

**FR-14 Neural Path Engine**
*   *Input:* DOM rect of active button and open window
*   *Process:* Compute cubic Bezier curve; re-calc on resize (debounce 100 ms)
*   *Output:* SVG path with 2 px Tactical Blue stroke; glow filter; animate via stroke-dashoffset

**FR-15 State Machine**
*   *States:* IDLE, MODE_SELECTION, CONSOLE_SETUP, STRATEGIC_REVIEW, HOMING_RETRACTION, AUTO-HANDSHAKE
*   *Transitions:* Triggered by user clicks or async job completion; persisted to IndexedDB for crash recovery

#### 4. NON-FUNCTIONAL REQUIREMENTS
**NFR-01 Performance**
*   First paint ≤ 500 ms on localhost
*   UI feedback (click→visual change) ≤ 200 ms
*   Batch throughput ≥ 5 files/s on 4-core, 8 GB machine

**NFR-02 Security**
*   API keys stored only in localStorage; never hit network except over HTTPS
*   All file parsing in Web Workers; no eval()
*   Confirm header “### SPARK RESPONSE ###” added before clipboard write

**NFR-03 Reliability**
*   Graceful degradation if IndexedDB unavailable (fallback to RAM + sessionStorage)
*   Retry failed API calls with exponential back-off (max 3 attempts)
*   Crash recovery: on reload, restore last known state machine state

**NFR-04 Visual Fidelity**
*   CRT scanline overlay at 60 % opacity; 8 px text glow; color accuracy ΔE < 3 vs spec

#### 5. DATA REQUIREMENTS
*   *Entities:* User, Stage, File, Strike, Log, API_Key, Preference
*   *Persistence:* All entities except API_Key live in IndexedDB; survive refresh and browser restart

#### 6. CRITICAL USER FLOWS
**Flow A: Manual Strike**
User clicks NEXUS → selects MANUAL → drops file → clicks WRAP → edits → clicks STRIKE → watches CLI → sees Homing Retraction → auto-advances to SPARK

**Flow B: Batch Factory**
User drags 500 files → system throttles → cards update → audio pings → [DOWNLOAD .ZIP] appears → user saves dossier

**Flow C: Archive Edit**
User clicks [N] rail → clicks red lock → types “modify this data” → edits JSON → clicks SAVE → change persisted

#### 7. GAP ANALYSIS & ASSUMPTIONS
*   *Missing Info:* Exact API rate limits, max payload size, retry policy
*   *Assumption:* Groq/Google/Mistral/DeepSeek impose 8 MB payload, 60 req/min; retry stops after 3 attempts
*   *Missing Info:* Accessibility compliance level
*   *Assumption:* WCAG 2.1 AA sufficient
*   *Missing Info:* i18n requirements
*   *Assumption:* English only for V21.3

SPARK ANALYSIS COMPLETE. READY FOR FALCON ARCHITECTURE.
"""

OPERATIONAL RULES (NON-NEGOTIABLE):

1.  **STACK ENFORCEMENT:** You must architect for this specific stack:
    *   **Runtime:** React 19 + Vite (TypeScript).
    *   **Styling:** Tailwind CSS (Utility-first, "Anti-Vibe" aesthetic).
    *   **Persistence:** Dexie.js (IndexedDB wrapper) for the "Tactical Vault".
    *   **State Management:** React Context + Custom Hooks (No Redux/Zustand unless critical).
    *   **Animation:** Framer Motion (for the "Homing Retraction").

2.  **NO HALLUCINATION:** Do not invent features not listed in the Spark Spec. If Spark says "Batch 500 files," you must architect a "Sliding Window" hook, not a server-side queue.

3.  **ASCII DIAGRAMS:** You must provide clean, high-fidelity ASCII diagrams for:
    *   The Data Flow (File -> Processing -> DB).
    *   The Component Tree (Layout -> Stage -> Nodes).

4.  **SECURITY FIRST:** Explicitly define how API keys are handled (LocalStorage vs Memory) and how the "Red Lock" mechanism works in code logic.

OUTPUT STRUCTURE (STRICT MARKDOWN):

### TECHNICAL ARCHITECTURE: [Project Name]

#### 1. SYSTEM CONTEXT
*   **Architecture Style:** (e.g., Local-First SPA)
*   **Core Dependencies:** List the exact `package.json` libs required.

#### 2. HIGH-LEVEL DESIGN (ASCII)
*   *Diagram:* The "Neural Journey" flow from a systems perspective.

#### 3. COMPONENT ARCHITECTURE
*   **Layout Layer:** (HUD, Rail, CLI)
*   **Stage Layer:** (Nexus, Spark, etc. - Polymorphic components?)
*   **Logic Layer:** (Custom Hooks breakdown: `useJourney`, `useBatch`, `useVault`)

#### 4. DATA ARCHITECTURE (SCHEMA)
*   **Dexie Schema:** Define the exact tables and indexes.
    *   `nexusIn`: ++id, timestamp, ...
    *   `nexusOut`: ...
*   **State Models:** TypeScript interfaces for the "Neural Path" coordinates.

#### 5. SECURITY & COMPLIANCE
*   **Key Management:** The `useSecrets` hook logic.
*   **Sanitization:** How file inputs are scrubbed before injection.

#### 6. IMPLEMENTATION ROADMAP
*   **Phase 1:** Skeleton & Routing.
*   **Phase 2:** The Database Layer.
*   **Phase 3:** The Visual Engine (SVG).
*   **Phase 4:** The Batch Factory.

FINAL INSTRUCTION:
End your response with: "FALCON ARCHITECTURE LOCKED. READY FOR EAGLE IMPLEMENTATION."
