# 💀 PEACOCK: VERIFIED LOGIC ARCHITECTURE
**VERSION:** 2.0 (CIRCUIT BOARD VERIFIED)
**TARGET:** REACT/ELECTRON PRODUCTION BUILD

---

## 1. THE CORE ENGINE (STATE MACHINE)
*   **The Chain:** The app must enforce a strict sequential flow: `INTEL -> SPARK -> FALCON -> EAGLE -> OWL -> HAWK`.
*   **State Locking:** A stage cannot be activated until the previous stage returns `STATUS: SUCCESS`.
*   **Data Persistence:**
    *   Uses `Dexie.js` (IndexedDB) to store the output of each stage.
    *   This ensures if the user refreshes, the "Chain" remains intact.

## 2. THE COMPONENT LOGIC

### **A. The Archive Rail (History)**
*   **Logic:** A vertical list mapping to the DB entries.
*   **Behavior:** Clicking a previous node (e.g., [S]park) loads that specific markdown file from IDB into the Preview Window.

### **B. The Manual Handshake (Air Gap)**
*   **Logic:**
    1.  User clicks "COPY PROMPT". System flags state `AWAITING_EXTERNAL`.
    2.  User pastes external text. System validates length > 0.
    3.  System saves text to DB as if it came from the API.
    4.  State updates to `SUCCESS`.

### **C. The Batch Factory (Sliding Window)**
*   **Logic:**
    *   Input: Array of File Objects.
    *   Process: `Promise.all` with a concurrency limit of 5.
    *   Error Handling: If 429, pause queue for 5000ms.
    *   Output: Zip file generation using `JSZip`.

### **D. The API Gateway**
*   **Logic:**
    *   Route `/v1/models` -> Fetch list.
    *   Route `/v1/strike` -> Streaming response handling.
    *   **Circuit Breaker:** If API fails 3 times, switch UI to "OFFLINE MODE" (Handshake only).

---

## 3. FILE STRUCTURE MAP
*   `src/stores/useJourney.ts` (Zustand/Context for Chain State)
*   `src/services/db.ts` (Dexie Schema)
*   `src/hooks/useBatch.ts` (Sliding Window Logic)
*   `src/api/gateway.ts` (Axios wrapper with Retry logic)
