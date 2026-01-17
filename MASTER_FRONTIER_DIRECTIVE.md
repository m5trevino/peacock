# 💀 PEACOCK FRONTIER V26.2: UNIFIED VISUAL & TACTICAL SPEC

**TARGET:** React 19 / Tailwind / Framer Motion Implementation
**VIBE:** 2027 Industrial Cyberpunk / High-Stakes Casino

---

## 1. THE SURFACE DOCTRINE (THE LOOK)
*   **The Void:** Background is `#050505` with a fixed `1px` high-density grid overlay.
*   **Tactical Glass:** All panels use `bg-void/80` with `backdrop-blur-md`. 
*   **The Chasing Light:** Primary action buttons MUST have a `conic-gradient` border animation that "chases" around the perimeter when the component is ready.
*   **Typography:** Strict **JetBrains Mono**. Text never fades; it uses a **Descramble** effect (random characters cycling until they lock).

---

## 2. THE SEQUENTIAL CHAMBER (THE FLOW)
*   **Single-Mission Focus:** The HUD only renders the active Bird's card (Spark, Falcon, etc.). 
*   **MiniMap Locking:** When a stage completes, its icon in the top MiniMap transforms into a **Solid Matrix Green (#00FF41)** tile with a permanent `20px` neon glow.
*   **The Snap:** New mission cards must **Snap** into the center pane with a mechanical jolt (use `type: "spring", stiffness: 500`).

---

## 3. TACTICAL UPGRADES (THE MECHANICS)

### A. THE SAFETY SWITCH RITUAL
*   **Constraint:** The `EXECUTE STRIKE` button is disabled by default.
*   **Mechanism:** Replace the standard toggle with a **Safety Cover**. To arm the strike, the user must perform a "Slide-to-Unlock" or a specific sequential interaction on the Payload and Prompt seals. 
*   **Feedback:** When armed, the border turns from dim grey to **Pulsing Voltage Yellow**.

### B. THE CONTEXT VU METER
*   **Visual:** A vertical analog-style gauge next to the Model Picker.
*   **Logic:** Tracks `payloadSize / modelContextWindow`. 
*   **States:** 
    *   0-60%: Steady Green.
    *   61-85%: Vibrating Yellow.
    *   86-100%: Redlining (needle shakes violently).
    *   >100%: The Execute button sparks Red and locks out.

### C. SEMANTIC AURAS
*   Each bird has a signature glow frequency that tints the background grid:
    *   **SPARK:** Deep Electric Blue.
    *   **FALCON:** Royal Purple.
    *   **EAGLE:** Industrial Orange.
    *   **OWL/HAWK:** Matrix Green.

### D. THE DATA GHOST (PIXEL EVAPORATION)
*   **Transition:** When a bird completes, its text/data "evaporates" into tiny green pixels.
*   **Motion:** These pixels travel along the SVG Neural Path to the MiniMap node, zip to the next bird, and then "rain down" to form the next interface.

### E. THE ARTIFACT VAULT (THE REVEAL)
*   **Trigger:** Post-Jackpot (Hawk Completion).
*   **Visual:** The Left Archive Rail fans out like a hand of winning cards.
*   **Effect:** Each file (`App.tsx`, etc.) has a holographic foil glimmer that reacts to the mouse position.

---

## 4. THE NERVE CENTER (LIVE CLI)
*   **Idle:** 20px green line at the bottom.
*   **Strike:** Flares to 30% screen height with **CRT Scanlines**.
*   **Dual-Core View:**
    *   **LEFT:** Outbound (Wrapped Prompt).
    *   **RIGHT:** Inbound (Real-time Raw Token Stream).

---

**FINAL INSTRUCTION TO IMPLEMENTER:** 
Everything must feel **Heavy, Machined, and Expensive.** If a component feels like a "standard web app," it is a failure of logic. Execute.
