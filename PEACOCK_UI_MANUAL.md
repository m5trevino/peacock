# 💀 PEACOCK: VISUAL DOCTRINE & UX GUIDE
**STYLE:** HIGH-STAKES CASINO / MILITARY HUD
**PALETTE:** #050505 (VOID), #00FF41 (MATRIX), #FFD700 (VOLTAGE)

---

## 1. GLOBAL PHYSICS (ANIMATION)
*   **No Fading:** Things do not "fade in." They **DESCRAMBLE** (Matrix text effect) or **SLIDE** (Mechanical insertion).
*   **Tension:** While processing, lines and borders must **VIBRATE** (x: -1, x: 1 loop) to show engine stress.
*   **Release:** Upon success, the UI **FLASHES WHITE** (100ms) and plays a `click_latch.mp3` sound.

## 2. COMPONENT STYLING

### **A. The Mind Map (Top Pane)**
*   **Visual:** SVG Nodes connected by "Laser Lines."
*   **Behavior:**
    *   *Idle:* Dim Green opacity 0.3.
    *   *Active:* Bright Yellow, pulsing line width (1px to 3px).
    *   *Success:* Solid Neon Green. "Data Packet" dot travels the line.

### **B. The Nerve Center (Bottom Console)**
*   **Style:** CRT Terminal. Scanline overlay (`pointer-events-none`).
*   **Typography:** `JetBrains Mono`. Glow effect (`text-shadow: 0 0 5px #00FF41`).
*   **Behavior:** Auto-scrolls to bottom.

### **C. The Tactical Flyout (Settings)**
*   **Transition:** `transform: translateX(100%)` to `0%`.
*   **Speed:** Instant (Type: Spring, Stiffness: 300).
*   **Glass:** Background `rgba(10, 10, 10, 0.95)` with `backdrop-filter: blur(10px)`.

### **D. The "Jackpot"**
*   **Trigger:** All stages complete.
*   **Effect:**
    *   Background flashes Green (opacity 0.1).
    *   Center Text: "SEQUENCE COMPLETE" descrambles.
    *   Border: Running ants animation turns solid.

---

## 3. ASSET LIST
*   `fonts/JetBrainsMono-Bold.ttf`
*   `sounds/mechanical_latch.mp3`
*   `sounds/turbine_hum.mp3`
*   `images/peacock_logo_matrix.png`
