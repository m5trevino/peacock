# PEACOCK V21: THE ARCHITECTURAL DOSSIER

## ⚡ THE COMMANDER'S INTEL
This document is the "Master Blueprint" for the Peacock V21 system. It maps the system from the inside out, rightside in, and top to bottom. If a new AI enters this cockpit, this is their first read.

---

## 🏗️ SYSTEM TOPOGRAPHY (PROJECT STRUCTURE)

### 📦 Root Files
- `index.tsx`: The primary mounting entry point.
- `index.html`: The HTML shell with Tailwind and Google Fonts.
- `scripts/iron_skeleton.ts`: **The Iron Skeleton**. The pure CLI logic reference for the engine strikes.
- `package.json`: Dependency list (React 19, Framer Motion, Axios).
- `vite.config.ts`: Alias/Env configuration.

### 🧩 Frontend (`/src`)
- `core/PeacockEngine.ts`: **The Brain**. Manages stages, payloads, and the strike logic.
- `config/protocols.ts`: **The Soul**. Contains the system prompts for Spark, Falcon, Eagle, Owl, and Hawk.
- `components/views/`:
  - `StageConsole.tsx`: The main cockpit for Spark, Falcon, and Eagle.
  - `OwlHangar.tsx`: The staging area for the one-file-at-a-time Owl strikes.
  - `SessionManager.tsx`: Handlers for session persistence.
- `components/layout/`:
  - `Header.tsx`: System status and Archive Vault access.
  - `FooterConsole.tsx`: Real-time token waterfall and payload mirror.
  - `IdentityNode.tsx`: Atomic components for the "Mind Map" phases.
- `components/ui/`: Tactical minimaps, custom dropdowns, VU meters, and overlays.
- `services/`: API gateway handles, audio loops, and database connectors.

### 🐍 Backend (`/ai-handler`)
- `app/main.py`: FastAPI entry point.
- `app/routes/strike.py`: The `/v1/strike` endpoint manager.
- `app/core/striker.py`: The logic that hits the model gateways (Moonshot, Gemini, etc.).

---

## 🔄 THE V21 PROTOCOL (LOGIC FLOW)

1. **SPARK (Requirements):** User inputs raw intel -> Spark generates a Functional Spec.
2. **FALCON (Architect):** Takes Spark's Spec -> Generates the File Structure Blueprint (Tree).
3. **EAGLE (Builder):** Takes Falcon's Tree -> Generates JSON Scaffolds (File Path + Skeleton + Directives).
4. **OWL (Executioner):** Takes Eagle's Scaffolds -> One-by-one file implementation.
5. **HAWK (QA):** Final verification and pass/fail audit.

---

## 🎨 THE UI DOCTRINE (EYES ONLY)

### The Mind Map Navigation (ACTIVE MISSION)
- **Current State:** A horizontal rail of phase icons. 
- **Target Logic:** Convert the rail into a tactical mind map where ONLY SPARK is active/pulsing at boot. Others are grayed out ghosts.
- **Success Flow:** On strike completion, the phase overlay closes. A tactical line "moves/draws" from the completed phase to the next. The next phase pulses and auto-opens.

### Semantic UI Elements
- **Stage Popups:** Nearly full-screen modal overlays. Closing them occurs on background/edge click.
- **Mini-Maps:** Sublime-style code previews for both current **Payload** and current **Prompt**.
- **Tactical Aesthetic:** ZERO solid "ugly" colors. All borders, buttons, and backgrounds use gradients, scanlines, and the Matrix/Voltage color palette.

---

## 🧪 THEMING SYSTEM (PLUGGABLE STYLE)
Theming is decoupled from React logic using **CSS Variables** defined in `index.css`. This allows for total visual control without risking a single line of functional code.

```css
:root {
  --color-primary: #00FF41; /* Matrix Green */
  --color-secondary: #FFD700; /* Voltage Gold */
  --surface-bg: rgba(5, 5, 5, 0.95);
  /* Add tactical theme tokens here */
}
```

---

## 🛡️ SAFETY ADVISORY
**NEVER** modify `PeacockEngine.ts` or `api.ts` when performing UI/UX refinements. All aesthetic changes should target CSS classes and global style tokens.
