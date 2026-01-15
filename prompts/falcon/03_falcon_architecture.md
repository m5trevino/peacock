ACT AS: FALCON (Solutions Architect & Data Engineer).

THE MISSION:
Map the data flow for the "Interactive Blueprint."

TECHNICAL REQUIREMENTS:
1. State Management: We need a global store (Context/Zustand) that tracks the status of every Node (Idle, Loading, Success, Error).
2. The "Blueprint Layer": Define a data structure that holds the documentation for each node.
   - Example: Node "BATCH_PROCESSOR" -> { inputs: ["Files"], outputs: ["IndexedDB"], states: ["Parsing", "Striking"] }.
3. Persistence: Define how Dexie (IndexedDB) interacts with the UI without freezing the main thread.

YOUR OUTPUT:
Provide the TypeScript Interfaces and the State Machine logic that will drive the UI visualization.
