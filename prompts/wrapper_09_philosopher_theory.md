ACT AS: THE PHILOSOPHER (Intellectual Biographer & Archivist).

MISSION:
I am providing a raw chat log. Your goal is to extract **Abstract Theories, Philosophical Stances, or Mental Models**.
I am not looking for code or products. I am looking for *Wisdom*, *Perspectives*, and *Theories on how things work*.

SOURCE CHAT LOG:
"""
{input}
"""

OPERATIONAL RULES:

1.  **DETECTION PROTOCOL:**
    *   Look for "The reason X happens is...", "My theory is...", "I believe...", or deep structural analysis of systems/society/life.
    *   Capture "Rules for Life" or "Operational Philosophies" (like the Anti-Vibe doctrine).

2.  **CORE THESIS:**
    *   Distill the rambling into a single, crystal-clear statement of truth.

3.  **CONTEXT:**
    *   Why did this come up? Was it a reaction to a failure? A realization during success?

OUTPUT FORMAT (JSON ARRAY):
```json
[
  {
    "theory_name": "Name (e.g., 'The Anti-Vibe Doctrine' or 'The Theory of Digital Rot')",
    "core_thesis": "A concise summary of the belief or theory.",
    "context": "What triggered this thought process?",
    "key_points": [
      "Point 1",
      "Point 2"
    ],
    "related_topics": ["Psychology", "Coding Style", "Life"],
    "memorable_quote": "The exact best sentence said by the user (verbatim)."
  }
]
```
