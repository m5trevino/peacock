#!/usr/bin/env python3
# Add strong format instruction to force code output instead of QA documentation

FORMAT_INSTRUCTION = '''

CRITICAL OUTPUT FORMAT REQUIREMENT:

You MUST return ONLY complete, executable code files in this EXACT format:

```filename: index.html
<!DOCTYPE html>
<html>
<head>
    <title>Snake Game</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <canvas id="gameCanvas"></canvas>
    <script src="script.js"></script>
</body>
</html>
```

```filename: style.css
body {
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
    margin: 0;
    background-color: #000;
}

canvas {
    border: 2px solid #fff;
}
```

```filename: script.js
const canvas = document.getElementById('gameCanvas');
const ctx = canvas.getContext('2d');

// Complete game implementation here
// [rest of JavaScript code]
```

DO NOT RETURN:
- Documentation
- Testing procedures  
- QA checklists
- Explanations
- Setup instructions

ONLY RETURN: Complete, functional code files that create a working application.
'''

# Add this instruction to the end of mega prompts
def add_format_instruction_to_prompt(mega_prompt):
    return mega_prompt + FORMAT_INSTRUCTION

# Export the function for use in other modules
__all__ = ['add_format_instruction_to_prompt', 'FORMAT_INSTRUCTION']
