{
  `title`: `STYLING BLOCK - CUT/PASTE READY`,
  `folder`: `peacock-debug`,
  `content`: `# 🎨 STYLING BLOCK - SAFE TO CUT/PASTE
# This entire block can be removed for debugging and pasted back when fixed
# START VISUAL BLOCK - SAFE TO DELETE
# ================================================================================

def show_cyberpunk_ascii():
    \"\"\"Show the sick ASCII art section\"\"\"
    chess_border = f\"{CyberStyle.NEON_CYAN}♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄‍‌♞▀▄▀▄♝▀▄ ♞▀▄▀▄♝▀▄‍‌♞▀▄▀▄♝▀▄{CyberStyle.RESET}\"
    
    print(f\"{chess_border}\")
    print(\"░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░\")
    print(\"░░█░░░███░░████░░██░░████░░██░░████░█░░█░░█░░\")
    print(\"░░ ░░░█  █░█   ░█  █░█   ░█  █░█   ░█░░█░░ ░░\")
    print(\"░░░░░░███ ░███░░████░█░░░░█░░█░█░░░░███ ░░░░░\")
    print(\"░░░░░░█  ░░█  ░░█  █░█░░░░█░░█░█░░░░█  █░░░░░\")
    print(\"░░░░░░█░░░░████░█░░█░████░ ██ ░████░█░░█░░░░░\")
    print(\"░░░░░░ ░░░░    ░ ░░ ░    ░░  ░░    ░ ░░ ░░░░░\")
    print(\"░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░\")
    print(f\"{chess_border}\
\")

def show_uniform_box(message: str, icon: str = \"\"):
    \"\"\"Show uniform cyberpunk box\"\"\"
    print(f\"╔═══════════════════════════════════════════════╗\")
    print(f\"{icon} {message}\")
    print(f\"╚═══════════════════════════════════════════════╝\")

def show_init_box():
    \"\"\"Show initialization box\"\"\"
    print(f\"╔════════════════════════════════════╗\")
    print(f\"⚡ Initializing Peacock MCP Server...\")
    print(f\"╚════════════════════════════════════╝\")

def show_config_box():
    \"\"\"Show configuration box\"\"\"
    print(f\"╔═════════════════════════════════════════════════════════════╗\")
    print(f\"   ♔ Primary Model: {PEACOCK_MODEL_STRATEGY['primary_model']}\")
    print(f\"   ♖ Speed Model: {PEACOCK_MODEL_STRATEGY['speed_model']}\")
    print(f\"   📊 Logging: {'Enabled' if LOGGING_ENABLED else 'Disabled'}\")
    print(f\"   👉 Session: {SESSION_TIMESTAMP}\")
    print(f\"╚═════════════════════════════════════════════════════════════╝\")

def show_stage_box(stage_name: str, message: str, icon: str = \"\"):
    \"\"\"Show stage progress box\"\"\"
    print(f\"┌──═━┈━═─────────┐\")
    print(f\"{icon} {stage_name}: {message}\")
    print(f\"└──═━┈━═─────────┘\")

def show_result_box(stage_name: str, message: str, icon: str = \"\"):
    \"\"\"Show result box\"\"\"
    print(f\"┌──═━┈━═──┐\")
    print(f\"{icon} {stage_name} - {message}\")
    print(f\"└──═━┈━═──┘\")

def show_character_count_summary(stage_results: dict):
    \"\"\"Show character count summary with sick formatting\"\"\"
    print(f\"\
STAGE CHARACTER COUNTS:\")
    print(f\"┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━»•» 🌺 «•«━━━━┑\")
    
    stage_icons = {\"spark\": \"⚡\", \"falcon\": \"👉\", \"eagle\": \"🐦\", \"hawk\": \"♔\"}
    
    for stage_name, stage_data in stage_results.items():
        char_count = stage_data.get(\"char_count\", 0)
        model = stage_data.get(\"model\", \"unknown\")
        icon = stage_icons.get(stage_name.lower(), \"🔥\")
        print(f\"{icon}  {stage_name.upper():7}: {char_count:4} chars {model}\")
    
    print(f\"┕━━━━━»•» 🌺 «•«━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙\")

# CYBERPUNK STYLING SYSTEM
class CyberStyle:
    RESET = '\\033[0m'
    BOLD = '\\033[1m'
    DIM = '\\033[2m'
    
    # CYBERPUNK COLORS
    NEON_GREEN = '\\033[92m'
    NEON_CYAN = '\\033[96m'
    NEON_PURPLE = '\\033[95m'
    NEON_YELLOW = '\\033[93m'
    NEON_RED = '\\033[91m'
    MATRIX_GREEN = '\\033[32m'
    ELECTRIC_BLUE = '\\033[94m'
    HOT_PINK = '\\033[35m'

# MASSIVE CYBERPUNK CFONTS ARSENAL - THE FULL EXPERIENCE!
CYBERPUNK_CFONTS = [
    # Gradient combinations (the sickest ones)
    \"cfonts 'PEACOCK' -f pallet -g yellow,red\",
    \"cfonts 'PEACOCK' -f slick -g green,cyan\", 
    \"cfonts 'PEACOCK' -f shade -g red,magenta\",
    \"cfonts 'PEACOCK' -f simple3d -g cyan,magenta\",
    \"cfonts 'PEACOCK' -f simple -g blue,magenta\",
    \"cfonts 'PEACOCK' -f shade -g green,red\",
    \"cfonts 'PEACOCK' -f block -g red,blue\",
    \"cfonts 'PEACOCK' -f grid -g red,blue\",
    \"cfonts 'PEACOCK' -f slick -g yellow,red\",
    \"cfonts 'PEACOCK' -f shade -g green,cyan\",
    \"cfonts 'PEACOCK' -f chrome -g green,cyan\",
    \"cfonts 'PEACOCK' -f simple -g green,cyan\",
    \"cfonts 'PEACOCK' -f block -g red,yellow\",
    \"cfonts 'PEACOCK' -f block -g cyan,magenta\",
    \"cfonts 'PEACOCK' -f simple -g yellow,red\",
    \"cfonts 'PEACOCK' -f shade -g red,blue\",
    \"cfonts 'PEACOCK' -f slick -g red,yellow\",
    \"cfonts 'PEACOCK' -f grid -g magenta,yellow\",
    \"cfonts 'PEACOCK' -f pallet -g green,cyan\",
    \"cfonts 'PEACOCK' -f tiny -g red,blue\",
    \"cfonts 'PEACOCK' -f chrome -g red,yellow\",
    \"cfonts 'PEACOCK' -f simple3d -g blue,red\",
    \"cfonts 'PEACOCK' -f pallet -g magenta,cyan\",
    \"cfonts 'PEACOCK' -f grid -g green,yellow\",
    \"cfonts 'PEACOCK' -f slick -g blue,magenta\",
    \"cfonts 'PEACOCK' -f shade -g cyan,red\",
    \"cfonts 'PEACOCK' -f block -g green,blue\",
    \"cfonts 'PEACOCK' -f simple -g red,cyan\",
    \"cfonts 'PEACOCK' -f chrome -g yellow,magenta\",
    \"cfonts 'PEACOCK' -f tiny -g green,red\",
    
    # Transition combinations (smooth flows)
    \"cfonts 'PEACOCK' -f pallet -t yellow,red,magenta\",
    \"cfonts 'PEACOCK' -f slick -t green,cyan,blue\", 
    \"cfonts 'PEACOCK' -f shade -t red,magenta,blue\",
    \"cfonts 'PEACOCK' -f simple3d -t cyan,magenta,red\",
    \"cfonts 'PEACOCK' -f block -t blue,cyan,green\",
    \"cfonts 'PEACOCK' -f chrome -t green,yellow,red\",
    \"cfonts 'PEACOCK' -f grid -t red,yellow,magenta\",
    \"cfonts 'PEACOCK' -f simple -t magenta,cyan,blue\",
    \"cfonts 'PEACOCK' -f shade -t yellow,green,cyan\",
    \"cfonts 'PEACOCK' -f slick -t blue,magenta,red\",
    
    # Single color classics (when you want clean)
    \"cfonts 'PEACOCK' -f pallet -c cyan\",
    \"cfonts 'PEACOCK' -f slick -c blueBright\",
    \"cfonts 'PEACOCK' -f simple -c yellowBright\",
    \"cfonts 'PEACOCK' -f simple -c blue\",
    \"cfonts 'PEACOCK' -f simple -c green\",
    \"cfonts 'PEACOCK' -f block -c whiteBright\",
    \"cfonts 'PEACOCK' -f block -c blue\",
    \"cfonts 'PEACOCK' -f pallet -c cyanBright\",
    \"cfonts 'PEACOCK' -f grid -c yellow\",
    \"cfonts 'PEACOCK' -f slick -c whiteBright\",
    \"cfonts 'PEACOCK' -f chrome -c magenta\",
    \"cfonts 'PEACOCK' -f simple -c green\",
    \"cfonts 'PEACOCK' -f block -c red\",
    \"cfonts 'PEACOCK' -f shade -c cyan\",
    \"cfonts 'PEACOCK' -f simple3d -c blue\",
    \"cfonts 'PEACOCK' -f tiny -c green\",
    \"cfonts 'PEACOCK' -f chrome -c red\",
    \"cfonts 'PEACOCK' -f grid -c magenta\",
    \"cfonts 'PEACOCK' -f pallet -c yellow\",
    \"cfonts 'PEACOCK' -f slick -c green\",
    
    # Background combinations (the fire ones)
    \"cfonts 'PEACOCK' -f block -c white -b blue\",
    \"cfonts 'PEACOCK' -f simple -c yellow -b black\",
    \"cfonts 'PEACOCK' -f pallet -c cyan -b magenta\",
    \"cfonts 'PEACOCK' -f grid -c green -b red\",
    \"cfonts 'PEACOCK' -f chrome -c white -b cyan\",
    \"cfonts 'PEACOCK' -f shade -c blue -b yellow\",
    \"cfonts 'PEACOCK' -f slick -c red -b blue\",
    \"cfonts 'PEACOCK' -f simple3d -c magenta -b green\",
    
    # Size variations (huge impact)
    \"cfonts 'PEACOCK' -f huge -c cyan\",
    \"cfonts 'PEACOCK' -f massive -c red\",
    \"cfonts 'PEACOCK' -f tiny -c green\",
    
    # Special effects (the wild ones)
    \"cfonts 'PEACOCK' -f chrome -c rainbow\",
    \"cfonts 'PEACOCK' -f block -c candy\",
    \"cfonts 'PEACOCK' -f simple3d -c system\",
    
    # More gradient madness
    \"cfonts 'PEACOCK' -f pallet -g blue,cyan,green\",
    \"cfonts 'PEACOCK' -f slick -g red,yellow,green\",
    \"cfonts 'PEACOCK' -f shade -g magenta,blue,cyan\",
    \"cfonts 'PEACOCK' -f chrome -g yellow,red,magenta\",
    \"cfonts 'PEACOCK' -f grid -g green,blue,magenta\",
    \"cfonts 'PEACOCK' -f block -g cyan,yellow,red\"
]

# END VISUAL BLOCK - SAFE TO DELETE
# ================================================================================`
}
Response

Error calling tool 'write_note': 1 validation error for EntityResponse
observations.0.content
  Value should have at most 1000 items after validation, not 1494 [type=too_long, input_value='CYBERPUNK_CFONTS = [\n  ... -f tiny -g green,red",', input_type=str]
    For further information visit https://errors.pydantic.dev/2.11/v/too_long