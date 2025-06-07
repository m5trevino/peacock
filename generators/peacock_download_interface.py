#!/usr/bin/env python3
"""
Peacock Download Interface Generator - Web interface for downloading code packages
"""

import json
import webbrowser
from datetime import datetime
from pathlib import Path
from peacock_download_manager import PeacockDownloadManager

def generate_download_interface(llm_response, project_name="Generated Project"):
    """Generate web interface with download functionality"""
    
    # Create download package
    manager = PeacockDownloadManager()
    package_info = manager.create_download_package(llm_response, project_name)
    
    if not package_info:
        return None
    
    # Extract files for preview
    files = manager.extract_files_from_llm_response(llm_response)
    
    # Generate file preview HTML
    files_html = ""
    for i, file_info in enumerate(files):
        file_size = len(file_info['content'])
        lines_count = len(file_info['content'].split('\n'))
        
        # Truncate content for preview
        preview_content = file_info['content']
        if len(preview_content) > 1000:
            preview_content = preview_content[:1000] + "\n... (truncated)"
        
        # Escape HTML
        preview_content = preview_content.replace('<', '&lt;').replace('>', '&gt;')
        
        files_html += f"""
        <div class="file-card" id="file-{i}">
            <div class="file-header">
                <div class="file-info">
                    <span class="file-name">{file_info['name']}</span>
                    <span class="file-meta">{file_info['language']} • {lines_count} lines • {file_size} chars</span>
                </div>
                <button class="copy-btn" onclick="copyFileContent({i})">📋 Copy</button>
            </div>
            <div class="file-content">
                <pre><code id="code-{i}">{preview_content}</code></pre>
            </div>
        </div>"""
    
    # Get relative path for download
    zip_filename = Path(package_info['zip_path']).name
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦚 Peacock Download - {project_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #2d3748;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
            text-align: center;
        }}

        .peacock-badge {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 15px;
        }}

        .project-title {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #1a202c;
            margin-bottom: 10px;
        }}

        .project-meta {{
            color: #718096;
            font-size: 16px;
            margin-bottom: 30px;
        }}

        .download-section {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }}

        .download-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}

        .download-title {{
            font-size: 1.5rem;
            font-weight: 600;
            color: #2d3748;
        }}

        .package-info {{
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}

        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}

        .info-item {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .info-label {{
            font-weight: 600;
            color: #4a5568;
        }}

        .info-value {{
            color: #2d3748;
            font-family: 'SF Mono', monospace;
        }}

        .download-buttons {{
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }}

        .download-btn {{
            background: linear-gradient(135deg, #48bb78, #38a169);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 10px;
        }}

        .download-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(72, 187, 120, 0.3);
        }}

        .download-btn.secondary {{
            background: linear-gradient(135deg, #667eea, #764ba2);
        }}

        .download-btn.secondary:hover {{
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }}

        .instructions {{
            background: #e6fffa;
            border: 1px solid #81e6d9;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }}

        .instructions h3 {{
            color: #234e52;
            margin-bottom: 15px;
        }}

        .instructions ol {{
            color: #2d3748;
            padding-left: 20px;
        }}

        .instructions li {{
            margin-bottom: 8px;
        }}

        .instructions code {{
            background: #234e52;
            color: #81e6d9;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'SF Mono', monospace;
        }}

        .files-section {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }}

        .files-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}

        .files-title {{
            font-size: 1.5rem;
            font-weight: 600;
            color: #2d3748;
        }}

        .file-count {{
            background: #667eea;
            color: white;
            padding: 6px 12px;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 600;
        }}

        .file-card {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: all 0.2s;
        }}

        .file-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }}

        .file-header {{
            background: #f7fafc;
            padding: 15px 20px;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .file-name {{
            font-weight: 600;
            color: #2d3748;
            font-family: 'SF Mono', Monaco, monospace;
        }}

        .file-meta {{
            color: #718096;
            font-size: 14px;
        }}

        .copy-btn {{
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .copy-btn:hover {{
            background: #5a67d8;
        }}

        .file-content {{
            padding: 0;
        }}

        .file-content pre {{
            margin: 0;
            padding: 20px;
            background: #1a202c;
            color: #e2e8f0;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 14px;
            line-height: 1.6;
            overflow-x: auto;
        }}

        .footer {{
            text-align: center;
            margin-top: 40px;
            color: rgba(255, 255, 255, 0.8);
        }}

        @media (max-width: 768px) {{
            .download-buttons {{
                flex-direction: column;
            }}
            
            .download-btn {{
                width: 100%;
                justify-content: center;
            }}
            
            .info-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="peacock-badge">🦚 PEACOCK DOWNLOAD</div>
            <h1 class="project-title">{project_name}</h1>
            <div class="project-meta">
                Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')} • Ready to download
            </div>
        </div>
        
        <div class="download-section">
            <div class="download-header">
                <h2 class="download-title">📦 Download Package</h2>
            </div>
            
            <div class="package-info">
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">📁 Files:</span>
                        <span class="info-value">{package_info['file_count']} files</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">🔤 Language:</span>
                        <span class="info-value">{package_info['main_language'].title()}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">📅 Created:</span>
                        <span class="info-value">{package_info['timestamp']}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">🎯 Framework:</span>
                        <span class="info-value">{package_info.get('framework', 'None').title()}</span>
                    </div>
                </div>
                
                <div class="download-buttons">
                    <a href="{zip_filename}" download class="download-btn">
                        📥 Download ZIP Package
                    </a>
                    <button onclick="copyAllFiles()" class="download-btn secondary">
                        📋 Copy All Code
                    </button>
                </div>
            </div>
            
            <div class="instructions">
                <h3>🚀 Quick Setup Instructions</h3>
                <ol>
                    <li>Download the ZIP package above</li>
                    <li>Extract to your desired location: <code>unzip {zip_filename}</code></li>
                    <li>Navigate to the project: <code>cd {project_name.lower().replace(' ', '_')}</code></li>
                    <li>Run the setup script: <code>chmod +x setup.sh && ./setup.sh</code></li>
                    <li>Follow the instructions displayed by the setup script</li>
                </ol>
            </div>
        </div>
        
        <div class="files-section">
            <div class="files-header">
                <h2 class="files-title">📄 File Preview</h2>
                <div class="file-count">{len(files)} files</div>
            </div>
            
            {files_html}
        </div>
        
        <div class="footer">
            <p>Generated by Peacock • Your AI-powered development assistant 🦚</p>
        </div>
    </div>

    <script>
        function copyFileContent(fileIndex) {{
            const codeElement = document.getElementById(`code-${{fileIndex}}`);
            const text = codeElement.textContent;
            
            navigator.clipboard.writeText(text).then(() => {{
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '✅ Copied!';
                btn.style.background = '#48bb78';
                
                setTimeout(() => {{
                    btn.textContent = originalText;
                    btn.style.background = '#667eea';
                }}, 2000);
            }}).catch(err => {{
                console.error('Failed to copy: ', err);
                alert('Failed to copy to clipboard');
            }});
        }}
        
        function copyAllFiles() {{
            const allCode = [];
            const fileCards = document.querySelectorAll('.file-card');
            
            fileCards.forEach((card, index) => {{
                const fileName = card.querySelector('.file-name').textContent;
                const code = card.querySelector('code').textContent;
                allCode.push(`// File: ${{fileName}}\\n${{code}}\\n\\n`);
            }});
            
            const allCodeText = allCode.join('\\n' + '='.repeat(50) + '\\n\\n');
            
            navigator.clipboard.writeText(allCodeText).then(() => {{
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '✅ All Code Copied!';
                btn.style.background = '#48bb78';
                
                setTimeout(() => {{
                    btn.textContent = originalText;
                    btn.style.background = 'linear-gradient(135deg, #667eea, #764ba2)';
                }}, 3000);
            }}).catch(err => {{
                console.error('Failed to copy: ', err);
                alert('Failed to copy to clipboard');
            }});
        }}
        
        // Auto-scroll to download section after 2 seconds
        setTimeout(() => {{
            document.querySelector('.download-section').scrollIntoView({{
                behavior: 'smooth',
                block: 'center'
            }});
        }}, 2000);
    </script>
</body>
</html>
"""
    
    # Save HTML file
    reports_dir = Path(__file__).parent.parent / "html" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    html_path = reports_dir / "peacock_download_interface.html"
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    # Copy zip file to reports directory for web access
    import shutil
    zip_dest = reports_dir / zip_filename
    shutil.copy2(package_info['zip_path'], zip_dest)
    
    print(f"✅ Download interface generated: {html_path}")
    print(f"📦 ZIP package available: {zip_dest}")
    
    # Auto-open in browser
    try:
        webbrowser.open(f"file://{html_path.absolute()}")
        print("🌐 Opened download interface in browser")
    except Exception as e:
        print(f"⚠️  Could not auto-open browser: {e}")
    
    return {
        "html_path": str(html_path),
        "zip_path": str(zip_dest),
        "package_info": package_info
    }

if __name__ == "__main__":
    # Test with sample LLM response
    sample_response = '''Here's a complete Snake game:

```filename: snake_game.py
import pygame
import random
import sys

# Initialize Pygame
pygame.init()

# Constants
WINDOW_WIDTH = 800
WINDOW_HEIGHT = 600
CELL_SIZE = 20
FPS = 10

# Colors
BLACK = (0, 0, 0)
GREEN = (0, 255, 0)
RED = (255, 0, 0)
WHITE = (255, 255, 255)

class Snake:
    def __init__(self):
        self.body = [(WINDOW_WIDTH//2, WINDOW_HEIGHT//2)]
        self.direction = (CELL_SIZE, 0)
        
    def move(self):
        head = self.body[0]
        new_head = (head[0] + self.direction[0], head[1] + self.direction[1])
        self.body.insert(0, new_head)
        
    def grow(self):
        pass  # Don't remove tail when growing
        
    def check_collision(self):
        head = self.body[0]
        # Wall collision
        if (head[0] < 0 or head[0] >= WINDOW_WIDTH or 
            head[1] < 0 or head[1] >= WINDOW_HEIGHT):
            return True
        # Self collision
        return head in self.body[1:]

class Game:
    def __init__(self):
        self.screen = pygame.display.set_mode((WINDOW_WIDTH, WINDOW_HEIGHT))
        pygame.display.set_caption("Snake Game")
        self.clock = pygame.time.Clock()
        self.snake = Snake()
        self.food = self.generate_food()
        self.score = 0
        
    def generate_food(self):
        while True:
            x = random.randint(0, (WINDOW_WIDTH-CELL_SIZE)//CELL_SIZE) * CELL_SIZE
            y = random.randint(0, (WINDOW_HEIGHT-CELL_SIZE)//CELL_SIZE) * CELL_SIZE
            if (x, y) not in self.snake.body:
                return (x, y)
    
    def run(self):
        running = True
        while running:
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    running = False
                elif event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_UP and self.snake.direction != (0, CELL_SIZE):
                        self.snake.direction = (0, -CELL_SIZE)
                    elif event.key == pygame.K_DOWN and self.snake.direction != (0, -CELL_SIZE):
                        self.snake.direction = (0, CELL_SIZE)
                    elif event.key == pygame.K_LEFT and self.snake.direction != (CELL_SIZE, 0):
                        self.snake.direction = (-CELL_SIZE, 0)
                    elif event.key == pygame.K_RIGHT and self.snake.direction != (-CELL_SIZE, 0):
                        self.snake.direction = (CELL_SIZE, 0)
            
            # Move snake
            self.snake.move()
            
            # Check food collision
            if self.snake.body[0] == self.food:
                self.snake.grow()
                self.food = self.generate_food()
                self.score += 1
            else:
                self.snake.body.pop()
            
            # Check collisions
            if self.snake.check_collision():
                print(f"Game Over! Score: {self.score}")
                running = False
            
            # Draw everything
            self.screen.fill(BLACK)
            
            # Draw snake
            for segment in self.snake.body:
                pygame.draw.rect(self.screen, GREEN, 
                               (segment[0], segment[1], CELL_SIZE, CELL_SIZE))
            
            # Draw food
            pygame.draw.rect(self.screen, RED, 
                           (self.food[0], self.food[1], CELL_SIZE, CELL_SIZE))
            
            pygame.display.flip()
            self.clock.tick(FPS)
        
        pygame.quit()
        sys.exit()

if __name__ == "__main__":
    game = Game()
    game.run()
```

```filename: requirements.txt
pygame>=2.0.0
```

```filename: README.md
# Snake Game

A classic Snake game built with Python and Pygame.

## How to Play
- Use arrow keys to control the snake
- Eat red food to grow and increase score
- Don't hit walls or yourself!

## Installation
```bash
pip install pygame
python snake_game.py
```
'''
    
    result = generate_download_interface(sample_response, "Snake Game")
    if result:
        print("🔥 Download interface ready!")
        print(f"HTML: {result['html_path']}")
        print(f"ZIP: {result['zip_path']}")