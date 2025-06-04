// Import XTerm.js from CDN in the HTML
// This file handles the terminal display and interaction

class XTermManager {
    constructor() {
        this.terminal = null;
        this.fitAddon = null;
        this.webLinksAddon = null;
        this.searchAddon = null;
        this.isInitialized = false;
        
        // Load XTerm.js from CDN
        this.loadXTermLibrary().then(() => {
            this.initializeTerminal();
        });
    }

    async loadXTermLibrary() {
        return new Promise((resolve, reject) => {
            // Check if already loaded
            if (window.Terminal) {
                resolve();
                return;
            }

            // Load XTerm CSS
            const css = document.createElement('link');
            css.rel = 'stylesheet';
            css.href = 'https://cdnjs.cloudflare.com/ajax/libs/xterm/5.3.0/xterm.min.css';
            document.head.appendChild(css);

            // Load XTerm JS
            const script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/xterm/5.3.0/xterm.min.js';
            script.onload = () => {
                // Load addons
                this.loadAddons().then(resolve);
            };
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    async loadAddons() {
        const addons = [
            'https://cdnjs.cloudflare.com/ajax/libs/xterm/5.3.0/addons/xterm-addon-fit.min.js',
            'https://cdnjs.cloudflare.com/ajax/libs/xterm/5.3.0/addons/xterm-addon-web-links.min.js',
            'https://cdnjs.cloudflare.com/ajax/libs/xterm/5.3.0/addons/xterm-addon-search.min.js'
        ];

        const loadPromises = addons.map(url => {
            return new Promise((resolve, reject) => {
                const script = document.createElement('script');
                script.src = url;
                script.onload = resolve;
                script.onerror = reject;
                document.head.appendChild(script);
            });
        });

        await Promise.all(loadPromises);
    }

    initializeTerminal() {
        const terminalElement = document.getElementById('terminal');
        if (!terminalElement || !window.Terminal) {
            console.error('Terminal element or XTerm library not found');
            return;
        }

        // Create terminal instance
        this.terminal = new Terminal({
            fontFamily: '"SF Mono", "Monaco", "Inconsolata", "Roboto Mono", monospace',
            fontSize: 14,
            lineHeight: 1.4,
            theme: {
                background: 'transparent',
                foreground: '#ffffff',
                cursor: '#00ff88',
                cursorAccent: '#ffffff',
                selection: 'rgba(0, 170, 255, 0.3)',
                black: '#1e1e2e',
                red: '#f38ba8',
                green: '#a6e3a1',
                yellow: '#f9e2af',
                blue: '#89b4fa',
                magenta: '#f5c2e7',
                cyan: '#94e2d5',
                white: '#cdd6f4',
                brightBlack: '#585b70',
                brightRed: '#f38ba8',
                brightGreen: '#a6e3a1',
                brightYellow: '#f9e2af',
                brightBlue: '#89b4fa',
                brightMagenta: '#f5c2e7',
                brightCyan: '#94e2d5',
                brightWhite: '#ffffff'
            },
            allowTransparency: true,
            cursorBlink: true,
            cursorStyle: 'block',
            scrollback: 10000,
            convertEol: true,
            screenKeys: true,
            useStyle: true,
            rightClickSelectsWord: true,
            macOptionIsMeta: true,
            macOptionClickForcesSelection: true
        });

        // Initialize addons
        if (window.FitAddon) {
            this.fitAddon = new FitAddon.FitAddon();
            this.terminal.loadAddon(this.fitAddon);
        }

        if (window.WebLinksAddon) {
            this.webLinksAddon = new WebLinksAddon.WebLinksAddon();
            this.terminal.loadAddon(this.webLinksAddon);
        }

        if (window.SearchAddon) {
            this.searchAddon = new SearchAddon.SearchAddon();
            this.terminal.loadAddon(this.searchAddon);
        }

        // Open terminal in DOM
        this.terminal.open(terminalElement);

        // Fit terminal to container
        if (this.fitAddon) {
            setTimeout(() => {
                this.fitAddon.fit();
            }, 100);
        }

        // Handle resize
        window.addEventListener('resize', () => {
            if (this.fitAddon) {
                this.fitAddon.fit();
            }
        });

        // Handle terminal events
        this.setupEventHandlers();

        this.isInitialized = true;
        console.log('🖥️ XTerm initialized successfully');
    }

    setupEventHandlers() {
        if (!this.terminal) return;

        // Handle data input
        this.terminal.onData((data) => {
            if (window.terminalManager && window.terminalManager.currentSession) {
                window.terminalManager.currentSession.write(data);
            }
        });

        // Handle selection for copy/paste
        this.terminal.onSelectionChange(() => {
            const selection = this.terminal.getSelection();
            if (selection) {
                // Store selection for context menu
                this.lastSelection = selection;
            }
        });

        // Handle key events
        this.terminal.onKey(({ key, domEvent }) => {
            // Ctrl+C copy behavior
            if (domEvent.ctrlKey && domEvent.key === 'c' && this.terminal.hasSelection()) {
                this.copySelection();
                domEvent.preventDefault();
                return false;
            }

            // Ctrl+V paste behavior
            if (domEvent.ctrlKey && domEvent.key === 'v') {
                this.pasteFromClipboard();
                domEvent.preventDefault();
                return false;
            }

            // Ctrl+F search
            if (domEvent.ctrlKey && domEvent.key === 'f') {
                this.openSearch();
                domEvent.preventDefault();
                return false;
            }

            // Escape to hide overlay
            if (domEvent.key === 'Escape') {
                const { ipcRenderer } = require('electron');
                ipcRenderer.send('hide-overlay');
                domEvent.preventDefault();
                return false;
            }
        });

        // Handle context menu
        this.terminal.element.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            this.showContextMenu(e.clientX, e.clientY);
        });

        // Handle paste events
        this.terminal.element.addEventListener('paste', (e) => {
            e.preventDefault();
            const text = e.clipboardData.getData('text');
            if (text && window.terminalManager && window.terminalManager.currentSession) {
                window.terminalManager.currentSession.write(text);
            }
        });
    }

    write(data) {
        if (this.terminal && this.isInitialized) {
            this.terminal.write(data);
        }
    }

    writeln(data) {
        if (this.terminal && this.isInitialized) {
            this.terminal.writeln(data);
        }
    }

    clear() {
        if (this.terminal && this.isInitialized) {
            this.terminal.clear();
        }
    }

    fit() {
        if (this.fitAddon && this.isInitialized) {
            this.fitAddon.fit();
        }
    }

    focus() {
        if (this.terminal && this.isInitialized) {
            this.terminal.focus();
        }
    }

    blur() {
        if (this.terminal && this.isInitialized) {
            this.terminal.blur();
        }
    }

    getSelection() {
        if (this.terminal && this.isInitialized) {
            return this.terminal.getSelection();
        }
        return '';
    }

    copySelection() {
        const selection = this.getSelection();
        if (selection && navigator.clipboard) {
            navigator.clipboard.writeText(selection).then(() => {
                console.log('📋 Text copied to clipboard');
            }).catch(err => {
                console.error('Failed to copy text:', err);
            });
        }
    }

    async pasteFromClipboard() {
        try {
            if (navigator.clipboard) {
                const text = await navigator.clipboard.readText();
                if (text && window.terminalManager && window.terminalManager.currentSession) {
                    window.terminalManager.currentSession.write(text);
                }
            }
        } catch (err) {
            console.error('Failed to paste text:', err);
        }
    }

    openSearch() {
        if (this.searchAddon && this.isInitialized) {
            // Implement search functionality
            const searchTerm = prompt('Search terminal:');
            if (searchTerm) {
                this.searchAddon.findNext(searchTerm);
            }
        }
    }

    showContextMenu(x, y) {
        const contextMenu = document.getElementById('contextMenu');
        if (!contextMenu) return;

        contextMenu.style.display = 'block';
        contextMenu.style.left = `${x}px`;
        contextMenu.style.top = `${y}px`;

        // Hide menu when clicking elsewhere
        const hideMenu = (e) => {
            if (!contextMenu.contains(e.target)) {
                contextMenu.style.display = 'none';
                document.removeEventListener('click', hideMenu);
            }
        };

        setTimeout(() => {
            document.addEventListener('click', hideMenu);
        }, 10);
    }

    resize(cols, rows) {
        if (this.terminal && this.isInitialized) {
            this.terminal.resize(cols, rows);
        }
    }

    getDimensions() {
        if (this.terminal && this.isInitialized) {
            return {
                cols: this.terminal.cols,
                rows: this.terminal.rows
            };
        }
        return { cols: 80, rows: 24 };
    }

    dispose() {
        if (this.terminal) {
            this.terminal.dispose();
            this.terminal = null;
        }
        this.isInitialized = false;
    }
}

// Initialize XTerm manager
window.xtermManager = new XTermManager();