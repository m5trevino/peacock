const { spawn } = require('node-pty');
const os = require('os');
const path = require('path');

class TerminalSession {
    constructor(sessionId, shell = null, cwd = null) {
        this.sessionId = sessionId;
        this.shell = shell || this.getDefaultShell();
        this.cwd = cwd || os.homedir();
        this.ptyProcess = null;
        this.isActive = false;
        this.history = [];
        this.currentCommand = '';
        this.lastActivity = Date.now();
        
        this.initialize();
    }

    getDefaultShell() {
        // Default to zsh since user specified it
        if (process.platform === 'win32') {
            return 'powershell.exe';
        }
        return process.env.SHELL || '/bin/zsh';
    }

    initialize() {
        try {
            this.ptyProcess = spawn(this.shell, [], {
                name: 'xterm-256color',
                cols: 80,
                rows: 24,
                cwd: this.cwd,
                env: {
                    ...process.env,
                    TERM: 'xterm-256color',
                    COLORTERM: 'truecolor',
                    TERM_PROGRAM: 'invisible-terminal'
                }
            });

            this.setupEventHandlers();
            this.isActive = true;
            
            console.log(`🐚 Terminal session ${this.sessionId} initialized with ${this.shell}`);
        } catch (error) {
            console.error(`Failed to initialize terminal session ${this.sessionId}:`, error);
            throw error;
        }
    }

    setupEventHandlers() {
        if (!this.ptyProcess) return;

        // Handle data from terminal
        this.ptyProcess.on('data', (data) => {
            this.lastActivity = Date.now();
            
            // Send to XTerm display
            if (window.xtermManager && window.xtermManager.isInitialized) {
                window.xtermManager.write(data);
            }

            // Parse for command completion and context
            this.parseOutput(data);
        });

        // Handle process exit
        this.ptyProcess.on('exit', (exitCode, signal) => {
            console.log(`Terminal session ${this.sessionId} exited with code ${exitCode}, signal ${signal}`);
            this.isActive = false;
            
            // Auto-restart if unexpected exit
            if (exitCode !== 0 && !signal) {
                setTimeout(() => {
                    this.restart();
                }, 1000);
            }
        });

        // Handle errors
        this.ptyProcess.on('error', (error) => {
            console.error(`Terminal session ${this.sessionId} error:`, error);
        });
    }

    parseOutput(data) {
        const text = data.toString();
        
        // Update current working directory
        this.updateCurrentDirectory(text);
        
        // Track command history
        this.trackCommandHistory(text);
        
        // Update context information
        if (window.contextManager) {
            window.contextManager.updateFromTerminalOutput(text);
        }
    }

    updateCurrentDirectory(output) {
        // Look for PWD changes or prompt indicators
        const pwdMatch = output.match(/PWD=([^\s\n]+)/);
        if (pwdMatch) {
            this.cwd = pwdMatch[1];
            this.updatePathDisplay();
        }

        // Parse common prompt formats
        const promptMatch = output.match(/([^@]+@[^:]+):([^$#]+)[$#]/);
        if (promptMatch) {
            const newPath = promptMatch[2].replace('~', os.homedir());
            if (newPath !== this.cwd) {
                this.cwd = newPath;
                this.updatePathDisplay();
            }
        }
    }

    updatePathDisplay() {
        const pathElement = document.getElementById('currentPath');
        if (pathElement) {
            const displayPath = this.cwd.replace(os.homedir(), '~');
            pathElement.textContent = displayPath;
        }
    }

    trackCommandHistory(output) {
        // Basic command tracking - can be enhanced
        const lines = output.split('\n');
        lines.forEach(line => {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('$') && !trimmed.startsWith('#')) {
                // This is a basic approach - more sophisticated parsing needed
                if (trimmed.length > 3 && !trimmed.includes('\x1b[')) {
                    this.addToHistory(trimmed);
                }
            }
        });
    }

    addToHistory(command) {
        const historyEntry = {
            command: command,
            timestamp: Date.now(),
            cwd: this.cwd
        };
        
        this.history.unshift(historyEntry);
        
        // Keep history size manageable
        if (this.history.length > 1000) {
            this.history = this.history.slice(0, 1000);
        }

        // Update history display
        if (window.historyManager) {
            window.historyManager.updateDisplay();
        }
    }

    write(data) {
        if (this.ptyProcess && this.isActive) {
            this.ptyProcess.write(data);
            this.lastActivity = Date.now();
        }
    }

    resize(cols, rows) {
        if (this.ptyProcess && this.isActive) {
            this.ptyProcess.resize(cols, rows);
        }
    }

    restart() {
        if (this.ptyProcess) {
            this.ptyProcess.kill();
        }
        
        setTimeout(() => {
            this.initialize();
        }, 500);
    }

    kill() {
        if (this.ptyProcess) {
            this.ptyProcess.kill();
            this.isActive = false;
        }
    }

    getCwd() {
        return this.cwd;
    }

    getHistory() {
        return this.history;
    }

    isIdle() {
        return Date.now() - this.lastActivity > 300000; // 5 minutes
    }
}

class TerminalManager {
    constructor() {
        this.sessions = new Map();
        this.currentSessionId = null;
        this.currentSession = null;
        this.nextSessionId = 1;
        
        this.initialize();
    }

    initialize() {
        // Create initial session
        this.createSession();
        
        // Setup periodic maintenance
        setInterval(() => {
            this.performMaintenance();
        }, 60000); // Every minute

        console.log('🔧 Terminal Manager initialized');
    }

    createSession(shell = null, cwd = null) {
        const sessionId = `session-${this.nextSessionId++}`;
        
        try {
            const session = new TerminalSession(sessionId, shell, cwd);
            this.sessions.set(sessionId, session);
            this.switchToSession(sessionId);
            
            console.log(`✨ Created new terminal session: ${sessionId}`);
            return sessionId;
        } catch (error) {
            console.error('Failed to create terminal session:', error);
            return null;
        }
    }

    switchToSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            console.error(`Session ${sessionId} not found`);
            return false;
        }

        this.currentSessionId = sessionId;
        this.currentSession = session;
        
        // Update display
        const sessionInfo = document.getElementById('sessionInfo');
        if (sessionInfo) {
            sessionInfo.textContent = path.basename(session.shell);
        }

        // Resize terminal to match current session
        if (window.xtermManager && window.xtermManager.isInitialized) {
            const { cols, rows } = window.xtermManager.getDimensions();
            session.resize(cols, rows);
        }

        console.log(`🔄 Switched to session: ${sessionId}`);
        return true;
    }

    closeSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (session) {
            session.kill();
            this.sessions.delete(sessionId);
            
            // If this was the current session, switch to another or create new
            if (sessionId === this.currentSessionId) {
                const remainingSessions = Array.from(this.sessions.keys());
                if (remainingSessions.length > 0) {
                    this.switchToSession(remainingSessions[0]);
                } else {
                    this.createSession();
                }
            }
            
            console.log(`🗑️ Closed session: ${sessionId}`);
        }
    }

    getAllSessions() {
        return Array.from(this.sessions.values());
    }

    getCurrentSession() {
        return this.currentSession;
    }

    executeCommand(command) {
        if (this.currentSession) {
            this.currentSession.write(command + '\r');
        }
    }

    changeDirectory(path) {
        if (this.currentSession) {
            this.currentSession.write(`cd "${path}"\r`);
        }
    }

    performMaintenance() {
        // Clean up idle sessions (but keep at least one)
        const sessions = Array.from(this.sessions.values());
        const activeSessions = sessions.filter(s => !s.isIdle() || s === this.currentSession);
        
        if (activeSessions.length === 0 && sessions.length > 0) {
            // Keep the current session even if idle
            return;
        }

        sessions.forEach(session => {
            if (session.isIdle() && session !== this.currentSession && sessions.length > 1) {
                this.closeSession(session.sessionId);
            }
        });
    }

    resize(cols, rows) {
        if (this.currentSession) {
            this.currentSession.resize(cols, rows);
        }
    }

    destroy() {
        this.sessions.forEach(session => {
            session.kill();
        });
        this.sessions.clear();
        this.currentSession = null;
        this.currentSessionId = null;
    }
}

// Initialize terminal manager
window.terminalManager = new TerminalManager();