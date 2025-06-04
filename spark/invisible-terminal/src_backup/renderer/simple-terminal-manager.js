const { spawn } = require('child_process');
const os = require('os');
const path = require('path');

class SimpleTerminalSession {
    constructor(sessionId, shell = null, cwd = null) {
        this.sessionId = sessionId;
        this.shell = shell || this.getDefaultShell();
        this.cwd = cwd || os.homedir();
        this.process = null;
        this.isActive = false;
        this.history = [];
        this.currentCommand = '';
        this.lastActivity = Date.now();
        
        this.initialize();
    }

    getDefaultShell() {
        if (process.platform === 'win32') {
            return 'cmd.exe';
        }
        return process.env.SHELL || '/bin/bash';
    }

    initialize() {
        try {
            // Use script command for better terminal emulation on Linux
            if (process.platform === 'linux') {
                this.process = spawn('script', ['-qfc', this.shell, '/dev/null'], {
                    cwd: this.cwd,
                    env: {
                        ...process.env,
                        TERM: 'xterm-256color',
                        COLORTERM: 'truecolor'
                    }
                });
            } else {
                this.process = spawn(this.shell, [], {
                    cwd: this.cwd,
                    env: {
                        ...process.env,
                        TERM: 'xterm-256color'
                    }
                });
            }

            this.setupEventHandlers();
            this.isActive = true;
            
            console.log(`🐚 Simple terminal session ${this.sessionId} initialized`);
        } catch (error) {
            console.error(`Failed to initialize terminal session ${this.sessionId}:`, error);
            throw error;
        }
    }

    setupEventHandlers() {
        if (!this.process) return;

        // Handle data from terminal
        this.process.stdout.on('data', (data) => {
            this.lastActivity = Date.now();
            
            // Send to XTerm display
            if (window.xtermManager && window.xtermManager.isInitialized) {
                window.xtermManager.write(data.toString());
            }

            this.parseOutput(data.toString());
        });

        this.process.stderr.on('data', (data) => {
            this.lastActivity = Date.now();
            
            // Send to XTerm display
            if (window.xtermManager && window.xtermManager.isInitialized) {
                window.xtermManager.write(data.toString());
            }
        });

        // Handle process exit
        this.process.on('exit', (exitCode, signal) => {
            console.log(`Terminal session ${this.sessionId} exited with code ${exitCode}`);
            this.isActive = false;
            
            // Auto-restart if unexpected exit
            if (exitCode !== 0 && !signal) {
                setTimeout(() => {
                    this.restart();
                }, 1000);
            }
        });

        // Handle errors
        this.process.on('error', (error) => {
            console.error(`Terminal session ${this.sessionId} error:`, error);
        });
    }

    parseOutput(data) {
        // Update current working directory
        this.updateCurrentDirectory(data);
        
        // Track command history
        this.trackCommandHistory(data);
        
        // Update context information
        if (window.contextManager) {
            window.contextManager.updateFromTerminalOutput(data);
        }
    }

    updateCurrentDirectory(output) {
        // Simple PWD detection
        const lines = output.split('\n');
        lines.forEach(line => {
            if (line.includes('@') && line.includes(':') && (line.includes('$') || line.includes('#'))) {
                const match = line.match(/[^:]+:([^$#]+)[$#]/);
                if (match) {
                    const newPath = match[1].trim().replace('~', os.homedir());
                    if (newPath !== this.cwd) {
                        this.cwd = newPath;
                        this.updatePathDisplay();
                    }
                }
            }
        });
    }

    updatePathDisplay() {
        const pathElement = document.getElementById('currentPath');
        if (pathElement) {
            const displayPath = this.cwd.replace(os.homedir(), '~');
            pathElement.textContent = displayPath;
        }
    }

    trackCommandHistory(output) {
        // Basic command tracking
        const lines = output.split('\n');
        lines.forEach(line => {
            const trimmed = line.trim();
            if (trimmed && trimmed.length > 3 && !trimmed.includes('\x1b[')) {
                // Simple heuristic for commands
                if (trimmed.match(/^[a-zA-Z]/)) {
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
        if (this.process && this.isActive && this.process.stdin) {
            this.process.stdin.write(data);
            this.lastActivity = Date.now();
        }
    }

    resize(cols, rows) {
        // Note: child_process doesn't support resize like node-pty
        // This is a limitation of the simple approach
        console.log(`Resize requested: ${cols}x${rows} (not supported in simple mode)`);
    }

    restart() {
        if (this.process) {
            this.process.kill();
        }
        
        setTimeout(() => {
            this.initialize();
        }, 500);
    }

    kill() {
        if (this.process) {
            this.process.kill();
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

class SimpleTerminalManager {
    constructor() {
        this.sessions = new Map();
        this.currentSessionId = null;
        this.currentSession = null;
        this.nextSessionId = 1;
        
        this.initialize();
    }

    initialize() {
        this.createSession();
        
        setInterval(() => {
            this.performMaintenance();
        }, 60000);

        console.log('🔧 Simple Terminal Manager initialized');
    }

    createSession(shell = null, cwd = null) {
        const sessionId = `session-${this.nextSessionId++}`;
        
        try {
            const session = new SimpleTerminalSession(sessionId, shell, cwd);
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
        
        const sessionInfo = document.getElementById('sessionInfo');
        if (sessionInfo) {
            sessionInfo.textContent = path.basename(session.shell);
        }

        console.log(`🔄 Switched to session: ${sessionId}`);
        return true;
    }

    closeSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (session) {
            session.kill();
            this.sessions.delete(sessionId);
            
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
            this.currentSession.write(command + '\n');
        }
    }

    changeDirectory(path) {
        if (this.currentSession) {
            this.currentSession.write(`cd "${path}"\n`);
        }
    }

    performMaintenance() {
        const sessions = Array.from(this.sessions.values());
        const activeSessions = sessions.filter(s => !s.isIdle() || s === this.currentSession);
        
        if (activeSessions.length === 0 && sessions.length > 0) {
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

// Initialize simple terminal manager
window.terminalManager = new SimpleTerminalManager();
