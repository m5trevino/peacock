const { app, BrowserWindow, globalShortcut, screen, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const os = require('os');

class InvisibleTerminalOverlay {
    constructor() {
        this.overlayWindow = null;
        this.currentMode = null;
        this.activeProcess = null;
        this.commandHistory = [];
        this.isActive = false;
        this.cursorPosition = { x: 0, y: 0 };
        
        this.initialize();
    }

    initialize() {
        app.whenReady().then(() => {
            this.createOverlayWindow();
            this.registerHotkeys();
            console.log('👻 True Invisible Terminal initialized');
        });

        app.on('window-all-closed', () => {
            if (process.platform !== 'darwin') {
                app.quit();
            }
        });

        app.on('will-quit', () => {
            globalShortcut.unregisterAll();
            this.cleanup();
        });
    }

    createOverlayWindow() {
        const primaryDisplay = screen.getPrimaryDisplay();
        const { width, height } = primaryDisplay.workAreaSize;

        this.overlayWindow = new BrowserWindow({
            width: width,
            height: height,
            x: 0,
            y: 0,
            transparent: true,
            frame: false,
            alwaysOnTop: true,
            skipTaskbar: true,
            resizable: false,
            movable: false,
            minimizable: false,
            maximizable: false,
            closable: false,
            focusable: true,
            show: false,
            titleBarStyle: 'hidden',
            webPreferences: {
                nodeIntegration: true,
                contextIsolation: false,
                enableRemoteModule: true,
                backgroundThrottling: false
            }
        });

        this.overlayWindow.setIgnoreMouseEvents(true);
        this.overlayWindow.setVisibleOnAllWorkspaces(true);
        
        this.overlayWindow.loadFile('src/renderer/overlay.html');
        this.overlayWindow.setSkipTaskbar(true);
        
        this.setupIPC();
    }

    registerHotkeys() {
        globalShortcut.register('CommandOrControl+`', () => {
            this.cleanActivateMode('quick');
        });

        globalShortcut.register('CommandOrControl+Shift+`', () => {
            this.cleanActivateMode('persistent');
        });

        globalShortcut.register('CommandOrControl+Alt+`', () => {
            this.cleanActivateMode('fullview');
        });

        globalShortcut.register('Escape', () => {
            this.hideOverlay();
        });

        console.log('🔥 True Invisible Hotkeys:');
        console.log('  Ctrl+` = Quick Command (auto-hide after 8sec)');
        console.log('  Ctrl+Shift+` = Persistent Mode');
        console.log('  Ctrl+Alt+` = Full Terminal View');
        console.log('  Esc = Hide overlay');
    }

    cleanActivateMode(mode) {
        console.log('🎯 Activating ' + mode + ' mode (fresh state)');
        
        this.cleanup();
        this.currentMode = mode;
        
        if (mode === 'fullview') {
            this.showFullTerminalView();
        } else {
            this.showOverlayAtCursor();
        }
    }

    showOverlayAtCursor() {
        const primaryDisplay = screen.getPrimaryDisplay();
        const { width, height } = primaryDisplay.workAreaSize;
        
        this.cursorPosition = { 
            x: Math.floor(width / 2), 
            y: Math.floor(height / 2) 
        };

        this.overlayWindow.webContents.send('show-cursor-mode', {
            mode: this.currentMode,
            position: this.cursorPosition
        });

        this.overlayWindow.show();
        this.overlayWindow.setIgnoreMouseEvents(false);
        this.overlayWindow.focus();
        this.isActive = true;
    }

    showFullTerminalView() {
        this.overlayWindow.webContents.send('show-fullview-mode', {
            history: this.commandHistory
        });

        this.overlayWindow.show();
        this.overlayWindow.setIgnoreMouseEvents(false);
        this.overlayWindow.focus();
        this.isActive = true;
    }

    hideOverlay() {
        if (this.isActive) {
            console.log('👻 Hiding overlay');
            this.overlayWindow.hide();
            this.overlayWindow.setIgnoreMouseEvents(true);
            this.cleanup();
        }
    }

    setupIPC() {
        ipcMain.on('execute-command', (event, command) => {
            this.executeCommand(command);
        });

        ipcMain.on('command-entered', (event) => {
            // Command entered
        });

        ipcMain.on('user-activity', (event) => {
            // User activity tracked
        });
    }

    executeCommand(command) {
        console.log('💻 Executing: ' + command);
        
        if (this.activeProcess) {
            this.activeProcess.kill();
        }
        
        const shell = process.platform === 'win32' ? 'cmd.exe' : '/bin/bash';
        const shellArgs = process.platform === 'win32' ? ['/c'] : ['-c'];
        
        this.activeProcess = spawn(shell, [...shellArgs, command], {
            cwd: os.homedir(),
            env: process.env
        });

        let output = '';
        let error = '';

        this.activeProcess.stdout.on('data', (data) => {
            const chunk = data.toString();
            output += chunk;
            this.overlayWindow.webContents.send('command-output', {
                type: 'stdout',
                data: chunk
            });
        });

        this.activeProcess.stderr.on('data', (data) => {
            const chunk = data.toString();
            error += chunk;
            this.overlayWindow.webContents.send('command-output', {
                type: 'stderr',
                data: chunk
            });
        });

        this.activeProcess.on('close', (code) => {
            const historyEntry = {
                command: command,
                output: output,
                error: error,
                exitCode: code,
                timestamp: Date.now(),
                cwd: os.homedir()
            };
            
            this.commandHistory.unshift(historyEntry);
            
            if (this.commandHistory.length > 100) {
                this.commandHistory = this.commandHistory.slice(0, 100);
            }

            this.overlayWindow.webContents.send('command-complete', historyEntry);
            this.activeProcess = null;
        });

        this.activeProcess.on('error', (err) => {
            console.error('Command execution error:', err);
            this.overlayWindow.webContents.send('command-output', {
                type: 'stderr',
                data: 'Error: ' + err.message + '\n'
            });
            this.activeProcess = null;
        });
    }

    cleanup() {
        if (this.activeProcess) {
            this.activeProcess.kill();
            this.activeProcess = null;
        }
        this.isActive = false;
        this.currentMode = null;
    }
}

const invisibleTerminal = new InvisibleTerminalOverlay();
