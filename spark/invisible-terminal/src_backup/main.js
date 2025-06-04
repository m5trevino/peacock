const { app, BrowserWindow, globalShortcut, screen, ipcMain, Menu } = require('electron');
const path = require('path');

class InvisibleTerminalApp {
    constructor() {
        this.overlayWindow = null;
        this.isVisible = false;
        this.config = {
            hotkey: 'CommandOrControl+`',
            opacity: 0.85,
            width: 800,
            height: 500
        };
        this.mousePosition = { x: 0, y: 0 };
    }

    async initialize() {
        await app.whenReady();
        this.setupMenu();
        this.createOverlayWindow();
        this.registerHotkeys();
        this.setupMouseTracking();
        this.setupIPC();
        
        console.log('🚀 Invisible Terminal initialized - Ready to hustle!');
    }

    setupMenu() {
        Menu.setApplicationMenu(null);
    }

    createOverlayWindow() {
        const { width, height } = screen.getPrimaryDisplay().workAreaSize;
        
        this.overlayWindow = new BrowserWindow({
            width: this.config.width,
            height: this.config.height,
            frame: false,
            transparent: true,
            alwaysOnTop: true,
            skipTaskbar: true,
            resizable: true,
            show: false,
            webPreferences: {
                nodeIntegration: true,
                contextIsolation: false,
                enableRemoteModule: true
            }
        });

        this.overlayWindow.loadFile('src/renderer/index.html');
        
        if (process.env.NODE_ENV === 'development') {
            this.overlayWindow.webContents.openDevTools({ mode: 'detach' });
        }

        this.overlayWindow.on('blur', () => {
            if (this.isVisible) {
                this.hideOverlay();
            }
        });

        this.overlayWindow.on('closed', () => {
            this.overlayWindow = null;
        });
    }

    registerHotkeys() {
        globalShortcut.register(this.config.hotkey, () => {
            this.toggleOverlay();
        });

        globalShortcut.register('Escape', () => {
            if (this.isVisible) {
                this.hideOverlay();
            }
        });

        console.log(`🔥 Hotkeys registered: ${this.config.hotkey} for toggle`);
    }

    setupMouseTracking() {
        setInterval(() => {
            const point = screen.getCursorScreenPoint();
            this.mousePosition = point;
            
            const display = screen.getPrimaryDisplay();
            const { width, height } = display.bounds;
            
            const edgeThreshold = 5;
            const isNearEdge = point.x <= edgeThreshold || 
                              point.x >= width - edgeThreshold ||
                              point.y <= edgeThreshold ||
                              point.y >= height - edgeThreshold;
            
            if (isNearEdge && !this.isVisible) {
                setTimeout(() => {
                    const newPoint = screen.getCursorScreenPoint();
                    if (Math.abs(newPoint.x - point.x) < 5 && 
                        Math.abs(newPoint.y - point.y) < 5) {
                        this.showOverlay();
                    }
                }, 200);
            }
        }, 100);
    }

    setupIPC() {
        ipcMain.on('hide-overlay', () => {
            this.hideOverlay();
        });

        ipcMain.on('resize-overlay', (event, { width, height }) => {
            this.config.width = width;
            this.config.height = height;
            this.overlayWindow.setSize(width, height);
        });

        ipcMain.on('set-opacity', (event, opacity) => {
            this.config.opacity = opacity;
            this.overlayWindow.setOpacity(opacity);
        });

        ipcMain.handle('get-cursor-position', () => {
            return this.mousePosition;
        });
    }

    showOverlay() {
        if (!this.overlayWindow || this.isVisible) return;

        const display = screen.getDisplayNearestPoint(this.mousePosition);
        const { bounds } = display;
        
        let x = this.mousePosition.x - (this.config.width / 2);
        let y = this.mousePosition.y - (this.config.height / 2);
        
        x = Math.max(bounds.x, Math.min(x, bounds.x + bounds.width - this.config.width));
        y = Math.max(bounds.y, Math.min(y, bounds.y + bounds.height - this.config.height));
        
        this.overlayWindow.setPosition(x, y);
        this.overlayWindow.setOpacity(this.config.opacity);
        this.overlayWindow.show();
        this.overlayWindow.focus();
        
        this.isVisible = true;
        console.log('👻 Overlay activated');
    }

    hideOverlay() {
        if (!this.overlayWindow || !this.isVisible) return;
        
        this.overlayWindow.hide();
        this.isVisible = false;
        console.log('👻 Overlay hidden');
    }

    toggleOverlay() {
        if (this.isVisible) {
            this.hideOverlay();
        } else {
            this.showOverlay();
        }
    }

    cleanup() {
        globalShortcut.unregisterAll();
        if (this.overlayWindow) {
            this.overlayWindow.close();
        }
    }
}

const terminalApp = new InvisibleTerminalApp();

app.on('ready', () => {
    terminalApp.initialize();
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        terminalApp.createOverlayWindow();
    }
});

app.on('will-quit', () => {
    terminalApp.cleanup();
});

process.on('uncaughtException', (error) => {
    console.error('💥 Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
});
