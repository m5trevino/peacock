const { ipcRenderer } = require('electron');

class RendererManager {
    constructor() {
        this.isInitialized = false;
        this.settings = {
            opacity: 0.85,
            fontSize: 14,
            theme: 'dark'
        };
        
        this.initialize();
    }

    async initialize() {
        console.log('🎨 Initializing Renderer Manager...');
        
        if (document.readyState === 'loading') {
            await new Promise(resolve => {
                document.addEventListener('DOMContentLoaded', resolve);
            });
        }

        this.setupGlobalEventHandlers();
        this.setupHeaderControls();
        this.setupStatusBar();
        this.setupContextMenu();
        this.setupHistoryManager();
        this.loadSettings();
        this.startTimeUpdater();
        
        await this.initializeManagers();
        
        this.isInitialized = true;
        console.log('✨ Renderer fully initialized');
    }

    async initializeManagers() {
        const maxWait = 10000;
        const startTime = Date.now();
        
        while (Date.now() - startTime < maxWait) {
            if (window.xtermManager?.isInitialized && 
                window.terminalManager && 
                window.aiAssistant && 
                window.contextManager) {
                
                console.log('🎯 All managers ready');
                this.setupManagerCommunication();
                return;
            }
            
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        console.warn('⚠️ Some managers may not be fully initialized');
    }

    setupManagerCommunication() {
        this.setupFocusManagement();
    }

    setupFocusManagement() {
        const observer = new MutationObserver(() => {
            if (document.hasFocus() && window.xtermManager?.isInitialized) {
                setTimeout(() => {
                    window.xtermManager.focus();
                }, 100);
            }
        });

        observer.observe(document.body, {
            attributes: true,
            attributeFilter: ['class']
        });
    }

    setupGlobalEventHandlers() {
        document.addEventListener('keydown', (e) => {
            this.handleGlobalKeydown(e);
        });

        window.addEventListener('focus', () => {
            if (window.xtermManager?.isInitialized) {
                window.xtermManager.focus();
            }
        });

        window.addEventListener('resize', () => {
            this.handleResize();
        });

        document.addEventListener('selectstart', (e) => {
            if (!e.target.closest('.terminal, input, textarea')) {
                e.preventDefault();
            }
        });

        document.addEventListener('contextmenu', (e) => {
            if (!e.target.closest('.terminal')) {
                e.preventDefault();
            }
        });
    }

    handleGlobalKeydown(e) {
        if (e.ctrlKey && e.shiftKey && e.key === 'H') {
            e.preventDefault();
            this.toggleHistory();
        }

        if (e.ctrlKey && e.shiftKey && e.key === 'A') {
            e.preventDefault();
            if (window.aiAssistant) {
                window.aiAssistant.togglePanel();
            }
        }

        if (e.ctrlKey && e.shiftKey && e.key === 'C') {
            e.preventDefault();
            if (window.xtermManager) {
                window.xtermManager.clear();
            }
        }

        if (e.key === 'Escape') {
            ipcRenderer.send('hide-overlay');
        }
    }

    setupHeaderControls() {
        const closeBtn = document.getElementById('closeBtn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                ipcRenderer.send('hide-overlay');
            });
        }

        const settingsBtn = document.getElementById('settingsBtn');
        if (settingsBtn) {
            settingsBtn.addEventListener('click', () => {
                this.showSettings();
            });
        }
    }

    setupStatusBar() {
        const historyBtn = document.getElementById('historyBtn');
        if (historyBtn) {
            historyBtn.addEventListener('click', () => {
                this.toggleHistory();
            });
        }

        const sessionsBtn = document.getElementById('sessionsBtn');
        if (sessionsBtn) {
            sessionsBtn.addEventListener('click', () => {
                this.showSessionManager();
            });
        }
    }

    setupContextMenu() {
        const contextMenu = document.getElementById('contextMenu');
        if (!contextMenu) return;

        contextMenu.addEventListener('click', (e) => {
            const action = e.target.dataset.action;
            if (!action) return;

            this.handleContextMenuAction(action);
            contextMenu.style.display = 'none';
        });

        document.addEventListener('click', (e) => {
            if (!contextMenu.contains(e.target)) {
                contextMenu.style.display = 'none';
            }
        });
    }

    handleContextMenuAction(action) {
        switch (action) {
            case 'copy':
                if (window.xtermManager) {
                    window.xtermManager.copySelection();
                }
                break;
            case 'paste':
                if (window.xtermManager) {
                    window.xtermManager.pasteFromClipboard();
                }
                break;
            case 'clear':
                if (window.xtermManager) {
                    window.xtermManager.clear();
                }
                break;
            case 'new-session':
                if (window.terminalManager) {
                    window.terminalManager.createSession();
                }
                break;
        }
    }

    setupHistoryManager() {
        const closeHistory = document.getElementById('closeHistory');
        if (closeHistory) {
            closeHistory.addEventListener('click', () => {
                this.hideHistory();
            });
        }

        const historySearch = document.getElementById('historySearch');
        if (historySearch) {
            historySearch.addEventListener('input', (e) => {
                this.filterHistory(e.target.value);
            });
        }
    }

    toggleHistory() {
        const sidebar = document.getElementById('historySidebar');
        if (sidebar) {
            const isActive = sidebar.classList.contains('active');
            if (isActive) {
                this.hideHistory();
            } else {
                this.showHistory();
            }
        }
    }

    showHistory() {
        const sidebar = document.getElementById('historySidebar');
        if (sidebar) {
            sidebar.style.display = 'block';
            setTimeout(() => {
                sidebar.classList.add('active');
                this.updateHistoryDisplay();
            }, 10);
        }
    }

    hideHistory() {
        const sidebar = document.getElementById('historySidebar');
        if (sidebar) {
            sidebar.classList.remove('active');
            setTimeout(() => {
                sidebar.style.display = 'none';
            }, 300);
        }
    }

    updateHistoryDisplay() {
        const historyList = document.getElementById('historyList');
        if (!historyList || !window.terminalManager) return;

        const session = window.terminalManager.getCurrentSession();
        if (!session) return;

        const history = session.getHistory();
        historyList.innerHTML = '';

        history.forEach((entry, index) => {
            const item = document.createElement('div');
            item.className = 'history-item';
            
            const command = document.createElement('div');
            command.className = 'history-item-command';
            command.textContent = entry.command;
            
            const time = document.createElement('div');
            time.className = 'history-item-time';
            time.textContent = new Date(entry.timestamp).toLocaleTimeString();
            
            item.appendChild(command);
            item.appendChild(time);
            
            item.addEventListener('click', () => {
                if (window.terminalManager?.currentSession) {
                    window.terminalManager.currentSession.write(entry.command + '\r');
                    this.hideHistory();
                }
            });
            
            historyList.appendChild(item);
        });
    }

    filterHistory(searchTerm) {
        const historyItems = document.querySelectorAll('.history-item');
        const term = searchTerm.toLowerCase();
        
        historyItems.forEach(item => {
            const command = item.querySelector('.history-item-command').textContent.toLowerCase();
            if (command.includes(term)) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });
    }

    showSettings() {
        console.log('⚙️ Settings (coming soon)');
    }

    showSessionManager() {
        console.log('🗂️ Session manager (coming soon)');
    }

    loadSettings() {
        try {
            const saved = localStorage.getItem('invisibleTerminalSettings');
            if (saved) {
                this.settings = { ...this.settings, ...JSON.parse(saved) };
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    }

    handleResize() {
        if (window.xtermManager?.isInitialized) {
            setTimeout(() => {
                window.xtermManager.fit();
            }, 100);
        }
    }

    startTimeUpdater() {
        const updateTime = () => {
            const timeEl = document.getElementById('timeStatus');
            if (timeEl) {
                const now = new Date();
                timeEl.textContent = now.toLocaleTimeString('en-US', { 
                    hour12: false,
                    hour: '2-digit',
                    minute: '2-digit'
                });
            }
        };

        updateTime();
        setInterval(updateTime, 1000);
    }

    destroy() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
        
        console.log('🎨 Renderer Manager destroyed');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.rendererManager = new RendererManager();
});

window.addEventListener('error', (e) => {
    console.error('💥 Uncaught error:', e.error);
});

window.addEventListener('unhandledrejection', (e) => {
    console.error('💥 Unhandled promise rejection:', e.reason);
});
