const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const chokidar = require('chokidar');

class ContextManager {
    constructor() {
        this.currentContext = {
            projectName: null,
            projectType: null,
            gitInfo: null,
            fileWatcher: null,
            activeProcesses: [],
            recentFiles: [],
            packageInfo: null
        };
        
        this.watchers = new Map();
        this.updateInterval = null;
        
        this.initialize();
    }

    initialize() {
        this.startPeriodicUpdates();
        this.setupEventHandlers();
        console.log('🔍 Context Manager initialized');
    }

    startPeriodicUpdates() {
        // Update context every 5 seconds
        this.updateInterval = setInterval(() => {
            this.updateAllContext();
        }, 5000);

        // Initial update
        this.updateAllContext();
    }

    setupEventHandlers() {
        // Listen for directory changes from terminal
        if (window.terminalManager) {
            const originalMethod = window.terminalManager.currentSession?.updateCurrentDirectory;
            if (originalMethod) {
                window.terminalManager.currentSession.updateCurrentDirectory = (output) => {
                    originalMethod.call(window.terminalManager.currentSession, output);
                    this.onDirectoryChange(window.terminalManager.currentSession.cwd);
                };
            }
        }
    }

    async updateAllContext() {
        const session = window.terminalManager?.getCurrentSession();
        if (!session) return;

        const cwd = session.getCwd();
        
        try {
            // Update all context information
            await Promise.all([
                this.updateProjectInfo(cwd),
                this.updateGitInfo(cwd),
                this.updateProcessInfo(),
                this.updatePackageInfo(cwd)
            ]);

            // Update display
            this.updateContextDisplay();
            
            // Notify AI assistant of context changes
            if (window.aiAssistant) {
                window.aiAssistant.updateContext(this.currentContext);
            }
        } catch (error) {
            console.error('Context update failed:', error);
        }
    }

    async updateProjectInfo(cwd) {
        try {
            // Determine project name from directory
            this.currentContext.projectName = path.basename(cwd);
            
            // Determine project type
            this.currentContext.projectType = await this.detectProjectType(cwd);
            
            // Setup file watcher for this directory
            this.setupFileWatcher(cwd);
        } catch (error) {
            console.error('Failed to update project info:', error);
        }
    }

    async detectProjectType(cwd) {
        const indicators = [
            { file: 'package.json', type: 'Node.js' },
            { file: 'Cargo.toml', type: 'Rust' },
            { file: 'requirements.txt', type: 'Python' },
            { file: 'pom.xml', type: 'Java/Maven' },
            { file: 'build.gradle', type: 'Java/Gradle' },
            { file: 'composer.json', type: 'PHP' },
            { file: 'Gemfile', type: 'Ruby' },
            { file: 'go.mod', type: 'Go' },
            { file: 'CMakeLists.txt', type: 'C/C++' },
            { file: 'Makefile', type: 'Make' },
            { file: 'docker-compose.yml', type: 'Docker' },
            { file: 'Dockerfile', type: 'Docker' }
        ];

        for (const indicator of indicators) {
            const filePath = path.join(cwd, indicator.file);
            if (await this.fileExists(filePath)) {
                return indicator.type;
            }
        }

        return 'Unknown';
    }

    async updateGitInfo(cwd) {
        return new Promise((resolve) => {
            exec('git rev-parse --is-inside-work-tree', { cwd }, (error) => {
                if (error) {
                    this.currentContext.gitInfo = null;
                    resolve();
                    return;
                }

                // Get git information
                const gitCommands = [
                    'git branch --show-current',
                    'git status --porcelain',
                    'git log -1 --format="%h %s"'
                ];

                Promise.all(gitCommands.map(cmd => this.execCommand(cmd, cwd)))
                    .then(([branch, status, lastCommit]) => {
                        this.currentContext.gitInfo = {
                            branch: branch.trim(),
                            isDirty: status.trim().length > 0,
                            lastCommit: lastCommit.trim(),
                            changedFiles: status.split('\n').filter(line => line.trim()).length
                        };
                        resolve();
                    })
                    .catch(() => {
                        this.currentContext.gitInfo = null;
                        resolve();
                    });
            });
        });
    }

    async updateProcessInfo() {
        try {
            // Get running processes (simplified for performance)
            const result = await this.execCommand('ps aux | wc -l');
            this.currentContext.activeProcesses = [{
                count: parseInt(result.trim()) || 0,
                timestamp: Date.now()
            }];
        } catch (error) {
            console.error('Failed to update process info:', error);
        }
    }

    async updatePackageInfo(cwd) {
        try {
            const packageJsonPath = path.join(cwd, 'package.json');
            
            if (await this.fileExists(packageJsonPath)) {
                const packageData = JSON.parse(await this.readFile(packageJsonPath));
                this.currentContext.packageInfo = {
                    name: packageData.name,
                    version: packageData.version,
                    scripts: Object.keys(packageData.scripts || {}),
                    dependencies: Object.keys(packageData.dependencies || {}),
                    devDependencies: Object.keys(packageData.devDependencies || {})
                };
            } else {
                this.currentContext.packageInfo = null;
            }
        } catch (error) {
            this.currentContext.packageInfo = null;
        }
    }

    setupFileWatcher(cwd) {
        // Close existing watcher
        if (this.watchers.has(cwd)) {
            this.watchers.get(cwd).close();
        }

        try {
            const watcher = chokidar.watch(cwd, {
                ignored: /(^|[\/\\])\../, // Ignore hidden files
                persistent: true,
                ignoreInitial: true,
                depth: 2 // Limit depth for performance
            });

            watcher.on('change', (filePath) => {
                this.onFileChange(filePath);
            });

            watcher.on('add', (filePath) => {
                this.onFileAdd(filePath);
            });

            this.watchers.set(cwd, watcher);
        } catch (error) {
            console.error('Failed to setup file watcher:', error);
        }
    }

    onDirectoryChange(newCwd) {
        console.log(`📁 Directory changed to: ${newCwd}`);
        this.updateAllContext();
    }

    onFileChange(filePath) {
        const fileName = path.basename(filePath);
        console.log(`📝 File changed: ${fileName}`);
        
        // Add to recent files
        this.addToRecentFiles(filePath);
        
        // Update package info if package.json changed
        if (fileName === 'package.json') {
            this.updatePackageInfo(path.dirname(filePath));
        }
    }

    onFileAdd(filePath) {
        const fileName = path.basename(filePath);
        console.log(`📄 File added: ${fileName}`);
        this.addToRecentFiles(filePath);
    }

    addToRecentFiles(filePath) {
        this.currentContext.recentFiles.unshift({
            path: filePath,
            name: path.basename(filePath),
            timestamp: Date.now()
        });

        // Keep only last 10 files
        this.currentContext.recentFiles = this.currentContext.recentFiles.slice(0, 10);
    }

    updateContextDisplay() {
        // Update project name
        const projectNameEl = document.getElementById('projectName');
        if (projectNameEl) {
            projectNameEl.textContent = this.currentContext.projectName || '-';
        }

        // Update git branch
        const gitBranchEl = document.getElementById('gitBranch');
        if (gitBranchEl) {
            if (this.currentContext.gitInfo) {
                const branch = this.currentContext.gitInfo.branch;
                const isDirty = this.currentContext.gitInfo.isDirty;
                gitBranchEl.textContent = `${branch}${isDirty ? '*' : ''}`;
                gitBranchEl.style.color = isDirty ? '#f38ba8' : '#a6e3a1';
            } else {
                gitBranchEl.textContent = '-';
                gitBranchEl.style.color = '#888';
            }
        }

        // Update process count
        const processCountEl = document.getElementById('processCount');
        if (processCountEl && this.currentContext.activeProcesses.length > 0) {
            processCountEl.textContent = this.currentContext.activeProcesses[0].count;
        }
    }

    updateFromTerminalOutput(output) {
        // Parse terminal output for context clues
        this.parseCommandExecution(output);
    }

    parseCommandExecution(output) {
        // Detect common command patterns and update context
        if (output.includes('npm install')) {
            setTimeout(() => {
                this.updatePackageInfo(window.terminalManager?.getCurrentSession()?.getCwd());
            }, 2000);
        }

        if (output.includes('git checkout') || output.includes('git branch')) {
            setTimeout(() => {
                this.updateGitInfo(window.terminalManager?.getCurrentSession()?.getCwd());
            }, 1000);
        }

        if (output.includes('cd ') && output.includes('/')) {
            // Directory change detected
            setTimeout(() => {
                this.updateAllContext();
            }, 500);
        }
    }

    // Utility methods
    async fileExists(filePath) {
        try {
            await fs.promises.access(filePath);
            return true;
        } catch {
            return false;
        }
    }

    async readFile(filePath) {
        return fs.promises.readFile(filePath, 'utf8');
    }

    execCommand(command, cwd = null) {
        return new Promise((resolve, reject) => {
            exec(command, { cwd }, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(stdout);
                }
            });
        });
    }

    // Public getters
    getProjectInfo() {
        return {
            name: this.currentContext.projectName,
            type: this.currentContext.projectType
        };
    }

    getGitInfo() {
        return this.currentContext.gitInfo;
    }

    getPackageInfo() {
        return this.currentContext.packageInfo;
    }

    getRecentFiles() {
        return this.currentContext.recentFiles;
    }

    getCurrentContext() {
        return { ...this.currentContext };
    }

    destroy() {
        // Clean up watchers
        this.watchers.forEach(watcher => watcher.close());
        this.watchers.clear();

        // Clear interval
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }

        console.log('🔍 Context Manager destroyed');
    }
}

// Initialize context manager
window.contextManager = new ContextManager();