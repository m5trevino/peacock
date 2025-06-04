const axios = require('axios');

class AIAssistant {
    constructor() {
        this.isEnabled = false;
        this.apiKey = null;
        this.baseURL = 'https://api.openai.com/v1';
        this.model = 'gpt-4';
        this.conversationHistory = [];
        this.suggestions = [];
        this.contextData = {};
        
        this.loadConfig();
        this.setupEventHandlers();
    }

    loadConfig() {
        // Load AI config from environment or settings
        this.apiKey = process.env.OPENAI_API_KEY;
        this.isEnabled = !!this.apiKey;
        
        if (!this.isEnabled) {
            console.log('🤖 AI Assistant disabled - no API key found');
        } else {
            console.log('🤖 AI Assistant enabled');
        }
    }

    setupEventHandlers() {
        const aiBtn = document.getElementById('aiBtn');
        const closeAi = document.getElementById('closeAi');
        const aiSend = document.getElementById('aiSend');
        const aiInput = document.getElementById('aiInput');

        if (aiBtn) {
            aiBtn.addEventListener('click', () => {
                this.togglePanel();
            });
        }

        if (closeAi) {
            closeAi.addEventListener('click', () => {
                this.hidePanel();
            });
        }

        if (aiSend) {
            aiSend.addEventListener('click', () => {
                this.handleUserInput();
            });
        }

        if (aiInput) {
            aiInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.handleUserInput();
                }
            });
        }

        // Context menu integration
        document.addEventListener('click', (e) => {
            if (e.target.dataset.action === 'ai-explain') {
                const selection = window.xtermManager ? window.xtermManager.getSelection() : '';
                if (selection) {
                    this.explainCommand(selection);
                }
            }
        });
    }

    togglePanel() {
        const panel = document.getElementById('aiPanel');
        if (panel) {
            const isActive = panel.classList.contains('active');
            if (isActive) {
                this.hidePanel();
            } else {
                this.showPanel();
            }
        }
    }

    showPanel() {
        const panel = document.getElementById('aiPanel');
        if (panel) {
            panel.style.display = 'block';
            setTimeout(() => {
                panel.classList.add('active');
                this.generateContextualSuggestions();
            }, 10);
        }
    }

    hidePanel() {
        const panel = document.getElementById('aiPanel');
        if (panel) {
            panel.classList.remove('active');
            setTimeout(() => {
                panel.style.display = 'none';
            }, 300);
        }
    }

    async handleUserInput() {
        const input = document.getElementById('aiInput');
        if (!input || !input.value.trim()) return;

        const userQuery = input.value.trim();
        input.value = '';
        
        this.addMessageToChat('user', userQuery);
        
        if (!this.isEnabled) {
            this.addMessageToChat('assistant', 'AI Assistant is not configured. Please set your OpenAI API key in the environment variables.');
            return;
        }

        try {
            const response = await this.queryAI(userQuery);
            this.addMessageToChat('assistant', response);
        } catch (error) {
            console.error('AI query failed:', error);
            this.addMessageToChat('assistant', 'Sorry, I encountered an error processing your request.');
        }
    }

    async queryAI(query) {
        const context = this.buildContext();
        
        const messages = [
            {
                role: 'system',
                content: `You are an expert terminal assistant for a Linux user running Debian 12 with zsh. 
                         You provide concise, practical command suggestions and explanations.
                         Current context: ${JSON.stringify(context, null, 2)}
                         
                         Guidelines:
                         - Give short, actionable responses
                         - Include actual commands when relevant
                         - Explain potential risks
                         - Consider the current directory and git state
                         - Use street-smart, direct language but stay professional`
            },
            ...this.conversationHistory.slice(-5), // Keep last 5 exchanges
            {
                role: 'user',
                content: query
            }
        ];

        const response = await axios.post(`${this.baseURL}/chat/completions`, {
            model: this.model,
            messages: messages,
            max_tokens: 500,
            temperature: 0.7
        }, {
            headers: {
                'Authorization': `Bearer ${this.apiKey}`,
                'Content-Type': 'application/json'
            }
        });

        const aiResponse = response.data.choices[0].message.content;
        
        // Store conversation
        this.conversationHistory.push(
            { role: 'user', content: query },
            { role: 'assistant', content: aiResponse }
        );

        return aiResponse;
    }

    buildContext() {
        const session = window.terminalManager ? window.terminalManager.getCurrentSession() : null;
        const context = {
            cwd: session ? session.getCwd() : '~',
            shell: 'zsh',
            os: 'Debian 12',
            recentCommands: session ? session.getHistory().slice(0, 5).map(h => h.command) : [],
            ...this.contextData
        };

        // Add git context if available
        if (window.contextManager) {
            const gitInfo = window.contextManager.getGitInfo();
            if (gitInfo) {
                context.git = gitInfo;
            }
        }

        return context;
    }

    addMessageToChat(role, content) {
        const suggestionsContainer = document.getElementById('aiSuggestions');
        if (!suggestionsContainer) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `ai-message ai-message-${role}`;
        
        const header = document.createElement('div');
        header.className = 'ai-message-header';
        header.textContent = role === 'user' ? '👤 You' : '🤖 AI Assistant';
        
        const content_div = document.createElement('div');
        content_div.className = 'ai-message-content';
        content_div.textContent = content;
        
        messageDiv.appendChild(header);
        messageDiv.appendChild(content_div);
        
        suggestionsContainer.appendChild(messageDiv);
        suggestionsContainer.scrollTop = suggestionsContainer.scrollHeight;

        // Style the messages
        this.styleMessages();
    }

    styleMessages() {
        const style = document.createElement('style');
        style.textContent = `
            .ai-message {
                margin-bottom: 15px;
                padding: 10px;
                border-radius: 8px;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            .ai-message-user {
                background: rgba(0, 170, 255, 0.1);
                border-color: rgba(0, 170, 255, 0.3);
            }
            .ai-message-assistant {
                background: rgba(0, 255, 136, 0.1);
                border-color: rgba(0, 255, 136, 0.3);
            }
            