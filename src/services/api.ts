import { ModelConfig } from '../types';

const API_BASE = 'http://localhost:3099/v1';

export const api = {
    async fetchModels(): Promise<ModelConfig[]> {
        try {
            const res = await fetch(`${API_BASE}/models`);
            if (!res.ok) throw new Error('Failed to fetch models');
            return await res.json();
        } catch (error) {
            console.error('API Error:', error);
            return [];
        }
    },

    async executeStrike(params: {
        modelId: string;
        prompt: string;
        temp?: number;
        format_mode?: string;
        response_format?: any;
    }): Promise<{ content: string; keyUsed?: string; ipUsed?: string }> {
        try {
            const res = await fetch(`${API_BASE}/strike`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(params),
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Strike failed');
            }

            const data = await res.json();
            // Handle new backend object format { content, keyUsed }
            if (typeof data === 'object' && data !== null && 'content' in data) {
                return {
                    content: data.content,
                    keyUsed: data.keyUsed,
                    ipUsed: data.ipUsed || 'ROTATING_PROXY'
                };
            }
            // Fallback for raw string
            return { content: typeof data === 'string' ? data : JSON.stringify(data) };
        } catch (error) {
            console.error('Strike Error:', error);
            throw error;
        }
    },

    async checkHealth(): Promise<boolean> {
        try {
            const res = await fetch('http://localhost:3099/health');
            return res.ok;
        } catch {
            return false;
        }
    },

    async fetchStartFiles(): Promise<string[]> {
        try {
            const res = await fetch(`${API_BASE}/fs/start`);
            if (!res.ok) throw new Error('Failed to fetch start files');
            return await res.json();
        } catch (error) {
            console.error('API Error:', error);
            return [];
        }
    },

    async fetchStartFile(fileName: string): Promise<string> {
        try {
            const res = await fetch(`${API_BASE}/fs/start/${fileName}`);
            if (!res.ok) throw new Error('Failed to fetch file content');
            const data = await res.json();
            return data.content;
        } catch (error) {
            console.error('API Error:', error);
            return '';
        }
    },

    async fetchPrompts(phase: string): Promise<import('../types').PromptAsset[]> {
        try {
            const res = await fetch(`${API_BASE}/fs/prompts/${phase}`);
            if (!res.ok) throw new Error('Failed to fetch prompts');
            return await res.json();
        } catch (error) {
            console.error('API Error:', error);
            return [];
        }
    }
};
