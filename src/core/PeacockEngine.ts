import { api } from '../services/api';
import * as fs from 'fs/promises';
import * as path from 'path';

export enum PipelineStage {
    SPARK = 'spark',
    FALCON = 'falcon',
    EAGLE = 'eagle',
    OWL = 'owl',
    HAWK = 'hawk'
}

export interface OwlFile {
    id: string;
    path: string;
    status: 'pending' | 'success' | 'error';
    skeleton: string;
    directives: string;
    output?: string;
    keyUsed?: string;
    ipUsed?: string;
    processedAt?: number;
}

export interface StrikeMeta {
    timestamp: number;
    key: string;
    ip: string;
    model: string;
}

export class PeacockEngine {
    // State
    inputs: Record<string, string> = {};
    outputs: Record<string, string> = {};
    prompts: Record<string, string> = {};
    activeStage: PipelineStage = PipelineStage.SPARK;
    owlQueue: OwlFile[] = [];
    lastCallMeta: StrikeMeta | null = null;
    telemetry: any = {};

    constructor() {
        this.resetState();
    }

    resetState() {
        this.inputs = {
            [PipelineStage.SPARK]: '',
            [PipelineStage.FALCON]: '',
            [PipelineStage.EAGLE]: '',
            [PipelineStage.OWL]: '',
            [PipelineStage.HAWK]: ''
        };
        this.outputs = {};
        this.activeStage = PipelineStage.SPARK;
        this.owlQueue = [];
    }

    async loadPrompt(stage: PipelineStage, filePath: string): Promise<void> {
        try {
            const content = await fs.readFile(filePath, 'utf-8');
            this.prompts[stage] = content;
            console.log(`[ENGINE] Loaded prompt for ${stage} from ${filePath}`);
        } catch (error) {
            console.error(`[ENGINE] Failed to load prompt: ${error}`);
            throw error;
        }
    }

    setPromptContent(stage: PipelineStage, content: string) {
        this.prompts[stage] = content;
    }

    setInput(stage: PipelineStage, content: string) {
        this.inputs[stage] = content;
    }

    async executeStrike(stage: PipelineStage, modelId: string = 'models/gemini-2.0-flash'): Promise<string> {
        console.log(`[ENGINE] Striking ${stage} with model ${modelId}...`);

        const prompt = this.prompts[stage];
        const payload = this.inputs[stage];

        if (!prompt) throw new Error(`No prompt loaded for ${stage}`);

        // Construct full prompt
        const fullPrompt = `${prompt}\n\n${payload}`;

        try {
            const response = await api.executeStrike({
                modelId,
                prompt: fullPrompt,
                temp: 0.7
            });

            this.outputs[stage] = response.content;

            this.lastCallMeta = {
                timestamp: Date.now(),
                key: response.keyUsed || 'UNKNOWN',
                ip: response.ipUsed || 'UNKNOWN',
                model: modelId
            };

            // Post-processing
            if (stage === PipelineStage.EAGLE) {
                this.parseEagleResponse(response.content);
            }

            return response.content;
        } catch (error) {
            console.error(`[ENGINE] Strike failed: ${error}`);
            throw error;
        }
    }

    parseEagleResponse(content: string) {
        console.log('[ENGINE] Parsing Eagle Response...');
        this.owlQueue = [];

        try {
            // Find JSON block
            const jsonMatch = content.match(/\{[\s\S]*\}/);
            if (!jsonMatch) throw new Error('No JSON found in response');

            const data = JSON.parse(jsonMatch[0]);

            if (data.files && Array.isArray(data.files)) {
                data.files.forEach((file: any, index: number) => {
                    this.owlQueue.push({
                        id: `file-${index}`,
                        path: file.path,
                        status: 'pending',
                        skeleton: file.skeleton,
                        directives: file.directives || "Follow standard implementation patterns."
                    });
                });
            }
            console.log(`[ENGINE] Successfully parsed ${this.owlQueue.length} files from JSON.`);
        } catch (error) {
            console.warn('[ENGINE] JSON Parsing failed, falling back to legacy EOF regex...');
            // Fallback to legacy EOF regex
            const eofRegex = /mkdir -p ([\w\/.-]+)\s+cat << 'EOF' > ([\w\/.-]+)\s+([\s\S]+?)EOF/g;
            let match;
            let count = 0;
            while ((match = eofRegex.exec(content)) !== null) {
                this.owlQueue.push({
                    id: `file-${count++}`,
                    path: match[2].trim(),
                    status: 'pending',
                    skeleton: match[3],
                    directives: "Extracted from EOF block."
                });
            }
            console.log(`[ENGINE] Fallback parsed ${this.owlQueue.length} files.`);
        }
    }

    async executeOwlStrike(fileId: string, modelId: string = 'models/gemini-2.0-flash'): Promise<string> {
        const file = this.owlQueue.find(f => f.id === fileId);
        if (!file) throw new Error('File not found');

        const prompt = this.prompts[PipelineStage.OWL];
        if (!prompt) throw new Error('No Owl prompt loaded');

        // Construct Payload
        const payload = `
CONTEXT_FILE: ${file.path}
DIRECTIVES: ${file.directives}
SKELETON_CODE:
${file.skeleton}
`;
        const fullPrompt = `${prompt}\n\n${payload}`;

        console.log(`[ENGINE] Striking Owl for ${file.path}...`);

        try {
            const response = await api.executeStrike({
                modelId,
                prompt: fullPrompt,
                temp: 0.2 // Lower temp for code
            });

            file.output = response.content;
            file.keyUsed = response.keyUsed;
            file.ipUsed = response.ipUsed;
            file.processedAt = Date.now();
            file.status = 'success';

            this.lastCallMeta = {
                timestamp: Date.now(),
                key: response.keyUsed || 'UNKNOWN',
                ip: response.ipUsed || 'UNKNOWN',
                model: modelId
            };

            return response.content;
        } catch (error) {
            file.status = 'error';
            console.error(`[ENGINE] Owl Strike failed for ${file.path}: ${error}`);
            throw error;
        }
    }

    getTimeSinceLastStrike(): number {
        if (!this.lastCallMeta) return Infinity;
        return (Date.now() - this.lastCallMeta.timestamp) / 1000;
    }

    generateDeployScript(): string {
        if (this.owlQueue.length === 0) return '# No files to deploy';

        let script = '#!/bin/bash\n# Peacock Deploy Script\n\n';

        for (const file of this.owlQueue) {
            if (file.status === 'success' && file.output) {
                script += `echo "Deploying ${file.path}..."\n`;
                script += `mkdir -p $(dirname "${file.path}")\n`;

                // Use EOF with delimiter that won't conflict
                const delimiter = 'PeacockEndOF';
                script += `cat << '${delimiter}' > "${file.path}"\n`;
                script += file.output + '\n';
                script += `${delimiter}\n\n`;
            }
        }

        return script;
    }
}

