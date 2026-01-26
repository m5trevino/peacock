export enum PipelineStage {
    SPARK = 'spark',
    FALCON = 'falcon',
    EAGLE = 'eagle',
    OWL = 'owl',
    HAWK = 'hawk'
}

export interface ModelConfig {
    id: string;
    gateway: string;
    tier?: string;
    note?: string;
    contextParams?: any;
}

export interface StageSettings {
    model: string;
    temperature: number;
}

export interface CasinoSettings {
    enabled: boolean;
    audio: boolean;
    volume: number;
}

export interface CallTelemetry {
    status: 'idle' | 'loading' | 'success' | 'error';
    exitIP?: string;
    assetLabel?: string;
    latency?: number;
}

export interface OwlFile {
    id: string;
    path: string;
    skeleton: string;
    directives: string;
    status: 'pending' | 'completed';
    output?: string;
}

export interface PromptAsset {
    id: string;
    name: string;
    content: string;
}

export interface SessionData {
    name: string;
    inputs: Record<string, string>;
    outputs: Record<string, string>;
    telemetry: Record<string, CallTelemetry>;
    activePrompts: Record<string, string>;
    owlQueue: OwlFile[];
}

export interface LogEntry {
    id: string;
    timestamp: number;
    message: string;
    type: 'info' | 'success' | 'warning' | 'error';
}
