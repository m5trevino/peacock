export enum PipelineStage {
  SPARK = 'spark',
  FALCON = 'falcon',
  EAGLE = 'eagle',
  OWL = 'owl',
  HAWK = 'hawk'
}

export interface ModelConfig {
  id: string;
  gateway: 'groq' | 'google' | 'deepseek' | 'mistral';
  tier: 'free' | 'cheap' | 'expensive' | 'custom';
  note: string;
}

export interface StageSettings {
  model: string;
  temperature: number;
}

export interface CallTelemetry {
  status: 'idle' | 'loading' | 'success' | 'error';
  errorMessage?: string;
  stats?: {
    words: number;
    tokens: number;
    chars: number;
  };
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
  phase: PipelineStage;
  content: string;
}

export interface SessionData {
  id: string;
  name: string;
  timestamp: number;
  ammoUsed?: string;
  inputs: Record<string, string>;
  outputs: Record<string, string>;
  telemetry: Record<string, CallTelemetry>;
  owlQueue: OwlFile[];
  activePrompts: Record<string, string>;
}