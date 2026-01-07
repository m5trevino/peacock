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
  fullCall?: string;
  errorMessage?: string;
  keyUsed?: string;
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

export interface PromptTemplate {
  id: string;
  content: string;
}

export interface Session {
  id: string;
  name: string;
  timestamp: number;
  ammoUsed?: string;
  inputs: Record<string, string>;
  outputs: Record<string, string>;
  telemetry: Record<string, CallTelemetry>;
  owlQueue: OwlFile[];
}