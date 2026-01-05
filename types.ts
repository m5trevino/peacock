
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

export interface HistoryItem {
  id?: number;
  stage: string;
  input: string;
  output: string;
  timestamp: number;
}
