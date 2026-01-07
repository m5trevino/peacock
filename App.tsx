import React, { useState, useEffect, useRef, useMemo } from 'react';
import axios from 'axios';
import Dexie, { Table } from 'dexie';
import { motion, AnimatePresence } from 'framer-motion';
import { PipelineStage, ModelConfig, StageSettings, CallTelemetry, OwlFile, PromptTemplate, Session } from './types';
import { audioService } from './services/audioService';

// ============================================================ 
// 💀 PEACOCK V21: THE OMERTA DATABASE
// ============================================================ 
class PeacockDB extends Dexie {
  prompts!: Table<PromptTemplate>;
  sessions!: Table<Session>;
  models!: Table<ModelConfig>;

  constructor() {
    super('PeacockV21_WarRoom');
    this.version(1).stores({
      prompts: 'id',
      sessions: 'id, timestamp',
      models: 'id, gateway'
    });
  }
}

const db = new PeacockDB();

// ============================================================ 
// ⚡ VISUAL DOCTRINE CONSTANTS
// ============================================================ 
const THEME = {
  void: '#050505',
  matrix: '#00FF41',
  voltage: '#FFD700',
  error: '#FF3131',
  surface: '#0A0A0A',
  border: '#1A1A1A',
  shadow: 'rgba(0, 255, 65, 0.2)'
};

const STAGES = [
  { id: PipelineStage.SPARK, label: 'SPARK', row: 1, col: 1 },
  { id: PipelineStage.FALCON, label: 'FALCON', row: 1, col: 2 },
  { id: PipelineStage.EAGLE, label: 'EAGLE', row: 2, col: 1 },
  { id: PipelineStage.OWL, label: 'OWL_HANGAR', row: 2, col: 2 },
  { id: PipelineStage.HAWK, label: 'HAWK', row: 3, col: 1.5 }
];

const ENGINE_URL = 'http://localhost:8888/v1';

// ============================================================ 
// 🧠 PEACOCK V21: CORE ORCHESTRATOR
// ============================================================ 
const App: React.FC = () => {
  // --- STATE: SESSION ---
  const [sessionId, setSessionId] = useState<string>(`SESSION_${Date.now()}`);
  const [sessionName, setSessionName] = useState<string>('NEW_UNNAMED_OP');
  
  // --- STATE: NAVIGATION & UI ---
  const [activeStage, setActiveStage] = useState<PipelineStage>(PipelineStage.SPARK);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<'nodes' | 'prompts' | 'casino' | 'engine'>('nodes');
  const [cliOpen, setCliOpen] = useState(true);
  const [dossierOpen, setDossierOpen] = useState(false);
  const [dossierData, setDossierOpenData] = useState<{stage: string, stats: any} | null>(null);

  // --- STATE: DATA ---
  const [inputs, setInputs] = useState<Record<string, string>>({
    spark: '', falcon: '', eagle: '', owl: '', hawk: ''
  });
  const [outputs, setOutputs] = useState<Record<string, string>>({
    spark: '', falcon: '', eagle: '', owl: '', hawk: ''
  });
  const [telemetry, setTelemetry] = useState<Record<string, CallTelemetry>>({
    spark: { status: 'idle' }, falcon: { status: 'idle' }, eagle: { status: 'idle' }, owl: { status: 'idle' }, hawk: { status: 'idle' }
  });

  // --- STATE: OWL QUEUE ---
  const [owlQueue, setOwlQueue] = useState<OwlFile[]>([]);
  const [activeOwlFile, setActiveOwlFile] = useState<OwlFile | null>(null);

  // --- STATE: CONFIG ---
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [stageSettings, setStageSettings] = useState<Record<string, StageSettings>>({
    spark: { model: 'gemini-2.0-flash-exp', temperature: 0.7 },
    falcon: { model: 'gemini-2.0-flash-exp', temperature: 0.5 },
    eagle: { model: 'gemini-2.0-flash-exp', temperature: 0.3 },
    owl: { model: 'gemini-2.0-flash-exp', temperature: 0.2 },
    hawk: { model: 'gemini-2.0-flash-exp', temperature: 0.4 }
  });
  const [casinoSettings, setCasinoSettings] = useState({ vibrations: true, audio: true, scanlines: true });
  const [ammoFiles, setAmmoFiles] = useState<string[]>([]);
  const [ammoUsed, setAmmoUsed] = useState<string | null>(null);

  // --- STATE: CLI ---
  const [logs, setLogs] = useState<{ t: string, msg: string, type: 'info' | 'error' | 'success' }[]>([]);

  // --- HELPERS ---
  const addLog = (msg: string, type: 'info' | 'error' | 'success' = 'info') => {
    setLogs(prev => [{ t: new Date().toLocaleTimeString(), msg, type }, ...prev].slice(0, 100));
  };

  // --- INITIALIZATION ---
  useEffect(() => {
    const boot = async () => {
      addLog("Initializing Peacock V21 Neural Bracket...");
      try {
        const mRes = await axios.get(`${ENGINE_URL}/models`);
        setModels(mRes.data);
        await db.models.bulkPut(mRes.data);
        addLog(`Engine active. ${mRes.data.length} nodes loaded.`);
      } catch (e) {
        const cached = await db.models.toArray();
        setModels(cached);
        addLog("Engine unreachable. Loading cached nodes.", "error");
      }

      try {
        const pRes = await axios.get(`${ENGINE_URL}/fs/prompts`);
        await db.prompts.bulkPut(pRes.data);
        addLog("Prompt Armory synced with disk.");
      } catch (e) {
        addLog("Prompt sync failed.", "error");
      }

      try {
        const aRes = await axios.get(`${ENGINE_URL}/fs/ammo`);
        setAmmoFiles(aRes.data);
        addLog(`Ammo Cache indexed: ${aRes.data.length} items.`);
      } catch (e) {}
    };
    boot();
  }, []);

  // --- PERSISTENCE ---
  useEffect(() => {
    const saveSession = async () => {
      await db.sessions.put({
        id: sessionId,
        name: sessionName,
        timestamp: Date.now(),
        ammoUsed: ammoUsed || undefined,
        inputs,
        outputs,
        telemetry,
        owlQueue
      });
    };
    if (outputs.spark || outputs.falcon) saveSession();
  }, [inputs, outputs, telemetry, owlQueue, sessionName, ammoUsed]);

  // --- STRIKE LOGIC ---
  const executeStrike = async (stageId: PipelineStage, customPrompt?: string) => {
    setTelemetry(prev => ({ ...prev, [stageId]: { status: 'loading' } }));
    addLog(`Initiating strike on ${stageId.toUpperCase()}...`);
    if (casinoSettings.audio) audioService.playSuccess();

    try {
      const promptTemplate = await db.prompts.get(stageId === PipelineStage.OWL ? 'owl_v21' : stageId);
      const payload = inputs[stageId];
      const fullPrompt = customPrompt || (promptTemplate?.content.replace('{input}', payload) || payload);

      const startTime = Date.now();
      const res = await axios.post(`${ENGINE_URL}/strike`, {
        modelId: stageSettings[stageId].model,
        prompt: fullPrompt,
        temp: stageSettings[stageId].temperature
      });

      const output = res.data.content;
      const keyUsed = res.data.keyUsed || "DEALER_UNKNOWN";
      const stats = {
        words: output.split(/\s+/).length,
        tokens: Math.ceil(output.length / 4),
        chars: output.length
      };

      setOutputs(prev => ({ ...prev, [stageId]: output }));
      setTelemetry(prev => ({ ...prev, [stageId]: { status: 'success', keyUsed, stats } }));
      addLog(`Strike Success [${keyUsed}]. Payload: ${stats.tokens} tokens.`, "success");

      // Set Dossier
      setDossierOpenData({ stage: stageId, stats });
      setDossierOpen(true);

      // Automatic Ports
      if (stageId === PipelineStage.SPARK) setInputs(v => ({ ...v, falcon: output }));
      if (stageId === PipelineStage.FALCON) setInputs(v => ({ ...v, eagle: output }));
      if (stageId === PipelineStage.EAGLE) parseEagleOutput(output);
      
      if (casinoSettings.audio) audioService.playSuccess();
    } catch (err: any) {
      const keyUsed = err.response?.data?.keyUsed || "DEALER_FAILED";
      setTelemetry(prev => ({ ...prev, [stageId]: { status: 'error', errorMessage: err.message, keyUsed } }));
      addLog(`CRITICAL FAILURE: ${err.message} [KEY: ${keyUsed}]`, "error");
      if (casinoSettings.audio) audioService.playError();
    }
  };

  const parseEagleOutput = (output: string) => {
    const fileRegex = /cat << '.*?' > (.*?)\n([\s\S]*)EOF/g;
    const directivesRegex = /### DIRECTIVES([\s\S]*?)(?=###|$)/i;
    
    const directives = output.match(directivesRegex)?.[1] || "Follow EAGLE skeleton precision.";
    const matches = [...output.matchAll(fileRegex)];
    
    const queue: OwlFile[] = matches.map((m, i) => ({
      id: `file-${i}`,
      path: m[1].trim(),
      skeleton: m[2],
      directives: directives.trim(),
      status: 'pending'
    }));

    setOwlQueue(queue);
    addLog(`Eagle skeleton analyzed. ${queue.length} OWL implementation tasks armed.`);
  };

  const strikeOwlFile = async (file: OwlFile) => {
    setActiveOwlFile(file);
    setTelemetry(prev => ({ ...prev, owl: { status: 'loading' } }));
    addLog(`Implementing ${file.path} via OWL...`);

    try {
      const promptTemplate = await db.prompts.get('owl_v21');
      const context = `
PHASE CHAIN CONTEXT:
SPARK: ${outputs.spark}
FALCON: ${outputs.falcon}
EAGLE DIRECTIVES: ${file.directives}
`;

      const res = await axios.post(`${ENGINE_URL}/strike`, {
        modelId: stageSettings.owl.model,
        prompt: promptTemplate?.content
          .replace('{skeleton}', file.skeleton)
          .replace('{directives}', file.directives)
          .replace('{context}', context)
          .replace('{path}', file.path) || `Implement: ${file.path}\n${file.skeleton}`,
        temp: stageSettings.owl.temperature
      });

      const output = res.data.content;
      const keyUsed = res.data.keyUsed || "DEALER_UNKNOWN";
      const stats = {
        words: output.split(/\s+/).length,
        tokens: Math.ceil(output.length / 4),
        chars: output.length
      };

      setOwlQueue(q => q.map(f => f.id === file.id ? { ...f, status: 'completed', output } : f));
      setTelemetry(prev => ({ ...prev, owl: { status: 'success', keyUsed, stats } }));
      addLog(`File ${file.path} implementation complete.`, "success");
      
      setDossierOpenData({ stage: `OWL: ${file.path}`, stats });
      setDossierOpen(true);
      
      audioService.playSuccess();
    } catch (err: any) {
      const keyUsed = err.response?.data?.keyUsed || "DEALER_FAILED";
      setTelemetry(prev => ({ ...prev, owl: { status: 'error', errorMessage: err.message, keyUsed } }));
      addLog(`OWL implementation failed: ${file.path}`, "error");
      audioService.playError();
    }
  };

  const loadAmmo = async (fileName: string) => {
    try {
      const res = await axios.get(`${ENGINE_URL}/fs/ammo/${fileName}`);
      setInputs(v => ({ ...v, spark: res.data.content }));
      setAmmoUsed(fileName);
      setActiveStage(PipelineStage.SPARK);
      addLog(`Ammo loaded: ${fileName}`);
      audioService.playSuccess();
    } catch (e) { addLog("Failed to load ammo.", "error"); }
  };

  const loadSession = (s: Session) => {
    setSessionId(s.id);
    setSessionName(s.name);
    setInputs(s.inputs);
    setOutputs(s.outputs);
    setTelemetry(s.telemetry);
    setOwlQueue(s.owlQueue);
    setAmmoUsed(s.ammoUsed || null);
    
    // Determine best active stage to show
    const stages = Object.values(PipelineStage);
    const lastDone = stages.reverse().find(st => s.telemetry[st]?.status === 'success');
    setActiveStage(lastDone || PipelineStage.SPARK);
    
    addLog(`Reloaded War Session: ${s.id}`);
  };

  const [railTab, setRailTab] = useState<'ammo' | 'sessions' | 'history'>('sessions');
  const [sessionHistory, setSessionHistory] = useState<Session[]>([]);

  useEffect(() => {
    const fetchHistory = async () => {
      const h = await db.sessions.orderBy('timestamp').reverse().toArray();
      setSessionHistory(h);
    };
    fetchHistory();
  }, [railTab, sessionId]); // Refresh on tab change or after a strike saves session

  const [ghostOpen, setGhostOpen] = useState(false);
  const [ghostData, setGhostData] = useState<{ title: string, content: string }>({ title: '', content: '' });

  const openGhost = (title: string, content: string) => {
    setGhostData({ title, content });
    setGhostOpen(true);
    addLog(`Opening Ghost Inspector: ${title}`);
  };

  const [historyItems, setHistoryItems] = useState<any[]>([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState<number | null>(null);

  useEffect(() => {
    const fetchHistory = async () => {
      const h = await db.history.orderBy('timestamp').reverse().toArray();
      setHistoryItems(h);
    };
    if (railTab === 'history') fetchHistory();
  }, [railTab]);

  const HistoryPane = () => (
    <div className="flex flex-col gap-4 h-full overflow-hidden">
      <h3 className="text-[7px] font-black text-zinc-800 uppercase mb-2 tracking-[0.2em]">War_History_Archive</h3>
      <div className="flex-1 overflow-y-auto custom-scrollbar space-y-2">
        {historyItems.map(h => (
          <div 
            key={h.id} 
            onClick={() => setSelectedHistoryId(h.id)}
            className={`p-3 bg-zinc-950 border transition-all rounded cursor-pointer group ${selectedHistoryId === h.id ? 'border-matrix shadow-[0_0_10px_rgba(0,255,65,0.2)]' : 'border-zinc-900 hover:border-zinc-700'}`}
          >
            <div className="flex justify-between items-center mb-2">
              <span className={`text-[8px] font-black uppercase ${selectedHistoryId === h.id ? 'text-matrix' : 'text-zinc-500'}`}>{h.stage}</span>
              <span className="text-[6px] text-zinc-800">{new Date(h.timestamp).toLocaleTimeString()}</span>
            </div>
            
            <div className="grid grid-cols-2 gap-2">
              <div className={`p-2 rounded bg-void text-[7px] truncate ${selectedHistoryId === h.id ? 'text-zinc-300' : 'text-zinc-700'}`}>
                PAYLOAD: {h.input.substring(0, 50)}...
              </div>
              <div className={`p-2 rounded bg-void text-[7px] truncate ${selectedHistoryId === h.id ? 'text-matrix/60' : 'text-zinc-700'}`}>
                INTEL: {h.output.substring(0, 50)}...
              </div>
            </div>

            {selectedHistoryId === h.id && (
              <div className="mt-3 flex gap-2">
                <button 
                  onClick={(e) => { e.stopPropagation(); openGhost(`${h.stage.toUpperCase()}_PAYLOAD`, h.input); }}
                  className="flex-1 py-1 bg-zinc-900 text-[6px] font-black uppercase text-zinc-400 hover:text-white border border-zinc-800"
                >
                  View_Payload
                </button>
                <button 
                  onClick={(e) => { e.stopPropagation(); openGhost(`${h.stage.toUpperCase()}_INTEL`, h.output); }}
                  className="flex-1 py-1 bg-matrix/10 text-[6px] font-black uppercase text-matrix hover:bg-matrix hover:text-void border border-matrix/20"
                >
                  View_Intel
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );

  const wipeStage = async (stageId: PipelineStage) => {
    if (!confirm(`WIPE INTEL FOR ${stageId.toUpperCase()}? This will clear all downstream progress.`)) return;

    setOutputs(prev => ({ ...prev, [stageId]: '' }));
    setTelemetry(prev => ({ ...prev, [stageId]: { status: 'idle' } }));
    
    if (stageId === PipelineStage.EAGLE) {
      setOwlQueue([]);
      setActiveOwlFile(null);
      setOutputs(prev => ({ ...prev, owl: '' }));
      setTelemetry(prev => ({ ...prev, owl: { status: 'idle' } }));
    }

    // Set the next stage's input to empty since the source is gone
    const stageIndex = STAGES.findIndex(s => s.id === stageId);
    const nextStage = STAGES[stageIndex + 1]?.id;
    if (nextStage) {
      setInputs(prev => ({ ...prev, [nextStage]: '' }));
    }

    setActiveStage(stageId);
    addLog(`Phase Wiped: ${stageId.toUpperCase()}. Ready for re-strike.`, "info");
    audioService.playError();
  };

  const DescrambleText = ({ text }: { text: string }) => {
    const [display, setDisplay] = useState('');
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$#@%&*";
    useEffect(() => {
      let iteration = 0;
      const interval = setInterval(() => {
        setDisplay(text.split('').map((c, i) => i < iteration ? text[i] : chars[Math.floor(Math.random() * chars.length)]).join(''));
        if (iteration >= text.length) clearInterval(interval);
        iteration += 1 / 2;
      }, 20);
      return () => clearInterval(interval);
    }, [text]);
    return <span>{display}</span>;
  };

  const GhostOverlay = () => (
    <AnimatePresence>
      {ghostOpen && (
        <motion.div 
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          className="fixed inset-0 z-[250] bg-black/90 backdrop-blur-xl flex items-center justify-center p-20"
        >
          <motion.div 
            initial={{ scale: 0.9, y: 20 }} animate={{ scale: 1, y: 0 }}
            className="w-full max-w-6xl h-full bg-surface border border-matrix/30 rounded-[3rem] flex flex-col overflow-hidden shadow-[0_0_100px_rgba(0,255,65,0.1)]"
          >
            <div className="p-8 border-b border-border flex justify-between items-center bg-black/40">
              <div className="flex items-center gap-4">
                <div className="w-3 h-3 bg-matrix rounded-full animate-pulse" />
                <h2 className="text-2xl font-black text-white tracking-tighter uppercase italic">{ghostData.title}</h2>
              </div>
              <button onClick={() => setGhostOpen(false)} className="w-12 h-12 rounded-full border border-zinc-800 flex items-center justify-center text-zinc-500 hover:text-matrix transition-all hover:border-matrix">✕</button>
            </div>
            <div className="flex-1 p-12 overflow-y-auto custom-scrollbar bg-void/50">
              <pre className="text-sm mono text-matrix/70 whitespace-pre-wrap leading-relaxed">
                {ghostData.content || "NO_DATA_STREAM_AVAILABLE"}
              </pre>
            </div>
            <div className="p-6 border-t border-border bg-black/20 flex justify-end">
              <button onClick={() => { navigator.clipboard.writeText(ghostData.content); audioService.playSuccess(); }} className="px-8 py-3 bg-zinc-900 border border-zinc-800 text-[10px] font-black text-matrix uppercase tracking-widest hover:bg-zinc-800 transition-all">Copy_Stream_To_Clipboard</button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );

  const TacticalModelPicker = ({ currentModelId, onSelect, stageId }: any) => {
    const [isOpen, setIsOpen] = useState(false);
    const [activeGateway, setActiveGateway] = useState<string | null>(null);
    const menuRef = useRef<HTMLDivElement>(null);

    const gateways = useMemo(() => {
      const g = Array.from(new Set(models.map(m => m.gateway)));
      return g.length > 0 ? g : ["groq", "google", "mistral", "deepseek"];
    }, [models]);

    const modelsByGateway = (g: string) => models.filter(m => m.gateway === g);

    return (
      <div className="relative inline-block text-left z-[100]" ref={menuRef}>
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="bg-black border border-zinc-800 rounded px-4 py-2 text-[10px] text-zinc-400 min-w-[200px] flex justify-between items-center hover:border-matrix/50 transition-all shadow-inner group"
        >
          <div className="flex flex-col items-start truncate">
            <span className="text-[6px] text-zinc-700 font-black uppercase tracking-widest">Active_Node</span>
            <span className="truncate font-black text-white group-hover:text-matrix transition-colors">{currentModelId || 'SELECT_NODE'}</span>
          </div>
          <span className="text-zinc-800 text-[8px] ml-2 group-hover:text-matrix">▼</span>
        </button>

        <AnimatePresence>
          {isOpen && (
            <motion.div 
              initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}
              className="absolute left-0 mt-2 w-48 bg-void border border-zinc-800 rounded-lg shadow-2xl z-[120] backdrop-blur-3xl py-2"
            >
              {gateways.map(g => (
                <div key={g} className="relative group/gate" onMouseEnter={() => setActiveGateway(g)}>
                  <button className={`w-full text-left px-4 py-3 text-[9px] font-black uppercase tracking-widest flex justify-between items-center transition-all ${activeGateway === g ? 'text-matrix bg-zinc-900' : 'text-zinc-600 hover:text-zinc-300'}`}>
                    <span>{g}_GW</span>
                    <span className="opacity-40 text-[7px]">▶</span>
                  </button>
                  
                  {activeGateway === g && (
                    <motion.div 
                      initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                      className="absolute left-full top-0 w-64 bg-void border border-zinc-800 rounded-lg shadow-2xl z-[130] backdrop-blur-3xl py-2 ml-1"
                    >
                      <div className="max-h-[400px] overflow-y-auto custom-scrollbar pr-1">
                        {modelsByGateway(g).map(m => (
                          <div key={m.id} className="relative group/model">
                            <button
                              onClick={() => { onSelect(m.id); setIsOpen(false); }}
                              className={`w-full text-left px-4 py-3 hover:bg-zinc-900 transition-all border-b border-zinc-900/30 last:border-0 flex justify-between items-center ${m.id === currentModelId ? 'bg-matrix/10' : ''}`}
                            >
                              <span className={`text-[10px] font-black uppercase truncate ${m.id === currentModelId ? 'text-matrix' : 'text-zinc-200'}`}>{m.id}</span>
                              <span className={`text-[6px] font-black uppercase px-1.5 py-0.5 rounded shrink-0 ${m.tier === 'expensive' ? 'bg-red-950 text-red-500' : 'bg-matrix/20 text-matrix'}`}>{m.tier[0]}</span>
                            </button>
                            
                            {/* Level 3: Intel Tooltip */}
                            <div className="hidden group-hover/model:block absolute left-full top-0 w-56 bg-zinc-950 border border-zinc-800 rounded p-4 shadow-2xl z-[150] ml-2 ring-1 ring-matrix/30 animate-in fade-in zoom-in-95">
                               <span className="text-[7px] font-black text-matrix uppercase block mb-2 tracking-widest">Technical_Intel</span>
                               <p className="text-[9px] text-zinc-400 italic leading-snug">{m.note}</p>
                               <div className="mt-3 flex justify-between border-t border-zinc-900 pt-2">
                                 <span className="text-[6px] text-zinc-700 font-black">GW: {m.gateway.toUpperCase()}</span>
                                 <span className="text-[6px] text-zinc-700 font-black">TIER: {m.tier.toUpperCase()}</span>
                               </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </motion.div>
                  )}
                </div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    );
  };

  const BracketNode = ({ stage }: { stage: typeof STAGES[0] }) => {
    const tel = telemetry[stage.id];
    const isSuccess = tel.status === 'success';
    const isError = tel.status === 'error';
    const isLoading = tel.status === 'loading';
    const isActive = activeStage === stage.id;

    return (
      <div 
        className="absolute flex flex-col items-center gap-3"
        style={{ top: `${stage.row * 250 - 150}px`, left: `${stage.col * 300 - 150}px` }}
      >
        <motion.div
          whileHover={{ scale: 1.05 }}
          onClick={() => setActiveStage(stage.id)}
          className={`w-32 h-32 rounded-3xl border-4 flex flex-col items-center justify-center cursor-pointer transition-all relative overflow-hidden bg-void ${isActive ? 'scale-110 shadow-[0_0_30px_#FFD700]' : ''} ${isSuccess ? 'border-matrix shadow-[0_0_20px_#00FF41]' : isError ? 'border-error shadow-[0_0_20px_#FF3131]' : isLoading ? 'border-voltage animate-pulse' : 'border-zinc-900'}`}
        >
          {isLoading && <motion.div className="absolute inset-0 bg-voltage/10 animate-shake" />}
          <span className={`text-4xl font-black ${isSuccess ? 'text-matrix' : isError ? 'text-error' : 'text-zinc-700'}`}>
            {stage.label[0]}
          </span>
          <span className="text-[8px] font-black text-zinc-500 uppercase tracking-widest mt-1">{stage.label}</span>
          
          {isSuccess && <div className="absolute top-2 right-2 w-3 h-3 bg-matrix rounded-full animate-ping" />}
        </motion.div>

        {/* Intelligence Slot */}
        <div className="w-48 bg-zinc-950 border border-zinc-900 rounded-xl p-3 flex flex-col gap-1 shadow-2xl">
          <span className="text-[7px] font-black text-zinc-700 uppercase tracking-widest">
            {stage.id === 'spark' ? 'AMMO_REF' : 'INTEL_UPSTREAM'}
          </span>
          <button 
            className="text-[9px] font-black text-zinc-400 truncate text-left hover:text-matrix transition-colors italic outline-none"
            onClick={(e) => { 
              e.stopPropagation();
              const title = stage.id === 'spark' ? `AMMO: ${ammoUsed}` : `${stage.label}_INPUT_STREAM`;
              const content = stage.id === 'spark' ? inputs.spark : inputs[stage.id];
              openGhost(title, content);
            }}
          >
            {stage.id === 'spark' ? (ammoUsed || 'AWAITING_AMMO...') : 
             stage.id === 'falcon' ? (outputs.spark ? 'SPARK_STRATEGIC_PAYLOAD' : 'NULL') : 
             stage.id === 'eagle' ? (outputs.falcon ? 'FALCON_ARCH_SPEC' : 'NULL') : 
             stage.id === 'owl' ? `${owlQueue.filter(f => f.status === 'completed').length}/${owlQueue.length} FILES IMPLEMENTED` : 
             (outputs.eagle ? 'EAGLE_IMPLEMENTATION' : 'NULL')
            }
          </button>
          {tel.stats && (
            <div className="flex justify-between mt-1 border-t border-zinc-900 pt-1">
              <span className="text-[6px] text-zinc-800">W: {tel.stats.words}</span>
              <span className="text-[6px] text-zinc-800">T: {tel.stats.tokens}</span>
              <span className="text-[6px] text-zinc-800">C: {tel.stats.chars}</span>
            </div>
          )}
          {isError && (
            <div className="mt-1 bg-error/10 text-error text-[7px] font-black p-1 rounded animate-pulse">
              FAIL: {tel.keyUsed}
            </div>
          )}
        </div>
      </div>
    );
  };

  const LaserLines = () => {
    const packetVariants = {
      animate: {
        offset: [0, 100],
        transition: { repeat: Infinity, duration: 2, ease: "linear" }
      }
    };

    return (
      <svg className="absolute inset-0 w-full h-full pointer-events-none z-0 opacity-40">
        <defs>
          <linearGradient id="laserGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="transparent" />
            <stop offset="50%" stopColor={THEME.matrix} />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
        </defs>

        {/* SPARK -> FALCON */}
        <path d="M 150 100 H 450" stroke={outputs.spark ? THEME.matrix : THEME.border} strokeWidth="1" fill="none" />
        {outputs.spark && (
          <motion.circle r="3" fill={THEME.matrix} initial={{ offsetDistance: "0%" }} animate={{ offsetDistance: "100%" }} transition={{ repeat: Infinity, duration: 1.5, ease: "linear" }}>
            <motion.animateMotion path="M 150 100 H 450" dur="1.5s" repeatCount="indefinite" />
          </motion.circle>
        )}

        {/* FALCON -> EAGLE */}
        <path d="M 450 100 L 450 200 L 150 200 L 150 350" stroke={outputs.falcon ? THEME.matrix : THEME.border} strokeWidth="1" fill="none" />
        {outputs.falcon && (
          <motion.circle r="3" fill={THEME.matrix}>
            <motion.animateMotion path="M 450 100 L 450 200 L 150 200 L 150 350" dur="2s" repeatCount="indefinite" />
          </motion.circle>
        )}

        {/* EAGLE -> OWL */}
        <path d="M 150 350 H 450" stroke={outputs.eagle ? THEME.matrix : THEME.border} strokeWidth="1" fill="none" />
        {outputs.eagle && (
          <motion.circle r="3" fill={THEME.matrix}>
            <motion.animateMotion path="M 150 350 H 450" dur="1.5s" repeatCount="indefinite" />
          </motion.circle>
        )}

        {/* OWL -> HAWK */}
        <path d="M 450 350 L 450 450 L 300 450 L 300 600" stroke={owlQueue.every(f => f.status === 'completed') && owlQueue.length > 0 ? THEME.matrix : THEME.border} strokeWidth="1" fill="none" />
        {owlQueue.every(f => f.status === 'completed') && owlQueue.length > 0 && (
          <motion.circle r="3" fill={THEME.matrix}>
            <motion.animateMotion path="M 450 350 L 450 450 L 300 450 L 300 600" dur="2s" repeatCount="indefinite" />
          </motion.circle>
        )}
      </svg>
    );
  };

  return (
    <div className={`min-h-screen bg-void text-zinc-400 font-mono flex flex-col relative overflow-hidden ${casinoSettings.scanlines ? 'scanlines' : ''}`}>
      {/* Visual Ambiance */}
      <div className="absolute inset-0 opacity-[0.03] pointer-events-none bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')]" />
      
      {/* Top Header */}
      <header className="p-6 flex justify-between items-center border-b border-border relative z-[60] bg-black/90 backdrop-blur-md">
        <div className="flex items-center gap-6">
          <div className="w-12 h-12 bg-matrix flex items-center justify-center text-void font-black text-2xl shadow-[0_0_20px_#00FF41]">P</div>
          <div>
            <h1 className="text-3xl font-black text-white tracking-tighter italic">PEACOCK<span className="text-matrix">_V21</span></h1>
            <p className="text-[7px] font-black tracking-[0.5em] text-zinc-600 mt-1 uppercase">Omerta_War_Room // Precision_Pipeline</p>
          </div>
        </div>
        
        <div className="flex gap-4">
          <div className="flex flex-col items-end px-4 border-r border-border">
            <span className="text-[7px] text-zinc-700 font-black">ACTIVE_SESSION</span>
            <span className="text-[9px] text-matrix font-black">{sessionId}</span>
          </div>
          <button onClick={() => setSettingsOpen(true)} className="px-6 py-2 border border-zinc-800 text-[9px] font-black uppercase tracking-widest hover:border-matrix hover:text-white transition-all">Command_Deck</button>
          <button onClick={() => window.location.reload()} className="px-6 py-2 bg-matrix/10 text-matrix border border-matrix/20 text-[9px] font-black uppercase tracking-widest">Wipe_Op</button>
        </div>
      </header>

      <main className="flex-1 flex overflow-hidden relative">
        {/* Left Archive Rail */}
        <aside className="w-72 border-r border-border bg-surface/30 p-6 flex flex-col gap-6 relative z-50">
          <div className="flex gap-2 border-b border-zinc-900 pb-4">
            {['ammo', 'sessions', 'history'].map(t => (
              <button 
                key={t} onClick={() => setRailTab(t as any)}
                className={`text-[8px] font-black uppercase tracking-widest px-3 py-1 rounded-full transition-all ${railTab === t ? 'bg-matrix text-void' : 'text-zinc-600 hover:text-zinc-400'}`}
              >
                {t}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar">
            {railTab === 'ammo' && (
              <div className="space-y-1">
                <h3 className="text-[7px] font-black text-zinc-800 uppercase mb-2 tracking-[0.2em]">Active_Ammo</h3>
                {ammoFiles.map(f => (
                  <button 
                    key={f} onClick={() => loadAmmo(f)}
                    className={`w-full text-left px-3 py-2 bg-zinc-950 border border-zinc-900 hover:border-matrix/30 transition-all rounded text-[9px] truncate group flex justify-between items-center ${ammoUsed === f ? 'text-matrix border-matrix/40' : 'text-zinc-500 hover:text-white'}`}
                  >
                    <span>{f}</span>
                    <span className="opacity-0 group-hover:opacity-100">▶</span>
                  </button>
                ))}
              </div>
            )}

            {railTab === 'sessions' && (
              <div className="space-y-2">
                <h3 className="text-[7px] font-black text-zinc-800 uppercase mb-2 tracking-[0.2em]">Vaulted_Sessions</h3>
                {sessionHistory.length === 0 ? (
                  <div className="p-3 bg-zinc-900/20 border border-zinc-900 rounded text-[8px] text-zinc-700 italic">Vault is currently empty.</div>
                ) : (
                  sessionHistory.map(s => (
                    <button 
                      key={s.id} onClick={() => loadSession(s)}
                      className={`w-full text-left p-3 bg-zinc-950 border transition-all rounded flex flex-col gap-1 ${sessionId === s.id ? 'border-matrix/40 bg-matrix/5' : 'border-zinc-900 hover:border-zinc-700'}`}
                    >
                      <div className="flex justify-between items-center">
                        <span className="text-[9px] font-black text-white truncate w-32">{s.name}</span>
                        <span className="text-[6px] text-zinc-800">{new Date(s.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <span className="text-[7px] text-zinc-600 uppercase tracking-tighter">{s.id}</span>
                    </button>
                  ))
                )}
              </div>
            )}

            {railTab === 'history' && (
              <HistoryPane />
            )}
          </div>
        </aside>

        {/* Center: The Neural Bracket Map */}
        <div className="flex-1 relative overflow-auto custom-scrollbar bg-black/20 p-20">
          <div className="min-w-[1000px] min-h-[800px] relative">
            <LaserLines />
            {STAGES.map(s => <BracketNode key={s.id} stage={s} />)}
          </div>
        </div>

        {/* Right Pane: Live Inspector */}
        <aside className="w-[500px] border-l border-border bg-black/40 flex flex-col relative z-50">
          <div className="p-6 border-b border-border bg-black/60 flex justify-between items-center">
            <div className="flex items-center gap-3">
              <div className={`w-2 h-2 rounded-full ${telemetry[activeStage].status === 'loading' ? 'bg-voltage animate-ping' : 'bg-matrix'}`} />
              <span className="text-[10px] font-black uppercase tracking-[0.2em] text-white">
                <DescrambleText text={`INSPECTING_${activeStage.toUpperCase()}`} />
              </span>
            </div>
            <div className="flex items-center gap-4">
              {outputs[activeStage] && (
                <button 
                  onClick={() => wipeStage(activeStage)}
                  className="px-4 py-2 border border-error/30 text-error text-[8px] font-black uppercase tracking-widest hover:bg-error hover:text-white transition-all mr-2"
                >
                  Wipe_Intel
                </button>
              )}
              <TacticalModelPicker 
                currentModelId={stageSettings[activeStage].model}
                onSelect={(mid: string) => setStageSettings(v => ({ ...v, [activeStage]: { ...v[activeStage], model: mid } }))}
                stageId={activeStage}
              />
              <button 
                onClick={() => {
                  if (activeStage === PipelineStage.OWL && activeOwlFile) strikeOwlFile(activeOwlFile);
                  else executeStrike(activeStage);
                }}
                disabled={telemetry[activeStage].status === 'loading' || (activeStage === PipelineStage.OWL && !activeOwlFile)}
                className="px-6 py-2 bg-matrix text-void font-black text-[9px] uppercase tracking-widest hover:bg-white transition-all disabled:opacity-50"
              >
                {activeStage === PipelineStage.OWL ? (activeOwlFile ? 'Strike_File' : 'Select_File') : 'Strike_Now'}
              </button>
            </div>
          </div>

          <div className="flex-1 flex flex-col p-6 gap-6 overflow-hidden">
            <div className="flex-1 flex flex-col gap-2">
              <span className="text-[7px] font-black text-zinc-700 uppercase">Input_Payload</span>
              <textarea 
                className="flex-1 bg-black/40 border border-zinc-900 rounded-lg p-4 text-xs mono text-zinc-400 outline-none focus:border-matrix/30 resize-none custom-scrollbar"
                value={inputs[activeStage]}
                onChange={(e) => setInputs(v => ({ ...v, [activeStage]: e.target.value }))}
              />
            </div>
            <div className="flex-1 flex flex-col gap-2">
              <span className="text-[7px] font-black text-zinc-700 uppercase">Output_Intelligence</span>
              <div className="flex-1 bg-zinc-950 border border-zinc-900 rounded-lg p-4 text-xs mono text-matrix/80 overflow-y-auto custom-scrollbar whitespace-pre-wrap relative">
                {outputs[activeStage] || "WAITING_FOR_INTEL..."}
              </div>
            </div>
          </div>
        </aside>
      </main>

      {/* Bottom CLI: The Black Box */}
      <AnimatePresence>
        {cliOpen && (
          <motion.footer 
            initial={{ height: 40 }} animate={{ height: 250 }} exit={{ height: 40 }}
            className="w-full bg-black border-t border-matrix/30 relative z-[100] flex flex-col shadow-[0_-10px_40px_rgba(0,0,0,0.8)]"
          >
            <div 
              className="h-10 border-b border-zinc-900 bg-zinc-950 flex justify-between items-center px-6 cursor-pointer hover:bg-zinc-900 transition-all"
              onClick={() => setCliOpen(!cliOpen)}
            >
              <div className="flex items-center gap-4">
                <span className="text-[8px] font-black text-matrix tracking-[0.3em] animate-pulse">VERBATIM_SYSTEM_SYNC</span>
                <span className="text-[7px] text-zinc-700 uppercase">Black_Box_Recorder</span>
              </div>
              <span className="text-zinc-600 text-xs">{cliOpen ? '▼' : '▲'}</span>
            </div>
            
            <div className="flex-1 overflow-y-auto p-6 font-mono text-[10px] space-y-1 custom-scrollbar">
              {logs.map((l, i) => (
                <div key={i} className={`flex gap-4 ${l.type === 'error' ? 'text-error' : l.type === 'success' ? 'text-matrix' : 'text-zinc-500'}`}>
                  <span className="opacity-30">[{l.t}]</span>
                  <span className="font-black opacity-50 uppercase">{l.type === 'info' ? 'SYS' : l.type.toUpperCase()}</span>
                  <span className="tracking-tighter">{l.msg}</span>
                </div>
              ))}
              <div className="text-matrix opacity-20">_</div>
            </div>
          </motion.footer>
        )}
      </AnimatePresence>

      {/* Success Dossier Modal */}
      <AnimatePresence>
        {dossierOpen && dossierData && (
          <div className="fixed inset-0 z-[200] flex items-center justify-center p-8 bg-black/90 backdrop-blur-md">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
              className="w-[500px] bg-surface border-2 border-matrix rounded-[2rem] p-10 flex flex-col gap-8 shadow-[0_0_100px_rgba(0,255,65,0.2)]"
            >
              <div className="flex justify-between items-start">
                <div>
                  <h2 className="text-3xl font-black text-white italic">STRIKE_SUCCESS</h2>
                  <p className="text-[9px] font-black text-matrix uppercase tracking-widest mt-1">Operational_Intelligence_Verified</p>
                </div>
                <button onClick={() => setDossierOpen(false)} className="text-zinc-600 hover:text-white text-2xl">✕</button>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div className="p-4 bg-zinc-950 border border-zinc-900 rounded-xl flex flex-col items-center">
                  <span className="text-[7px] text-zinc-700 font-black uppercase">Words</span>
                  <span className="text-xl font-black text-white">{dossierData.stats.words}</span>
                </div>
                <div className="p-4 bg-zinc-950 border border-zinc-900 rounded-xl flex flex-col items-center">
                  <span className="text-[7px] text-zinc-700 font-black uppercase">Tokens</span>
                  <span className="text-xl font-black text-matrix">{dossierData.stats.tokens}</span>
                </div>
                <div className="p-4 bg-zinc-950 border border-zinc-900 rounded-xl flex flex-col items-center">
                  <span className="text-[7px] text-zinc-700 font-black uppercase">Chars</span>
                  <span className="text-xl font-black text-white">{dossierData.stats.chars}</span>
                </div>
              </div>

              <div className="p-6 bg-zinc-900/40 border border-zinc-800 rounded-2xl flex flex-col gap-2">
                <span className="text-[8px] font-black text-zinc-600 uppercase tracking-widest">Dealer_Hand</span>
                <div className="flex justify-between items-center">
                  <span className="text-xs font-black text-zinc-300">{telemetry[dossierData.stage].keyUsed}</span>
                  <span className="text-[8px] font-black text-matrix px-2 py-1 bg-matrix/10 rounded uppercase">Verified</span>
                </div>
              </div>

              <div className="flex flex-col gap-3">
                <button 
                  onClick={() => {
                    if (dossierData.stage.startsWith('OWL:')) {
                      const allDone = owlQueue.every(f => f.status === 'completed');
                      if (allDone) setActiveStage(PipelineStage.HAWK);
                      // If not all done, just dismiss so they can pick another file in the hangar
                    } else {
                      const next = STAGES[STAGES.findIndex(s => s.id === dossierData.stage) + 1]?.id;
                      if (next) setActiveStage(next as any);
                    }
                    setDossierOpen(false);
                  }}
                  className="w-full py-5 bg-matrix text-void font-black uppercase text-[11px] tracking-widest hover:bg-white transition-all shadow-xl"
                >
                  {dossierData.stage.startsWith('OWL:') 
                    ? (owlQueue.every(f => f.status === 'completed') ? 'Launch_Final_QA' : 'Return_To_Hangar')
                    : 'Launch_Next_Phase'}
                </button>
                <button onClick={() => setDossierOpen(false)} className="w-full py-4 border border-zinc-800 text-zinc-600 font-black uppercase text-[9px] tracking-widest hover:text-white transition-all">Dismiss_Dossier</button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <GhostOverlay />

      <SettingsOverlay 
        open={settingsOpen} setOpen={setSettingsOpen}
        tab={settingsTab} setTab={setSettingsTab}
        models={models} casino={casinoSettings} setCasino={setCasinoSettings}
      />

      <style>{`
        body { margin: 0; background: #000; overflow: hidden; font-family: 'JetBrains Mono', monospace; }
        .scanlines::before {
          content: ""; position: absolute; inset: 0; pointer-events: none; z-index: 1000;
          background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.1) 50%), 
                      linear-gradient(90deg, rgba(255, 0, 0, 0.03), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.03));
          background-size: 100% 3px, 2px 100%;
        }
        .custom-scrollbar::-webkit-scrollbar { width: 3px; height: 3px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #1a1a1a; border-radius: 10px; }
        @keyframes shake { 0%{transform:translate(1px,1px)} 50%{transform:translate(-1px,-1px)} 100%{transform:translate(0px,0px)} }
        .animate-shake { animation: shake 0.1s infinite; }
      `}</style>
    </div>
  );
};

const SettingsOverlay = ({ open, setOpen, tab, setTab, models, casino, setCasino }: any) => (
  <AnimatePresence>
    {open && (
      <>
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setOpen(false)} className="fixed inset-0 bg-black/80 z-[110]" />
        <motion.div initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }} className="fixed inset-y-0 right-0 w-[600px] bg-surface border-l border-border z-[120] p-10 flex flex-col gap-8 shadow-2xl">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-black text-white italic">COMMAND_DECK</h2>
            <button onClick={() => setOpen(false)} className="text-zinc-600 hover:text-white">✕</button>
          </div>
          <div className="flex gap-6 border-b border-border">
            {['nodes', 'prompts', 'casino', 'engine'].map(t => (
              <button key={t} onClick={() => setTab(t as any)} className={`pb-4 text-[10px] font-black uppercase tracking-widest ${tab === t ? 'text-matrix border-b-2 border-matrix' : 'text-zinc-700'}`}>{t}</button>
            ))}
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar pr-4">
            {tab === 'nodes' && models.map((m: any) => (
              <div key={m.id} className="p-5 bg-zinc-950 border border-zinc-900 rounded-lg mb-4">
                <div className="flex justify-between items-center mb-2">
                  <span className="text-[11px] font-black text-white">{m.id}</span>
                  <span className={`text-[7px] font-black uppercase px-2 py-0.5 rounded ${m.tier === 'expensive' ? 'bg-red-950/30 text-red-500' : 'bg-matrix/10 text-matrix'}`}>{m.tier}</span>
                </div>
                <p className="text-[9px] text-zinc-600 italic leading-relaxed">{m.note}</p>
              </div>
            ))}
            {tab === 'prompts' && <p className="text-[10px] text-zinc-700 italic">Access Prompts via main Agent View or through /home/flintx/prompts sync.</p>}
            {tab === 'casino' && Object.entries(casino).map(([k, v]: any) => (
              <div key={k} className="flex justify-between items-center p-5 bg-zinc-950 border border-zinc-900 rounded-lg mb-4">
                <span className="text-[10px] font-black uppercase text-white">{k}</span>
                <button onClick={() => setCasino((p: any) => ({ ...p, [k]: !v }))} className={`w-14 h-7 rounded-full border-2 ${v ? 'bg-matrix border-matrix' : 'bg-zinc-900 border-zinc-800'}`}>
                  <motion.div animate={{ x: v ? 28 : 4 }} className="w-4 h-4 bg-void rounded-full" />
                </button>
              </div>
            ))}
          </div>
        </motion.div>
      </>
    )}
  </AnimatePresence>
);

export default App;