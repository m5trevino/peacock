import React, { useState, useEffect, useRef, useMemo } from 'react';
import axios from 'axios';
import Dexie, { Table } from 'dexie';
import { motion, AnimatePresence } from 'framer-motion';
import { PipelineStage, ModelConfig, StageSettings, CallTelemetry, OwlFile, PromptTemplate, Session } from './types';
import { audioService } from './services/audioService';

// ============================================================ 
// 💀 PEACOCK V22: THE OMERTA DATABASE
// ============================================================ 
class PeacockDB extends Dexie {
  prompts!: Table<PromptTemplate>;
  sessions!: Table<Session>;
  models!: Table<ModelConfig>;
  history!: Table<{ id?: number; stage: string; input: string; output: string; timestamp: number }>;

  constructor() {
    super('PeacockV22_WarRoom');
    this.version(1).stores({
      prompts: 'id',
      sessions: 'id, timestamp',
      models: 'id, gateway',
      history: '++id, stage, timestamp'
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
  purple: '#BC13FE',
  cyan: '#00FFFF',
  error: '#FF3131',
  surface: '#0A0A0A',
  border: '#1A1A1A',
  shadow: 'rgba(0, 255, 65, 0.2)'
};

const LINK_COLORS: Record<string, string> = {
  nexus: THEME.matrix,
  spark: THEME.matrix,
  falcon: THEME.purple,
  eagle: THEME.voltage,
  owl: THEME.cyan
};

const STAGES = [
  { id: PipelineStage.NEXUS, label: 'NEXUS', row: 1, col: 0.5, linkColor: LINK_COLORS.nexus },
  { id: PipelineStage.SPARK, label: 'SPARK', row: 1, col: 1.5, linkColor: LINK_COLORS.spark },
  { id: PipelineStage.FALCON, label: 'FALCON', row: 1, col: 2.5, linkColor: LINK_COLORS.falcon },
  { id: PipelineStage.EAGLE, label: 'EAGLE', row: 2, col: 1.5, linkColor: LINK_COLORS.eagle },
  { id: PipelineStage.OWL, label: 'OWL_HANGAR', row: 2, col: 2.5, linkColor: LINK_COLORS.owl },
  { id: PipelineStage.HAWK, label: 'HAWK', row: 3, col: 2, linkColor: THEME.matrix }
];

const ENGINE_URL = 'http://localhost:8888/v1';

// ============================================================ 
// 🛠️ SHARED SUB-COMPONENTS
// ============================================================ 

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

// ============================================================ 
// 🧠 PEACOCK V22: CORE ORCHESTRATOR
// ============================================================ 
const App: React.FC = () => {
  // --- STATE ---
  const [sessionId, setSessionId] = useState<string>(`SESSION_${Date.now()}`);
  const [sessionName, setSessionName] = useState<string>('NEW_WAR_OP');
  const [activeStage, setActiveStage] = useState<PipelineStage>(PipelineStage.SPARK);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<'nodes' | 'prompts' | 'casino' | 'engine'>('nodes');
  const [dossierOpen, setDossierOpen] = useState(false);
  const [dossierData, setDossierOpenData] = useState<{stage: string, stats: any} | null>(null);
  
  const [inputs, setInputs] = useState<Record<string, string>>({ nexus: '', spark: '', falcon: '', eagle: '', owl: '', hawk: '' });
  const [outputs, setOutputs] = useState<Record<string, string>>({ nexus: '', spark: '', falcon: '', eagle: '', owl: '', hawk: '' });
  const [telemetry, setTelemetry] = useState<Record<string, CallTelemetry>>({
    nexus: { status: 'idle' }, spark: { status: 'idle' }, falcon: { status: 'idle' }, eagle: { status: 'idle' }, owl: { status: 'idle' }, hawk: { status: 'idle' }
  });
  
  const [owlQueue, setOwlQueue] = useState<OwlFile[]>([]);
  const [activeOwlFile, setActiveOwlFile] = useState<OwlFile | null>(null);
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [ammoFiles, setAmmoFiles] = useState<string[]>([]);
  const [ammoUsed, setAmmoUsed] = useState<string | null>(null);
  
  // Rails Logic
  const [railTab, setRailTab] = useState<'ammo' | 'gemini' | 'claude' | 'vault' | 'sessions'>('ammo');
  const [geminiRaw, setGeminiRaw] = useState<string[]>([]);
  const [geminiHumanized, setGeminiHumanized] = useState<string[]>([]);
  const [claudeHumanized, setClaudeHumanized] = useState<string[]>([]);
  const [vaultTree, setVaultTree] = useState<Record<string, string[]>>({});
  const [nexusPrompts, setNexusPrompts] = useState<string[]>([]);
  const [activeNexusPrompt, setActiveNexusPrompt] = useState<string | null>(null);
  
  const [cliHeight, setCliHeight] = useState(40);
  const [isDraggingCli, setIsDraggingCli] = useState(false);
  const [logs, setLogs] = useState<{ t: string, msg: string, type: 'info' | 'error' | 'success' }[]>([]);
  const [sessionHistory, setSessionHistory] = useState<Session[]>([]);
  const [ghostOpen, setGhostOpen] = useState(false);
  const [ghostData, setGhostData] = useState<{ title: string, content: string }>({ title: '', content: '' });

  const [stageSettings, setStageSettings] = useState<Record<string, StageSettings>>({
    nexus: { model: 'models/gemini-3-flash-preview', temperature: 0.7 },
    spark: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
    falcon: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.5 },
    eagle: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.3 },
    owl: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.2 },
    hawk: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.4 }
  });
  const [casinoSettings, setCasinoSettings] = useState({ vibrations: true, audio: true, scanlines: true });

  const addLog = (msg: string, type: 'info' | 'error' | 'success' = 'info') => {
    setLogs(prev => [{ t: new Date().toLocaleTimeString(), msg, type }, ...prev].slice(0, 100));
  };

  const handleMouseDown = () => setIsDraggingCli(true);
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDraggingCli) return;
      const newHeight = window.innerHeight - e.clientY;
      setCliHeight(Math.max(40, Math.min(newHeight, window.innerHeight * 0.95)));
    };
    const handleMouseUp = () => setIsDraggingCli(false);
    if (isDraggingCli) { window.addEventListener('mousemove', handleMouseMove); window.addEventListener('mouseup', handleMouseUp); }
    return () => { window.removeEventListener('mousemove', handleMouseMove); window.removeEventListener('mouseup', handleMouseUp); };
  }, [isDraggingCli]);

  const toggleCli = () => { setCliHeight(cliHeight > 40 ? 40 : window.innerHeight * 0.33); audioService.playSuccess(); };

  const refreshRails = async () => {
    try {
      const a = await axios.get(`${ENGINE_URL}/fs/ammo`); setAmmoFiles(a.data);
      const gr = await axios.get(`${ENGINE_URL}/nexus/list/staging`); setGeminiRaw(gr.data.map((f:any)=>f.name));
      const gh = await axios.get(`${ENGINE_URL}/nexus/list/gemini`); setGeminiHumanized(gh.data.map((f:any)=>f.name));
      const ch = await axios.get(`${ENGINE_URL}/nexus/list/claude`); setClaudeHumanized(ch.data.map((f:any)=>f.name));
      const vt = await axios.get(`${ENGINE_URL}/nexus/vault/list`); setVaultTree(vt.data);
      const pRes = await axios.get(`${ENGINE_URL}/nexus/prompts`); setNexusPrompts(pRes.data);
    } catch (e) {}
  };

  useEffect(() => {
    const boot = async () => {
      addLog("Initializing War Room...");
      try {
        const mRes = await axios.get(`${ENGINE_URL}/models`);
        setModels(mRes.data);
        addLog(`Engine ready. ${mRes.data.length} nodes active.`, "success");
      } catch (e) { addLog("Engine unreachable.", "error"); }
      refreshRails();
    };
    boot();
  }, []);

  useEffect(() => {
    const saveSession = async () => {
      await db.sessions.put({ id: sessionId, name: sessionName, timestamp: Date.now(), ammoUsed: ammoUsed || undefined, inputs, outputs, telemetry, owlQueue });
    };
    if (outputs.spark || outputs.falcon) saveSession();
  }, [inputs, outputs, telemetry, owlQueue, sessionName, ammoUsed]);

  useEffect(() => {
    const fetchHistory = async () => { setSessionHistory(await db.sessions.orderBy('timestamp').reverse().toArray()); };
    if (railTab === 'sessions') fetchHistory();
  }, [railTab, sessionId]);

  // --- ACTIONS ---
  const humanizeGeminiFile = async (name: string) => {
    addLog(`Humanizing: ${name}...`);
    try {
      const raw = await axios.get(`${ENGINE_URL}/nexus/get/staging/${name}`);
      const res = await axios.post(`${ENGINE_URL}/nexus/ingest/gemini`, { name, content: raw.data.content });
      addLog(`Gemini Flesh Loaded: ${res.data.file}`, "success");
      refreshRails();
    } catch (e) { addLog("Humanization failed.", "error"); }
  };

  const ingestClaudeExport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    addLog("Ingesting Claude Export...");
    const reader = new FileReader();
    reader.onload = async (ev) => {
      try {
        const res = await axios.post(`${ENGINE_URL}/nexus/ingest/claude`, { content: ev.target?.result });
        addLog(`Mass Humanization Complete: ${res.data.count} chats vaulted.`, "success");
        refreshRails();
      } catch (e) { addLog("Claude ingest failed.", "error"); }
    };
    reader.readAsText(file);
  };

  const handleNexusDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (!file) return;
    addLog(`Ingesting: ${file.name}...`);
    const reader = new FileReader();
    reader.onload = async (ev) => {
      try {
        const res = await axios.post(`${ENGINE_URL}/nexus/ingest/gemini`, { name: file.name, content: ev.target?.result });
        addLog(`Humanized & Vaulted: ${res.data.file}`, "success");
        refreshRails();
        setRailTab('gemini');
      } catch (e) { addLog("Ingest failed.", "error"); }
    };
    reader.readAsText(file);
  };

  const loadHumanized = async (source: 'gemini' | 'claude', fileName: string) => {
    try {
      const res = await axios.get(`${ENGINE_URL}/nexus/get/${source}/${fileName}`);
      setInputs(v => ({ ...v, nexus: res.data.content })); setAmmoUsed(fileName); setActiveStage(PipelineStage.NEXUS);
      addLog(`Intel Loaded: ${fileName}`);
    } catch (e) {}
  };

  const checkNexusPrompt = async (fileName: string) => {
    setActiveNexusPrompt(fileName);
    try {
      const res = await axios.get(`${ENGINE_URL}/nexus/prompts/${fileName}`);
      if (!res.data.content.includes('[[CHAT_DATA]]')) {
        openGhost("INJECTION_REQUIRED", res.data.content);
        addLog("Marker missing. Inject manually.", "error");
      } else addLog("Protocol verified.", "success");
    } catch (e) {}
  };

  const executeStrike = async (stageId: PipelineStage) => {
    setTelemetry(prev => ({ ...prev, [stageId]: { status: 'loading' } }));
    addLog(`Strike Sequence: ${stageId.toUpperCase()}...`);
    try {
      let finalPrompt = '';
      if (stageId === PipelineStage.NEXUS) {
        if (!activeNexusPrompt || !inputs.nexus) throw new Error("MISSING_DATA");
        const pRes = await axios.get(`${ENGINE_URL}/nexus/prompts/${activeNexusPrompt}`);
        let pContent = pRes.data.content;
        if (!pContent.includes('[[CHAT_DATA]]')) {
           if (ghostData.title === "INJECTION_REQUIRED" && ghostData.content.includes('[[CHAT_DATA]]')) {
             pContent = ghostData.content;
             await axios.post(`${ENGINE_URL}/nexus/prompts`, { name: activeNexusPrompt, content: pContent });
           } else throw new Error("MISSING_MARKER");
        }
        finalPrompt = pContent.replace('[[CHAT_DATA]]', inputs.nexus);
      } else {
        const template = await db.prompts.get(stageId === PipelineStage.OWL ? 'owl_v21' : stageId);
        finalPrompt = template?.content.replace('{input}', inputs[stageId]) || inputs[stageId];
      }
      const res = await axios.post(`${ENGINE_URL}/strike`, { modelId: stageSettings[stageId].model, prompt: finalPrompt, temp: stageSettings[stageId].temperature });
      const output = res.data.content;
      const key = res.data.keyUsed || "UNKNOWN";
      const stats = { words: output.split(/\s+/).length, tokens: Math.ceil(output.length / 4), chars: output.length };

      setOutputs(prev => ({ ...prev, [stageId]: output }));
      setTelemetry(prev => ({ ...prev, [stageId]: { status: 'success', keyUsed: key, stats } }));
      addLog(`Success [${key}]. ${stats.tokens} tokens returned.`, "success");
      setDossierOpenData({ stage: stageId, stats }); setDossierOpen(true);

      if (stageId === PipelineStage.NEXUS) {
         await axios.post(`${ENGINE_URL}/nexus/disposition`, { fileName: ammoUsed, source: 'gemini', strikeOutput: output });
         setInputs(v => ({ ...v, spark: output }));
      }
      if (stageId === PipelineStage.SPARK) setInputs(v => ({ ...v, falcon: output }));
      if (stageId === PipelineStage.FALCON) setInputs(v => ({ ...v, eagle: output }));
      if (stageId === PipelineStage.EAGLE) parseEagleOutput(output);
    } catch (err: any) {
      setTelemetry(prev => ({ ...prev, [stageId]: { status: 'error', errorMessage: err.message, keyUsed: "FAILED" } }));
      addLog(`ERROR: ${err.message}`, "error");
    }
  };

  const parseEagleOutput = (output: string) => {
    const fileRegex = /cat\s+<<\s*['"]?(.*?)['"]?\s*>\s*(.*?)\n([\s\S]*?)\1/g;
    const matches = [...output.matchAll(fileRegex)];
    const queue: OwlFile[] = matches.map((m, i) => ({ id: `file-${i}`, path: m[2].trim(), skeleton: m[3], directives: "Follow EAGLE precision.", status: 'pending' }));
    setOwlQueue(queue); 
    addLog(`Eagle analysis: ${queue.length} file skeletons armed.`, queue.length > 0 ? "success" : "error");
  };

  const strikeOwlFile = async (file: OwlFile) => {
    setActiveOwlFile(file); setTelemetry(prev => ({ ...prev, owl: { status: 'loading' } }));
    try {
      const p = await db.prompts.get('owl_v21');
      const res = await axios.post(`${ENGINE_URL}/strike`, { 
        modelId: stageSettings.owl.model, 
        prompt: p?.content.replace('{skeleton}', file.skeleton).replace('{directives}', file.directives).replace('{path}', file.path) || file.skeleton,
        temp: stageSettings.owl.temperature 
      });
      setOwlQueue(q => q.map(f => f.id === file.id ? { ...f, status: 'completed', output: res.data.content } : f));
      setTelemetry(prev => ({ ...prev, owl: { status: 'success' } }));
      addLog(`Implemented: ${file.path}`, "success");
    } catch (e) { setTelemetry(prev => ({ ...prev, owl: { status: 'error' } })); }
  };

  const toggleFileDeployment = (fileId: string) => {
    setOwlQueue(q => q.map(f => f.id === fileId ? { ...f, status: f.status === 'completed' ? 'pending' : 'completed' } : f));
  };

  const loadAmmo = async (f: string) => {
    try {
      const res = await axios.get(`${ENGINE_URL}/fs/ammo/${f}`);
      setInputs(v => ({ ...v, spark: res.data.content })); setAmmoUsed(f); setActiveStage(PipelineStage.SPARK);
      addLog(`Payload Ready: ${f}`);
    } catch (e) {}
  };

  const loadSession = (s: Session) => {
    setSessionId(s.id); setInputs(s.inputs); setOutputs(s.outputs); setTelemetry(s.telemetry); setOwlQueue(s.owlQueue); setAmmoUsed(s.ammoUsed || null);
    addLog(`Restored Session: ${s.id}`);
  };

  const wipeStage = async (id: PipelineStage) => {
    if (!confirm(`WIPE ${id.toUpperCase()}?`)) return;
    setOutputs(v => ({ ...v, [id]: '' })); setTelemetry(v => ({ ...v, [id]: { status: 'idle' } })); addLog(`Phase Purged: ${id}`);
  };

  const openGhost = (title: string, content: string) => { setGhostData({ title, content }); setGhostOpen(true); };

  // --- RENDER ---
  const TacticalModelPicker = ({ currentModelId, onSelect }: any) => {
    const [isOpen, setIsOpen] = useState(false);
    const [activeGateway, setActiveGateway] = useState<string | null>(null);
    const gateways = useMemo(() => Array.from(new Set(models.map(m => m.gateway))), [models]);
    return (
      <div className="relative inline-block text-left z-[100]">
        <button onClick={() => setIsOpen(!isOpen)} className="bg-black border border-zinc-800 rounded px-4 py-2 text-[10px] text-zinc-400 min-w-[200px] flex justify-between items-center hover:border-matrix/50 transition-all shadow-inner group">
          <div className="flex flex-col items-start truncate"><span className="text-[6px] text-zinc-700 font-black uppercase tracking-widest italic">Node_Lock</span><span className="truncate font-black text-white group-hover:text-matrix transition-colors">{currentModelId || 'OFFLINE'}</span></div>
          <span className="text-zinc-800 text-[8px] ml-2 group-hover:text-matrix">▼</span>
        </button>
        <AnimatePresence>
          {isOpen && (
            <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="absolute left-0 mt-2 w-48 bg-void border border-zinc-800 rounded-lg shadow-2xl z-[120] backdrop-blur-3xl py-2">
              {gateways.map(g => (
                <div key={g} className="relative group/gate" onMouseEnter={() => setActiveGateway(g)}>
                  <button className={`w-full text-left px-4 py-3 text-[9px] font-black uppercase tracking-widest flex justify-between items-center transition-all ${activeGateway === g ? 'text-matrix bg-zinc-900' : 'text-zinc-600 hover:text-zinc-300'}`}>
                    <span>{g}_GW</span><span className="opacity-40 text-[7px]">▶</span>
                  </button>
                  {activeGateway === g && (
                    <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="absolute left-full top-0 w-64 bg-void border border-zinc-800 rounded-lg shadow-2xl z-[130] backdrop-blur-3xl py-2 ml-1">
                      <div className="max-h-[400px] overflow-y-auto custom-scrollbar pr-1">
                        {models.filter(m => m.gateway === g).map(m => (
                          <div key={m.id} className="relative group/model">
                            <button onClick={() => { onSelect(m.id); setIsOpen(false); }} className={`w-full text-left px-4 py-3 hover:bg-zinc-900 transition-all border-b border-zinc-900/30 last:border-0 flex justify-between items-center ${m.id === currentModelId ? 'bg-matrix/10' : ''}`}>
                              <span className="text-[10px] font-black uppercase truncate text-zinc-200">{m.id}</span>
                              <span className={`text-[6px] font-black uppercase px-1.5 py-0.5 rounded bg-matrix/20 text-matrix`}>{m.tier[0]}</span>
                            </button>
                            <div className="hidden group-hover/model:block absolute left-full top-0 w-56 bg-zinc-950 border border-zinc-800 rounded p-4 shadow-2xl z-[150] ml-2 ring-1 ring-matrix/30"><p className="text-[9px] text-zinc-400 italic leading-snug">{m.note}</p></div>
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
    const isActive = activeStage === stage.id;
    return (
      <div className="absolute flex flex-col items-center gap-3" style={{ top: `${stage.row * 250 - 150}px`, left: `${stage.col * 300 - 150}px` }}>
        <motion.div whileHover={{ scale: 1.05 }} onClick={() => setActiveStage(stage.id)} className={`w-32 h-32 rounded-3xl border-4 flex flex-col items-center justify-center cursor-pointer transition-all bg-void ${isActive ? 'scale-110 shadow-[0_0_30px_#FFD700]' : ''} ${isSuccess ? 'border-matrix shadow-[0_0_20px_#00FF41]' : tel.status === 'error' ? 'border-error shadow-[0_0_20px_#FF3131]' : tel.status === 'loading' ? 'border-voltage animate-pulse' : 'border-zinc-900'}`}> 
          <span className={`text-4xl font-black ${isSuccess ? 'text-matrix' : tel.status === 'error' ? 'text-error' : 'text-zinc-700'}`}>{stage.label[0]}</span>
          <span className="text-[8px] font-black text-zinc-500 uppercase tracking-widest mt-1">{stage.label}</span>
        </motion.div>
        <div className="w-48 bg-zinc-950 border rounded-xl p-3 flex flex-col gap-1 shadow-2xl transition-all" style={{ borderColor: isActive ? THEME.voltage : (isSuccess ? stage.linkColor : THEME.border) }}>
          <span className="text-[7px] font-black text-zinc-700 uppercase tracking-widest">{stage.id === 'nexus' ? 'RAW_DATA' : 'INTEL_BLOODLINE'}</span>
          <button className="text-[9px] font-black truncate text-left hover:text-white transition-colors italic outline-none" style={{ color: isSuccess ? stage.linkColor : '#52525b' }} onClick={(e) => { e.stopPropagation(); openGhost(stage.label, inputs[stage.id]); }}>
            {stage.id === 'nexus' ? (inputs.nexus ? 'DATA_LOCKED' : 'AWAITING_DROP...') : (outputs[STAGES[STAGES.findIndex(s=>s.id===stage.id)-1]?.id] ? 'UPSTREAM_LOCKED' : 'NULL')}
          </button>
        </div>
      </div>
    );
  };

  const GhostOverlay = () => (
    <AnimatePresence>
      {ghostOpen && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-[250] bg-black/95 backdrop-blur-xl flex items-center justify-center p-20">
          <motion.div initial={{ scale: 0.9, y: 20 }} animate={{ scale: 1, y: 0 }} className="w-full max-w-6xl h-full bg-surface border border-matrix/30 rounded-[3rem] flex flex-col overflow-hidden shadow-[0_0_100px_rgba(0,255,65,0.1)]">
            <div className="p-8 border-b border-border flex justify-between items-center bg-black/40">
              <div className="flex items-center gap-4"><div className={`w-3 h-3 rounded-full animate-pulse ${ghostData.title === 'INJECTION_REQUIRED' ? 'bg-error' : 'bg-matrix'}`} /><h2 className="text-2xl font-black text-white tracking-tighter uppercase italic">{ghostData.title}</h2></div>
              <button onClick={() => setGhostOpen(false)} className="w-12 h-12 rounded-full border border-zinc-800 flex items-center justify-center text-zinc-500 hover:text-matrix transition-all hover:border-matrix">✕</button>
            </div>
            <div className="flex-1 p-12 bg-void/50 border-x border-border/20 relative">
              <textarea className="w-full h-full bg-transparent border-none outline-none text-sm mono text-matrix/70 whitespace-pre-wrap leading-relaxed resize-none custom-scrollbar" value={ghostData.content} onChange={(e) => setGhostData({ ...ghostData, content: e.target.value })} spellCheck={false} />
            </div>
            <div className="p-6 border-t border-border bg-black/20 flex justify-between items-center px-12">
              <span className="text-[8px] font-black text-zinc-800 uppercase tracking-[0.5em]">Command_Override // V22_HUD</span>
              <div className="flex gap-4">
                <button onClick={async () => { if (activeNexusPrompt) { await axios.post(`${ENGINE_URL}/nexus/prompts`, { name: activeNexusPrompt, content: ghostData.content }); addLog("Protocol Sync: Saved."); setGhostOpen(false); } }} className="px-8 py-3 bg-zinc-900 border border-zinc-800 text-[10px] font-black text-white uppercase hover:border-matrix transition-all">Save_To_Disk</button>
                <button onClick={() => { navigator.clipboard.writeText(ghostData.content); addLog("Copied stream."); }} className="px-8 py-3 bg-matrix text-void border border-matrix/20 text-[10px] font-black uppercase hover:bg-white transition-all shadow-xl">Copy_Stream</button>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );

  const LaserLines = () => (
    <svg className="absolute inset-0 w-full h-full pointer-events-none z-0 opacity-40">
      <path d="M 50 100 H 150" stroke={outputs.nexus ? LINK_COLORS.nexus : THEME.border} strokeWidth="1" fill="none" />
      <path d="M 150 100 H 450" stroke={outputs.spark ? LINK_COLORS.spark : THEME.border} strokeWidth="1" fill="none" />
      <path d="M 450 100 L 450 200 L 150 200 L 150 350" stroke={outputs.falcon ? LINK_COLORS.falcon : THEME.border} strokeWidth="1" fill="none" />
      <path d="M 150 350 H 450" stroke={outputs.eagle ? LINK_COLORS.eagle : THEME.border} strokeWidth="1" fill="none" />
      <path d="M 450 350 L 450 450 L 300 450 L 300 600" stroke={owlQueue.every(f=>f.status==='completed') && owlQueue.length > 0 ? LINK_COLORS.owl : THEME.border} strokeWidth="1" fill="none" />
    </svg>
  );

  const PromptEditor = ({ stageId, label }: { stageId: string, label: string }) => {
    const [content, setContent] = useState('');
    useEffect(() => { db.prompts.get(stageId).then(p => setContent(p?.content || '')); }, [stageId]);
    const save = async () => {
      await db.prompts.put({ id: stageId, content });
      try { await axios.post(`${ENGINE_URL}/fs/prompts`, { id: stageId, content }); addLog(`Saved ${label} prompt.`); } catch (e) {}
      audioService.playSuccess();
    };
    return (
      <div className="space-y-3 p-6 bg-zinc-950 border border-zinc-900 rounded-xl relative overflow-hidden group mb-4">
        <div className="flex justify-between items-center relative z-10">
          <div className="flex items-center gap-3"><div className="w-2 h-2 bg-matrix rounded-full shadow-[0_0_5px_#00FF41]" /><span className="text-[9px] font-black text-white uppercase tracking-widest">{label}</span></div>
          <button onClick={save} className="text-[8px] font-black text-matrix hover:underline bg-matrix/5 px-3 py-1 border border-matrix/20 rounded uppercase">Sync</button>
        </div>
        <textarea className="w-full h-40 bg-black/60 border border-zinc-800 rounded p-4 text-[11px] leading-relaxed text-zinc-400 outline-none focus:border-matrix/30 transition-all custom-scrollbar resize-none font-mono" value={content} onChange={(e) => setContent(e.target.value)} spellCheck={false} />
      </div>
    );
  };

  return (
    <div className={`h-screen bg-void text-zinc-400 font-mono flex flex-col relative overflow-hidden ${casinoSettings.scanlines ? 'scanlines' : ''}`}>
      <div className="absolute inset-0 opacity-[0.03] pointer-events-none bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')]" />
      
      <header className="p-6 h-24 flex justify-between items-center border-b border-border bg-black/90 backdrop-blur-md relative z-[60] shrink-0">
        <div className="flex items-center gap-6"><div className="w-12 h-12 bg-matrix flex items-center justify-center text-void font-black text-2xl shadow-[0_0_20px_#00FF41]">P</div><div><h1 className="text-3xl font-black text-white tracking-tighter italic">PEACOCK<span className="text-matrix">_V22</span></h1><p className="text-[7px] font-black tracking-[0.5em] text-zinc-600 mt-1 uppercase italic underline decoration-matrix/30">Omerta_War_Room // Precision_HUD</p></div></div>
        <div className="flex gap-4"><button onClick={() => setSettingsOpen(true)} className="px-6 py-2 border border-zinc-800 text-[9px] font-black uppercase hover:border-matrix hover:text-white transition-all bg-zinc-950">Command_Deck</button><button onClick={() => window.location.reload()} className="px-6 py-2 bg-matrix/10 text-matrix border border-matrix/20 text-[9px] font-black uppercase tracking-widest">Wipe_Op</button></div>
      </header>

      <main className="flex-1 flex overflow-hidden relative shrink min-h-0">
        <aside className="w-72 border-r border-border bg-surface/30 p-6 flex flex-col gap-6 relative z-50 shrink-0">
          <div className="flex gap-2 border-b border-zinc-900 pb-4">{['ammo', 'gemini', 'claude', 'vault', 'sessions'].map(t => (<button key={t} onClick={() => setRailTab(t as any)} className={`text-[8px] font-black uppercase tracking-widest px-2 py-1 rounded-full transition-all ${railTab === t ? 'bg-matrix text-void' : 'text-zinc-600 hover:text-zinc-400'}`}>{t}</button>))}
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar">
            {railTab === 'ammo' && ammoFiles.map(f => (<button key={f} onClick={() => loadAmmo(f)} className={`w-full text-left px-3 py-2 bg-zinc-950 border border-zinc-900 hover:border-matrix/30 rounded text-[9px] truncate mb-1 flex justify-between items-center ${ammoUsed === f ? 'text-matrix border-matrix/40' : 'text-zinc-500 hover:text-white'}`}><span>{f}</span><span>▶</span></button>))}
            {railTab === 'gemini' && (
              <div className="space-y-4">
                <div><h3 className="text-[7px] font-black text-zinc-700 uppercase mb-2">Raw_Intel</h3>
                {geminiRaw.map(f => (<button key={f} onClick={() => humanizeGeminiFile(f)} className="w-full text-left px-3 py-2 bg-zinc-950 border border-zinc-900 text-[9px] text-zinc-500 hover:text-white rounded mb-1 truncate">Humanize: {f}</button>))}
                </div>
                <div><h3 className="text-[7px] font-black text-matrix uppercase mb-2">Humanized</h3>
                {geminiHumanized.map(f => (<button key={f} onClick={() => loadHumanized('gemini', f)} className={`w-full text-left px-3 py-2 bg-zinc-950 border transition-all rounded text-[9px] truncate mb-1 ${ammoUsed === f ? 'border-matrix/40 text-matrix' : 'border-zinc-900 text-zinc-500 hover:text-white'}`}>{f}</button>))}
                </div>
              </div>
            )}
            {railTab === 'claude' && (
              <div className="space-y-4">
                <label className="block w-full py-2 bg-zinc-900 border border-zinc-800 text-[8px] font-black text-center text-zinc-500 hover:bg-zinc-800 cursor-pointer uppercase">Ingest_Export<input type="file" className="hidden" accept=".json" onChange={ingestClaudeExport}/></label>
                {claudeHumanized.map(f => (<button key={f} onClick={() => loadHumanized('claude', f)} className={`w-full text-left px-3 py-2 bg-zinc-950 border transition-all rounded text-[9px] truncate mb-1 ${ammoUsed === f ? 'border-matrix/40 text-matrix' : 'border-zinc-900 text-zinc-500 hover:text-white'}`}>{f}</button>))}
              </div>
            )}
            {railTab === 'vault' && Object.entries(vaultTree).map(([dom, ops]) => (
              <div key={dom} className="mb-4"><h3 className="text-[7px] font-black text-matrix uppercase mb-2">{dom}</h3>
              {ops.map(op => (<div key={op} className="pl-3 py-1 border-l border-zinc-900 text-[9px] text-zinc-500 hover:text-white cursor-pointer">{op}</div>))}
              </div>
            ))}
            {railTab === 'sessions' && sessionHistory.map(s => (<button key={s.id} onClick={() => loadSession(s)} className={`w-full text-left p-3 bg-zinc-950 border rounded mb-2 ${sessionId === s.id ? 'border-matrix/40 bg-matrix/5' : 'border-zinc-900'}`}><span className="text-[9px] font-black text-white truncate">{s.name}</span></button>))}
          </div>
        </aside>

        <div className="flex-1 relative overflow-auto bg-black/20 p-20 custom-scrollbar shrink min-h-0">
          <div className="min-w-[1000px] min-h-[800px] relative"><LaserLines />{STAGES.map(s => <BracketNode key={s.id} stage={s} />)}</div>
        </div>

        <aside className="w-[500px] border-l border-border bg-black/40 flex flex-col relative z-50 shrink-0">
          <div className="p-6 border-b border-border flex justify-between items-center bg-black/60">
            <span className="text-[10px] font-black uppercase tracking-[0.2em] text-white italic"><DescrambleText text={`INSPECTING_${activeStage.toUpperCase()}`} /></span>
            <div className="flex items-center gap-4">
              {activeStage === PipelineStage.EAGLE && outputs.eagle && (<button onClick={() => { const script = outputs.eagle.match(/cat\s+<<\s*['"]?(.*?)['"]?\s*>\s*(.*?)\n([\s\S]*?)\1/g)?.map(m=>m[0]).join('\n\n') || "NO_SCRIPT"; navigator.clipboard.writeText(script); addLog("Bone-Setter Copied."); audioService.playSuccess(); }} className="px-4 py-2 border border-voltage/30 text-voltage text-[8px] font-black uppercase hover:bg-voltage hover:text-void transition-all">Bone_Setter</button>)}
              {outputs[activeStage] && <button onClick={() => wipeStage(activeStage)} className="px-4 py-2 border border-error/30 text-error text-[8px] font-black uppercase hover:bg-error hover:text-white transition-all">Wipe</button>}
              <TacticalModelPicker currentModelId={stageSettings[activeStage].model} onSelect={(mid: string) => setStageSettings(v => ({ ...v, [activeStage]: { ...v[activeStage], model: mid } }))} />
              <button onClick={() => executeStrike(activeStage)} disabled={telemetry[activeStage].status === 'loading'} className="px-6 py-2 bg-matrix text-void font-black text-[9px] uppercase tracking-widest hover:bg-white transition-all disabled:opacity-50 shadow-[0_0_15px_rgba(0,255,65,0.2)]">Strike</button>
            </div>
          </div>
          <div className="flex-1 flex flex-col p-6 gap-6 overflow-hidden bg-[rgba(5,5,5,0.4)]">
            {activeStage === PipelineStage.NEXUS ? (
              <div onDragOver={e => e.preventDefault()} onDrop={handleNexusDrop} className="flex-1 flex flex-col gap-4">
                <div className="h-32 border-2 border-dashed border-zinc-800 rounded-xl flex flex-col items-center justify-center gap-2 hover:border-matrix/40 transition-all bg-void/50 cursor-pointer"><span className="text-[20px]">📥</span><span className="text-[8px] font-black text-zinc-600 uppercase tracking-widest">Drop_Raw_Intel_Here</span></div>
                <select className="bg-black border border-zinc-800 text-[10px] text-matrix p-3 rounded outline-none" onChange={e => checkNexusPrompt(e.target.value)} value={activeNexusPrompt || ''}>
                  <option value="">Select Protocol...</option>
                  {nexusPrompts.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
                <textarea className="flex-1 bg-black/40 border border-zinc-900 rounded-lg p-4 text-xs mono text-zinc-400 outline-none resize-none custom-scrollbar" value={inputs.nexus} onChange={e => setInputs(v => ({ ...v, nexus: e.target.value }))} placeholder="Humanized intel stream..." />
              </div>
            ) : (
              <textarea className="flex-1 bg-black/40 border border-zinc-900 rounded-lg p-4 text-xs mono text-zinc-400 outline-none focus:border-matrix/30 resize-none custom-scrollbar" value={inputs[activeStage]} onChange={(e) => setInputs(v => ({ ...v, [activeStage]: e.target.value }))} placeholder="Awaiting Tactical DNA..." />
            )}
            <div className="flex-1 bg-zinc-950 border border-zinc-900 rounded-lg p-4 text-xs mono text-matrix/80 overflow-y-auto custom-scrollbar whitespace-pre-wrap relative group"><button onClick={() => { navigator.clipboard.writeText(outputs[activeStage]); addLog(`Copied Output.`); audioService.playSuccess(); }} className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity bg-zinc-900 border border-zinc-800 p-2 text-[8px] font-black text-matrix">COPY_INTEL</button>{outputs[activeStage] || "SYSTEM_WAITING_FOR_STRIKE..."}</div>
          </div>
        </aside>
      </main>

      {/* OWL */}
      {activeStage === PipelineStage.OWL && owlQueue.length > 0 && (
        <motion.div initial={{ y: 100 }} animate={{ y: 0 }} className="h-64 border-t border-border bg-surface/95 backdrop-blur-md p-6 overflow-x-auto flex gap-4 custom-scrollbar relative z-[80] shrink-0 shadow-2xl">
          {owlQueue.map(file => (
            <div key={file.id} className={`shrink-0 w-72 p-5 border rounded-lg flex flex-col gap-3 transition-all ${file.status === 'completed' ? 'border-matrix/40 bg-matrix/5' : 'border-zinc-800 bg-zinc-950/50'}`}>
              <div className="flex justify-between items-center"><span className="text-[10px] font-black text-white truncate italic w-48">{file.path}</span><div className={`w-2 h-2 rounded-full ${file.status === 'completed' ? 'bg-matrix shadow-[0_0_5px_#00FF41]' : 'bg-zinc-800'}`} /></div>
              <button onClick={() => strikeOwlFile(file)} className="py-2 bg-zinc-900 text-matrix text-[8px] font-black uppercase border border-zinc-800 hover:border-matrix/40 transition-all">Implement</button>
              {file.status === 'completed' && (<div className="mt-auto flex flex-col gap-2"><button onClick={() => { navigator.clipboard.writeText(file.output || ''); addLog(`Copied Flesh.`); }} className="py-2 bg-matrix/10 text-matrix text-[8px] font-black uppercase rounded border border-matrix/20 hover:bg-matrix hover:text-void">Copy_Flesh</button><label className="flex items-center gap-2 cursor-pointer"><input type="checkbox" className="w-3 h-3 accent-matrix" checked={file.status === 'completed'} onChange={() => toggleFileDeployment(file.id)} /><span className="text-[7px] font-black text-zinc-600 uppercase">Deployed</span></label></div>)}
            </div>
          ))}
        </motion.div>
      )}

      {/* CLI */}
      <motion.footer animate={{ height: cliHeight }} className="w-full bg-black border-t border-matrix/30 relative z-[100] flex flex-col shadow-2xl overflow-hidden shrink-0">
        <div className="h-1 bg-zinc-800 hover:bg-matrix cursor-ns-resize transition-all shrink-0" onMouseDown={handleMouseDown} />
        <div className="h-9 border-b border-zinc-900 bg-zinc-950 flex justify-between items-center px-6 cursor-pointer group shrink-0" onClick={toggleCli}>
          <div className="flex items-center gap-4"><div className="w-8 h-1 bg-zinc-800 rounded-full group-hover:bg-matrix transition-all" /><span className="text-[8px] font-black text-matrix tracking-[0.3em] animate-pulse uppercase italic">Verbatim_System_Sync</span><span className="text-[7px] text-zinc-700 uppercase italic ml-4">Black_Box // {logs.length} events</span></div>
          <span className="text-zinc-600 text-xs">{cliHeight > 40 ? '▼' : '▲'}</span>
        </div>
        <div className="flex-1 overflow-y-auto p-6 font-mono text-[10px] space-y-1 custom-scrollbar bg-[rgba(5,5,5,0.8)] backdrop-blur-sm">
          {logs.map((l, i) => (<div key={i} className={`flex gap-4 group/log ${l.type === 'error' ? 'text-error' : l.type === 'success' ? 'text-matrix' : 'text-zinc-500'}`}><span className="opacity-20 w-20 shrink-0">[{l.t}]</span><span className="font-black opacity-40 uppercase w-12 shrink-0">{l.type === 'info' ? 'SYS' : l.type.toUpperCase()}</span><span className="tracking-tighter group-hover/log:text-white transition-colors uppercase italic">${l.msg}</span></div>))}
          <div className="text-matrix opacity-20 animate-pulse">
          _
          </div>
        </div>
      </motion.footer>

      <GhostOverlay />
      <AnimatePresence>
        {dossierOpen && dossierData && (
          <div className="fixed inset-0 z-[200] flex items-center justify-center p-8 bg-black/90 backdrop-blur-md">
            <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="w-[500px] bg-surface border-2 border-matrix rounded-[2rem] p-10 flex flex-col gap-8 shadow-2xl">
              <h2 className="text-3xl font-black text-white italic text-center">STRIKE_SUCCESS</h2>
              <div className="p-4 bg-zinc-950 border border-zinc-900 rounded-xl flex justify-around text-[10px] font-black uppercase"><span className="text-white">Tokens: {dossierData.stats.tokens}</span><span className="text-zinc-500">Words: {dossierData.stats.words}</span></div>
              <button onClick={() => setDossierOpen(false)} className="w-full py-5 bg-matrix text-void font-black uppercase text-[11px] hover:bg-white transition-all shadow-xl">Dismiss</button>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {settingsOpen && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSettingsOpen(false)} className="fixed inset-0 bg-black/80 z-[110]" />
            <motion.div initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }} className="fixed inset-y-0 right-0 w-[600px] bg-surface border-l border-border z-[120] p-10 flex flex-col gap-8 shadow-2xl">
              <h2 className="text-2xl font-black text-white italic uppercase italic">Command_Deck</h2>
              <div className="flex-1 overflow-y-auto custom-scrollbar pr-4">
                {casinoSettings && Object.entries(casinoSettings).map(([k, v]: any) => (
                  <div key={k} className="flex justify-between items-center p-5 bg-zinc-950 border border-zinc-900 rounded-lg mb-4">
                    <span className="text-[10px] font-black uppercase text-white tracking-widest">{k}</span>
                    <button onClick={() => setCasinoSettings((p: any) => ({ ...p, [k]: !v }))} className={`w-14 h-7 rounded-full border-2 ${v ? 'bg-matrix border-matrix' : 'bg-zinc-900 border-zinc-800'}`}></button>
                  </div>
                ))}
                <div className="mt-8 space-y-6">{STAGES.map(s => <PromptEditor key={s.id} stageId={s.id} label={s.label} />)}<PromptEditor stageId="owl_v21" label="OWL_GLOBAL" /></div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      <style>{`
        body { margin: 0; background: #000; overflow: hidden; font-family: 'JetBrains Mono', monospace; }
        .scanlines::before { content: ""; position: absolute; inset: 0; pointer-events: none; z-index: 1000; background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.1) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.03), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.03)); background-size: 100% 3px, 2px 100%; }
        .custom-scrollbar::-webkit-scrollbar { width: 3px; height: 3px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #1a1a1a; border-radius: 10px; }
        @keyframes shake { 0%{transform:translate(1px,1px)} 50%{transform:translate(-1px,-1px)} 100%{transform:translate(0px,0px)} }
        .animate-shake { animation: shake 0.1s infinite; }
      `}</style>
    </div>
  );
};

export default App;