import React, { useState, useEffect, useRef, useMemo } from 'react';
import axios from 'axios';
import Dexie, { Table } from 'dexie';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  PipelineStage, ModelConfig, StageSettings, CallTelemetry, 
  OwlFile, PromptTemplate, HistoryItem 
} from './types';
import { audioService } from './services/audioService';

// ============================================================ 
// 💀 PEACOCK V21: THE OMERTA DATABASE
// ============================================================ 
class PeacockDB extends Dexie {
  prompts!: Table<PromptTemplate>;
  history!: Table<HistoryItem>;
  models!: Table<ModelConfig>;

  constructor() {
    super('PeacockV21');
    this.version(1).stores({
      prompts: 'id',
      history: '++id, stage, timestamp',
      models: 'id, gateway'
    });
  }
}

const db = new PeacockDB();

const THEME = {
  void: '#050505',
  matrix: '#00FF41',
  voltage: '#FFD700',
  error: '#FF3131',
  surface: '#0A0A0A',
  border: '#1A1A1A'
};

const ENGINE_URL = 'http://localhost:8888/v1';

// ============================================================ 
// 🧠 PEACOCK V21: CORE ORCHESTRATOR
// ============================================================ 
const App: React.FC = () => {
  const [activeStage, setActiveStage] = useState<PipelineStage>(PipelineStage.SPARK);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<'nodes' | 'prompts' | 'casino' | 'engine'>('nodes');
  const [sidebarTab, setSidebarTab] = useState<'ammo' | 'history' | 'logs'>('ammo');
  const [isJackpot, setIsJackpot] = useState(false);
  const [isAppLoading, setIsAppLoading] = useState(true);

  const [inputs, setInputs] = useState<Record<string, string>>({
    spark: '', falcon: '', eagle: '', owl: '', hawk: ''
  });
  const [outputs, setOutputs] = useState<Record<string, string>>({
    spark: '', falcon: '', eagle: '', owl: '', hawk: ''
  });
  const [telemetry, setTelemetry] = useState<Record<string, CallTelemetry>>({
    spark: { status: 'idle' }, falcon: { status: 'idle' }, eagle: { status: 'idle' }, owl: { status: 'idle' }, hawk: { status: 'idle' }
  });

  const [owlQueue, setOwlQueue] = useState<OwlFile[]>([]);
  const [activeOwlFile, setActiveOwlFile] = useState<OwlFile | null>(null);
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [stageSettings, setStageSettings] = useState<Record<string, StageSettings>>({
    spark: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
    falcon: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.5 },
    eagle: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.3 },
    owl: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.2 },
    hawk: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.4 }
  });
  const [casinoSettings, setCasinoSettings] = useState({ vibrations: true, audio: true, scanlines: true });
  const [ammoFiles, setAmmoFiles] = useState<string[]>([]);
  const [historyItems, setHistoryItems] = useState<HistoryItem[]>([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState<number | null>(null);

  // --- ENGINE BUS STATE (FOR CIRCUIT VISUALS) ---
  const [busActive, setBusBusActive] = useState({ engine: false, database: false, ammo: false });

  useEffect(() => {
    const boot = async () => {
      try {
        const mRes = await axios.get(`${ENGINE_URL}/models`);
        setModels(mRes.data);
        await db.models.bulkPut(mRes.data);
      } catch (e) {
        const cached = await db.models.toArray();
        setModels(cached);
      }
      try {
        const pRes = await axios.get(`${ENGINE_URL}/fs/prompts`);
        const prompts: PromptTemplate[] = pRes.data;
        const mapping: Record<string, string> = {
          'spark2': PipelineStage.SPARK, 'falcon2': PipelineStage.FALCON,
          'eagle3': PipelineStage.EAGLE, 'owl_v21': 'owl_v21', 'hawk': PipelineStage.HAWK
        };
        const standardPrompts = prompts.map(p => ({ id: mapping[p.id] || p.id, content: p.content }));
        await db.prompts.bulkPut(standardPrompts);
      } catch (e) {}
      try {
        const aRes = await axios.get(`${ENGINE_URL}/fs/ammo`);
        setAmmoFiles(aRes.data);
      } catch (e) {}
      await refreshHistory();
      setTimeout(() => setIsAppLoading(false), 1500); // Artificial delay for effect
    };
    boot();
  }, []);

  const refreshHistory = async () => {
    const items = await db.history.reverse().toArray();
    setHistoryItems(items);
  };

  const executeStrike = async (stageId: PipelineStage, customPrompt?: string) => {
    setTelemetry(prev => ({ ...prev, [stageId]: { status: 'loading' } }));
    setBusBusActive(v => ({ ...v, engine: true }));
    if (casinoSettings.audio) audioService.playSuccess();

    try {
      const promptTemplate = await db.prompts.get(stageId === PipelineStage.OWL ? 'owl_v21' : stageId);
      const payload = inputs[stageId];
      const fullPrompt = customPrompt || (promptTemplate?.content.replace('{input}', payload) || payload);

      const res = await axios.post(`${ENGINE_URL}/strike`, {
        modelId: stageSettings[stageId].model,
        prompt: fullPrompt,
        temp: stageSettings[stageId].temperature
      });

      const output = res.data.content;
      setOutputs(prev => ({ ...prev, [stageId]: output }));
      setTelemetry(prev => ({ ...prev, [stageId]: { status: 'success' } }));
      setBusBusActive(v => ({ ...v, engine: false, database: true }));

      if (stageId === PipelineStage.SPARK) setInputs(v => ({ ...v, falcon: output }));
      if (stageId === PipelineStage.FALCON) setInputs(v => ({ ...v, eagle: output }));
      if (stageId === PipelineStage.EAGLE) parseEagleOutput(output);
      if (stageId === PipelineStage.HAWK) {
        setIsJackpot(true);
        setTimeout(() => setIsJackpot(false), 3000);
      }
      
      const id = await db.history.add({ stage: stageId, input: payload, output, timestamp: Date.now() });
      setSelectedHistoryId(id as number);
      refreshHistory();
      setTimeout(() => setBusBusActive(v => ({ ...v, database: false })), 1000);
    } catch (err: any) {
      setTelemetry(prev => ({ ...prev, [stageId]: { status: 'error', errorMessage: err.message } }));
      setBusBusActive({ engine: false, database: false, ammo: false });
      if (casinoSettings.audio) audioService.playError();
    }
  };

  const parseEagleOutput = (output: string) => {
    const fileRegex = /cat << '.*?' > (.*?)\n([\s\S]*?)EOF/g;
    const directivesRegex = /### DIRECTIVES([\s\S]*?)(?=###|$)/i;
    const directives = output.match(directivesRegex)?.[1] || "Follow EAGLE skeleton precision.";
    const matches = [...output.matchAll(fileRegex)];
    const queue: OwlFile[] = matches.map((m, i) => ({
      id: `file-${i}`, path: m[1].trim(), skeleton: m[2], directives: directives.trim(), status: 'pending'
    }));
    setOwlQueue(queue);
    setActiveStage(PipelineStage.OWL);
  };

  const strikeOwlFile = async (file: OwlFile) => {
    setActiveOwlFile(file);
    setTelemetry(prev => ({ ...prev, owl: { status: 'loading' } }));
    setBusBusActive(v => ({ ...v, engine: true }));
    try {
      const promptTemplate = await db.prompts.get('owl_v21');
      const context = `CONTEXT:\nSPARK: ${outputs.spark}\nFALCON: ${outputs.falcon}\nDIRECTIVES: ${file.directives}`;
      const fullPrompt = promptTemplate?.content
        .replace('{skeleton}', file.skeleton).replace('{directives}', file.directives)
        .replace('{context}', context).replace('{path}', file.path) || `Implement: ${file.path}\n${file.skeleton}`;

      const res = await axios.post(`${ENGINE_URL}/strike`, {
        modelId: stageSettings.owl.model, prompt: fullPrompt, temp: stageSettings.owl.temperature
      });
      const result = res.data.content;
      setOwlQueue(q => q.map(f => f.id === file.id ? { ...f, status: 'completed', output: result } : f));
      setTelemetry(prev => ({ ...prev, owl: { status: 'success' } }));
      setBusBusActive(v => ({ ...v, engine: false, database: true }));
      setTimeout(() => setBusBusActive(v => ({ ...v, database: false })), 1000);
      audioService.playSuccess();
    } catch (err: any) {
      setTelemetry(prev => ({ ...prev, owl: { status: 'error', errorMessage: err.message } }));
      setBusBusActive({ engine: false, database: false, ammo: false });
      audioService.playError();
    }
  };

  // --- UI: SCHEMATIC NODES ---
  const LogicNode = ({ id, label, status, type = 'phase' }: any) => {
    const isActive = activeStage === id;
    const isWorking = telemetry[id]?.status === 'loading' || (type === 'engine' && busActive.engine) || (type === 'database' && busActive.database);
    const isDone = telemetry[id]?.status === 'success';

    return (
      <div className="flex flex-col items-center gap-2 relative group">
        <motion.button
          whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.9 }}
          onClick={() => type === 'phase' && setActiveStage(id)}
          className={`w-14 h-14 rounded-lg border-2 flex items-center justify-center font-black transition-all relative z-10 ${isActive ? 'bg-zinc-900 border-voltage text-voltage shadow-[0_0_20px_rgba(255,215,0,0.4)]' : isWorking ? 'bg-zinc-900 border-voltage text-voltage animate-pulse shadow-[0_0_15px_#FFD700]' : isDone ? 'bg-matrix/10 border-matrix text-matrix shadow-[0_0_10px_#00FF41]' : type !== 'phase' ? 'bg-black border-zinc-800 text-zinc-500' : 'bg-zinc-950 border-zinc-900 text-zinc-700'}`}
        >
          {type === 'engine' ? '⚡' : type === 'database' ? 'V' : type === 'ammo' ? 'A' : isDone ? '✓' : label[0]}
        </motion.button>
        <span className={`text-[7px] font-black tracking-widest uppercase ${isActive ? 'text-white' : 'text-zinc-700'}`}>{label}</span>
        {isWorking && <div className="absolute inset-0 bg-voltage/5 rounded-lg animate-ping pointer-events-none" />}
      </div>
    );
  };

  const MindMap = () => {
    const stagesPos = [
      { x: 300, y: 100, id: 'spark' }, { x: 450, y: 100, id: 'falcon' },
      { x: 600, y: 100, id: 'eagle' }, { x: 750, y: 100, id: 'owl' },
      { x: 900, y: 100, id: 'hawk' }
    ];
    const enginePos = { x: 600, y: 200 };
    const dbPos = { x: 600, y: 20 };
    const ammoPos = { x: 150, y: 100 };

    return (
      <div className="h-64 border-b border-border bg-surface/50 relative overflow-hidden">
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          {/* Main Bus */}
          <line x1={ammoPos.x} y1={ammoPos.y} x2={stagesPos[0].x} y2={stagesPos[0].y} stroke={busActive.ammo ? THEME.matrix : THEME.border} strokeWidth="1" strokeDasharray="5 5" />
          {stagesPos.map((s, i) => i < stagesPos.length - 1 && (
            <line key={i} x1={s.x} y1={s.y} x2={stagesPos[i+1].x} y2={stagesPos[i+1].y} stroke={telemetry[s.id].status === 'success' ? THEME.matrix : THEME.border} strokeWidth="1" />
          ))}
          
          {/* Engine & DB Links */}
          {stagesPos.map(s => (
            <React.Fragment key={`links-${s.id}`}>
              <motion.path 
                d={`M ${s.x} ${s.y} L ${enginePos.x} ${enginePos.y}`} 
                stroke={telemetry[s.id].status === 'loading' ? THEME.voltage : THEME.border} 
                strokeWidth="1" fill="none" opacity={activeStage === s.id || telemetry[s.id].status === 'loading' ? 0.5 : 0.1}
              />
              <motion.path 
                d={`M ${s.x} ${s.y} L ${dbPos.x} ${dbPos.y}`} 
                stroke={busActive.database && activeStage === s.id ? THEME.matrix : THEME.border} 
                strokeWidth="1" fill="none" opacity={activeStage === s.id ? 0.5 : 0.1}
              />
            </React.Fragment>
          ))}

          {/* Pulse Animations */}
          {busActive.engine && (
            <motion.circle 
              r="3" fill={THEME.voltage} initial={{ offset: 0 }} animate={{ cx: [stagesPos.find(s => s.id === activeStage)?.x, enginePos.x], cy: [stagesPos.find(s => s.id === activeStage)?.y, enginePos.y] }} transition={{ repeat: Infinity, duration: 0.6 }} />
          )}
        </svg>

        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div style={{ position: 'absolute', left: ammoPos.x - 28, top: ammoPos.y - 28 }} className="pointer-events-auto">
            <LogicNode id="ammo" label="AMMO" type="ammo" />
          </div>
          <div style={{ position: 'absolute', left: dbPos.x - 28, top: dbPos.y - 28 }} className="pointer-events-auto">
            <LogicNode id="db" label="VAULT" type="database" />
          </div>
          {stagesPos.map(s => (
            <div key={s.id} style={{ position: 'absolute', left: s.x - 28, top: s.y - 28 }} className="pointer-events-auto">
              <LogicNode id={s.id} label={s.id.toUpperCase()} />
            </div>
          ))}
          <div style={{ position: 'absolute', left: enginePos.x - 28, top: enginePos.y - 28 }} className="pointer-events-auto">
            <LogicNode id="engine" label="ENGINE" type="engine" />
          </div>
        </div>
      </div>
    );
  };

  const TacticalModelPicker = ({ currentModelId, onSelect }: any) => {
    const [isOpen, setIsOpen] = useState(false);
    const [hoveredGateway, setHoveredGateway] = useState<string | null>(null);
    const [hoveredModel, setHoveredModel] = useState<ModelConfig | null>(null);
    const gateways = useMemo(() => Array.from(new Set(models.map(m => m.gateway))), [models]);

    return (
      <div className="relative inline-block text-left" onMouseLeave={() => { setIsOpen(false); setHoveredGateway(null); setHoveredModel(null); }}>
        <button onClick={() => setIsOpen(!isOpen)} className="bg-black/60 border border-zinc-800 rounded px-4 py-2 flex items-center gap-4 hover:border-matrix transition-all group">
          <div className="flex flex-col items-start">
            <span className="text-[6px] font-black text-zinc-600 uppercase tracking-[0.3em]">Active_Relay</span>
            <span className="text-[10px] font-black text-white group-hover:text-matrix truncate max-w-[150px]">{currentModelId}</span>
          </div>
          <span className="text-[8px] text-zinc-800">▼</span>
        </button>
        <AnimatePresence>
          {isOpen && (
            <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }} className="absolute left-0 mt-2 w-48 bg-zinc-950 border border-zinc-800 rounded-lg shadow-2xl z-[200] overflow-visible">
              {gateways.map(g => (
                <div key={g} className="relative" onMouseEnter={() => setHoveredGateway(g)}>
                  <button className={`w-full text-left px-4 py-3 text-[9px] font-black uppercase tracking-widest flex justify-between items-center transition-all ${hoveredGateway === g ? 'bg-matrix/10 text-matrix' : 'text-zinc-500'}`}>
                    <span>{g}</span><span>▶</span>
                  </button>
                  {hoveredGateway === g && (
                    <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="absolute left-full top-0 ml-1 w-64 bg-zinc-950 border border-zinc-800 rounded-lg shadow-2xl overflow-visible">
                      {models.filter(m => m.gateway === g).map(m => (
                        <div key={m.id} className="relative" onMouseEnter={() => setHoveredModel(m)}>
                          <button onClick={() => { onSelect(m.id); setIsOpen(false); }} className={`w-full text-left px-4 py-3 text-[9px] font-black uppercase transition-all ${hoveredModel?.id === m.id ? 'bg-matrix/10 text-matrix' : 'text-zinc-400'}`}>{m.id}</button>
                          {hoveredModel?.id === m.id && (
                            <motion.div initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} className="absolute left-full top-0 ml-2 w-64 bg-surface border border-matrix/20 rounded-lg p-4 shadow-[0_0_30px_rgba(0,255,65,0.1)] pointer-events-none">
                              <div className="flex justify-between items-center mb-2"><span className="text-[8px] font-black text-matrix uppercase">Intel_Package</span><span className={`text-[6px] font-black uppercase px-1.5 py-0.5 rounded ${m.tier === 'expensive' ? 'bg-red-950/30 text-red-500' : 'bg-matrix/10 text-matrix'}`}>{m.tier}</span></div>
                              <p className="text-[9px] text-zinc-400 italic leading-relaxed">{m.note || "No field telemetry recorded."}</p>
                            </motion.div>
                          )}
                        </div>
                      ))}
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

  return (
    <div className={`min-h-screen bg-void text-zinc-400 font-mono flex flex-col relative overflow-hidden ${casinoSettings.scanlines ? 'scanlines' : ''}`}>
      <div className="absolute inset-0 opacity-[0.03] pointer-events-none bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')]" />
      
      {/* INITIAL LOADING SCREEN */}
      <AnimatePresence>
        {isAppLoading && (
          <motion.div 
            initial={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-[2000] bg-void flex flex-col items-center justify-center p-20"
          >
            <div className="relative group">
              <div className="absolute -inset-10 bg-matrix/20 blur-3xl rounded-full opacity-50 animate-pulse" />
              <img 
                src="/assets/images/bird_typing_v21.png" // Image #6
                alt="PEACOCK_PROCESSING"
                className="w-96 h-96 object-cover border border-matrix/20 rounded-[4rem] shadow-2xl relative z-10"
                onError={(e) => (e.currentTarget.src = 'https://placehold.co/400x400/050505/00FF41?text=LOADING_PEACOCK...')}
              />
            </div>
            <div className="mt-12 flex flex-col items-center gap-4">
              <h2 className="text-4xl font-black text-white italic tracking-tighter uppercase"><DescrambleText text="INITIALIZING_PROTOCOL_V21" /></h2>
              <div className="flex gap-2">
                {[...Array(3)].map((_, i) => (
                  <motion.div 
                    key={i} animate={{ opacity: [0.2, 1, 0.2] }} 
                    transition={{ repeat: Infinity, duration: 1, delay: i * 0.2 }}
                    className="w-2 h-2 bg-matrix rounded-full shadow-[0_0_10px_#00FF41]"
                  />
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* JACKPOT OVERLAY */}
      <AnimatePresence>
        {isJackpot && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-[1000] bg-matrix/10 flex items-center justify-center backdrop-blur-md">
            <div className="flex flex-col items-center gap-8">
              <motion.h2 animate={{ scale: [1, 1.2, 1] }} transition={{ repeat: Infinity, duration: 0.5 }} className="text-8xl font-black text-white italic tracking-tighter"><DescrambleText text="SEQUENCE_COMPLETE" /></motion.h2>
              <div className="text-4xl font-black text-matrix tracking-[1em]">JACKPOT_STRIKE_CONFIRMED</div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <header className="p-6 flex justify-between items-center border-b border-border bg-black/80 backdrop-blur-md relative z-50">
        <div className="flex items-center gap-6">
          <div className="w-12 h-12 bg-matrix flex items-center justify-center text-void font-black text-2xl shadow-[0_0_15px_#00FF41]">P</div>
          <div><h1 className="text-3xl font-black text-white tracking-tighter italic">PEACOCK<span className="text-matrix">_V21</span></h1><p className="text-[7px] font-black tracking-[0.5em] text-zinc-600 mt-1 uppercase italic">Omerta_Protocol // High_Stakes_Architecture</p></div>
        </div>
        <div className="flex gap-4">
          <button onClick={() => setSettingsOpen(true)} className="px-6 py-2 border border-zinc-800 text-[9px] font-black uppercase tracking-widest hover:border-matrix hover:text-white transition-all">Command_Deck</button>
          <button onClick={() => window.location.reload()} className="px-6 py-2 bg-matrix/10 text-matrix border border-matrix/20 text-[9px] font-black uppercase tracking-widest">Reboot</button>
        </div>
      </header>

      <MindMap />

      <main className="flex-1 flex overflow-hidden">
        <aside className="w-72 border-r border-border bg-surface/30 flex flex-col">
          <div className="flex border-b border-border">
            {['ammo', 'history', 'logs'].map(t => (
              <button key={t} onClick={() => setSidebarTab(t as any)} className={`flex-1 py-3 text-[8px] font-black uppercase tracking-widest transition-all ${sidebarTab === t ? 'bg-matrix/10 text-matrix' : 'text-zinc-700 hover:text-zinc-400'}`}>{t}</button>
            ))}
          </div>
          <div className="flex-1 overflow-y-auto p-4 custom-scrollbar space-y-2">
            {sidebarTab === 'ammo' && ammoFiles.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 opacity-20 group">
                <img 
                  src="/assets/images/bird_skull_v21.png" // Image #7
                  alt="EMPTY_AMMO" className="w-20 h-20 object-cover mb-4 rounded-xl border border-matrix/20 filter grayscale group-hover:grayscale-0 transition-all"
                  onError={(e) => (e.currentTarget.src = 'https://placehold.co/100x100/050505/00FF41?text=A')}
                />
                <p className="text-[8px] font-black tracking-widest uppercase text-matrix">Ammo_Cache_Void</p>
              </div>
            )}
            {sidebarTab === 'ammo' && ammoFiles.map(f => (
              <button key={f} onClick={async () => {
                setBusBusActive(v => ({ ...v, ammo: true }));
                const res = await axios.get(`${ENGINE_URL}/fs/ammo/${f}`);
                setInputs(v => ({ ...v, spark: res.data.content }));
                setActiveStage(PipelineStage.SPARK);
                setTimeout(() => setBusBusActive(v => ({ ...v, ammo: false })), 500);
                audioService.playSuccess();
              }} className="w-full text-left p-3 bg-zinc-950 border border-zinc-900 hover:border-matrix/30 rounded text-[9px] truncate text-zinc-500 hover:text-white group transition-all"><span className="opacity-0 group-hover:opacity-100 mr-2 text-matrix">▶</span>{f}</button>
            ))}
            {sidebarTab === 'history' && historyItems.filter(h => h.stage === activeStage).map(h => (
              <button key={h.id} onClick={() => { setInputs(v => ({ ...v, [h.stage]: h.input })); setOutputs(v => ({ ...v, [h.stage]: h.output })); setSelectedHistoryId(h.id!); audioService.playSuccess(); }} className={`w-full text-left p-3 border rounded text-[9px] transition-all ${selectedHistoryId === h.id ? 'border-matrix bg-matrix/5 text-white' : 'border-zinc-900 bg-zinc-950/50 text-zinc-600 hover:border-zinc-700'}`}>
                <div className="flex justify-between items-center mb-1"><span className="font-black text-zinc-500 uppercase">{h.stage}</span><span className="text-[7px] opacity-40">{new Date(h.timestamp).toLocaleTimeString()}</span></div>
                <p className="truncate italic">"{h.input.substring(0, 30)}"...</p>
              </button>
            ))}
            {sidebarTab === 'logs' && historyItems.map(h => (
              <div key={h.id} className="p-3 border-b border-zinc-900 opacity-60 text-[7px]"><span className="text-matrix">[SYNC]</span> {h.stage.toUpperCase()} Strike: {h.output.length} bytes</div>
            ))}
          </div>
        </aside>

        <div className="flex-1 flex flex-col bg-surface relative">
          <div className="flex justify-between items-center px-8 py-3 bg-black/40 border-b border-border">
             <div className="flex items-center gap-4">
                <span className={`w-2 h-2 rounded-full ${telemetry[activeStage].status === 'loading' ? 'bg-voltage animate-ping' : 'bg-matrix animate-pulse shadow-[0_0_8px_#00FF41]'}`} />
                <span className="text-[9px] font-black uppercase tracking-widest text-white"><DescrambleText text={`PHASE_${activeStage.toUpperCase()}_STRIKE_HUD`} /></span>
             </div>
             <div className="flex items-center gap-4">
                <TacticalModelPicker currentModelId={stageSettings[activeStage].model} onSelect={(mid: string) => setStageSettings(v => ({ ...v, [activeStage]: { ...v[activeStage], model: mid } }))} />
                <button onClick={() => executeStrike(activeStage)} disabled={telemetry[activeStage].status === 'loading'} className="px-10 py-2 bg-matrix text-void font-black text-[9px] uppercase tracking-[0.2em] hover:bg-white transition-all disabled:opacity-50">
                  {telemetry[activeStage].status === 'loading' ? 'STRIKING...' : 'EXECUTE_STRIKE'}
                </button>
             </div>
          </div>

          <div className="flex-1 flex p-6 gap-6 overflow-hidden">
             <div className="flex-1 flex flex-col gap-3">
                <span className="text-[7px] font-black text-zinc-700 uppercase tracking-[0.3em] px-2">Payload_Input</span>
                <textarea className={`flex-1 bg-black/40 border rounded-lg p-6 text-sm mono text-zinc-300 outline-none transition-all resize-none custom-scrollbar ${selectedHistoryId ? 'border-matrix shadow-[0_0_15px_rgba(0,255,65,0.1)]' : 'border-border focus:border-matrix/20'} ${casinoSettings.vibrations && telemetry[activeStage].status === 'loading' ? 'animate-shake' : ''}`} value={inputs[activeStage]} onChange={(e) => setInputs(v => ({ ...v, [activeStage]: e.target.value }))} placeholder={`Awaiting tactical data for ${activeStage.toUpperCase()}...`} />
             </div>
             <div className="flex-1 flex flex-col gap-3">
                <span className="text-[7px] font-black text-zinc-700 uppercase tracking-[0.3em] px-2">Intelligence_Feed</span>
                <div className={`flex-1 bg-black/60 border rounded-lg p-6 text-sm mono text-zinc-400 overflow-y-auto custom-scrollbar whitespace-pre-wrap relative group ${selectedHistoryId ? 'border-matrix shadow-[0_0_15px_rgba(0,255,65,0.1)]' : 'border-border'}`}>
                   {outputs[activeStage] ? (
                     <>
                       <button onClick={() => { navigator.clipboard.writeText(outputs[activeStage]); audioService.playSuccess(); }} className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity bg-zinc-950 border border-zinc-800 px-3 py-1 text-[8px] font-black text-matrix hover:border-matrix">COPY_INTEL</button>
                       {outputs[activeStage]}
                     </>
                   ) : (
                     <div className="h-full flex flex-col items-center justify-center opacity-30">
                        <img 
                          src="/assets/images/bird_skull_v21.png" // Image #7
                          alt="NO_DATA" className="w-40 h-40 object-cover border border-matrix/10 rounded-3xl mb-6 grayscale hover:grayscale-0 transition-all cursor-crosshair"
                          onError={(e) => (e.currentTarget.src = 'https://placehold.co/200x200/050505/00FF41?text=AWAITING_DATA')}
                        />
                        <p className="text-[10px] font-black tracking-[0.5em] uppercase italic text-matrix">System_Awaiting_Strike_Execution</p>
                     </div>
                   )}
                </div>
             </div>
          </div>

          {activeStage === PipelineStage.OWL && owlQueue.length > 0 && (
            <motion.div initial={{ y: 50, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="h-64 border-t border-border bg-zinc-950/90 backdrop-blur-xl p-6 overflow-x-auto flex gap-4 custom-scrollbar">
              {owlQueue.map(file => (
                <button key={file.id} onClick={() => strikeOwlFile(file)} className={`shrink-0 w-72 p-5 border rounded-lg flex flex-col gap-3 transition-all relative group ${activeOwlFile?.id === file.id ? 'border-voltage ring-1 ring-voltage shadow-[0_0_20px_rgba(255,215,0,0.1)]' : file.status === 'completed' ? 'border-matrix/40 bg-matrix/5' : 'border-zinc-800 bg-zinc-950/50 hover:border-zinc-600'}`}>
                  <div className="flex justify-between items-center"><span className="text-[10px] font-black text-white truncate w-48 italic">{file.path}</span><div className={`w-2 h-2 rounded-full ${file.status === 'completed' ? 'bg-matrix' : 'bg-zinc-800'}`} /></div>
                  <div className="text-[8px] text-zinc-600 line-clamp-4 leading-relaxed opacity-60 italic">{file.skeleton}</div>
                  {file.status === 'completed' && (
                    <button onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(file.output || ''); audioService.playSuccess(); }} className="mt-auto py-2 bg-matrix/10 text-matrix text-[8px] font-black uppercase rounded border border-matrix/20 hover:bg-matrix hover:text-void transition-colors">Copy_Implementation</button>
                  )}
                </button>
              ))}
            </motion.div>
          )}
        </div>
      </main>

      <SettingsDeck open={settingsOpen} setOpen={setSettingsOpen} tab={settingsTab} setTab={setSettingsTab} models={models} casino={casinoSettings} setCasino={setCasinoSettings} />

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap');
        * { font-family: 'JetBrains Mono', monospace; }
        ::selection { background: #00FF41; color: #000; }
        .scanlines::before {
          content: ""; position: absolute; inset: 0; pointer-events: none; z-index: 1000;
          background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.1) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.03), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.03));
          background-size: 100% 3px, 2px 100%;
        }
        .custom-scrollbar::-webkit-scrollbar { width: 3px; height: 3px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: #050505; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #1a1a1a; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #00FF41; }
        @keyframes shake { 0%, 100% { transform: translate(0,0); } 20% { transform: translate(-2px, 1px); } 40% { transform: translate(2px, -1px); } 60% { transform: translate(-1px, 2px); } 80% { transform: translate(1px, -2px); } } 
        .animate-shake { animation: shake 0.1s infinite; }
      `}</style>
    </div>
  );
};

const SettingsDeck = ({ open, setOpen, tab, setTab, models, casino, setCasino }: any) => (
  <AnimatePresence>
    {open && (
      <>
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setOpen(false)} className="fixed inset-0 bg-black/90 backdrop-blur-sm z-[90]" />
        <motion.div initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }} className="fixed inset-y-0 right-0 w-[600px] bg-surface border-l border-border z-[100] shadow-2xl p-10 flex flex-col gap-8">
          <div className="flex justify-between items-center">
            <div><h2 className="text-2xl font-black text-white tracking-tighter italic">COMMAND_DECK</h2><p className="text-[8px] font-black text-zinc-600 uppercase tracking-widest mt-1">System_Configuration_Override</p></div>
            <button onClick={() => setOpen(false)} className="w-10 h-10 rounded-full border border-zinc-800 flex items-center justify-center text-zinc-600 hover:text-error transition-all">✕</button>
          </div>
          <div className="flex gap-6 border-b border-border">
            {['nodes', 'prompts', 'casino', 'engine'].map(t => (
              <button key={t} onClick={() => setTab(t as any)} className={`pb-4 text-[10px] font-black uppercase tracking-[0.2em] transition-all ${tab === t ? 'text-matrix border-b-2 border-matrix' : 'text-zinc-700 hover:text-zinc-400'}`}>{t}</button>
            ))}
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar pr-4">
            {tab === 'nodes' && models.map((m: any) => (
              <div key={m.id} className="p-5 bg-zinc-950 border border-zinc-900 rounded-lg mb-4 hover:border-matrix/20 transition-all">
                <div className="flex justify-between items-center mb-3"><span className="text-xs font-black text-white">{m.id}</span><span className={`text-[7px] font-black uppercase px-2 py-0.5 rounded ${m.tier === 'expensive' ? 'bg-red-950/30 text-red-500' : 'bg-matrix/10 text-matrix'}`}>{m.tier}</span></div>
                <p className="text-[9px] text-zinc-600 italic leading-relaxed">{m.note}</p>
              </div>
            ))}
            {tab === 'prompts' && ['spark', 'falcon', 'eagle', 'owl', 'hawk', 'owl_v21'].map(id => <PromptEditor key={id} stageId={id} label={id.toUpperCase()} />)}
            {tab === 'casino' && Object.entries(casino).map(([key, val]) => (
              <div key={key} className="flex justify-between items-center p-5 bg-zinc-950 border border-zinc-900 rounded-lg mb-4"><span className="text-[10px] font-black uppercase tracking-widest text-white">{key}</span><button onClick={() => setCasino((v: any) => ({ ...v, [key]: !val }))} className={`w-14 h-7 rounded-full relative transition-all border-2 ${val ? 'bg-matrix border-matrix' : 'bg-zinc-900 border-zinc-800'}`}><motion.div animate={{ x: val ? 28 : 4 }} className="w-4 h-4 bg-void rounded-full absolute top-1" /></button></div>
            ))}
          </div>
        </motion.div>
      </>
    )}
  </AnimatePresence>
);

const PromptEditor = ({ stageId, label }: { stageId: string, label: string }) => {
  const [content, setContent] = useState('');
  useEffect(() => { db.prompts.get(stageId).then(p => setContent(p?.content || '')); }, [stageId]);
  const save = async () => {
    await db.prompts.put({ id: stageId, content });
    try { await axios.post(`${ENGINE_URL}/fs/prompts`, { id: stageId, content }); } catch (e) {}
    audioService.playSuccess();
  };
  return (
    <div className="space-y-3 p-6 bg-zinc-950 border border-zinc-900 rounded-xl mb-6">
      <div className="flex justify-between items-center"><span className="text-[9px] font-black text-white uppercase tracking-widest">{label}</span><button onClick={save} className="text-[8px] font-black text-matrix hover:underline uppercase">Sync_To_Disk</button></div>
      <textarea className="w-full h-40 bg-black/60 border border-zinc-800 rounded p-4 text-[11px] text-zinc-400 outline-none focus:border-matrix/30 transition-all custom-scrollbar resize-none font-mono" value={content} onChange={(e) => setContent(e.target.value)} spellCheck={false} />
    </div>
  );
};

const DescrambleText = ({ text }: { text: string }) => {
  const [display, setDisplay] = useState('');
  useEffect(() => {
    let iteration = 0;
    const interval = setInterval(() => {
      setDisplay(text.split('').map((c, i) => i < iteration ? text[i] : "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$#@%"[Math.floor(Math.random() * 36)]).join(''));
      if (iteration >= text.length) clearInterval(interval);
      iteration += 1/2;
    }, 30);
    return () => clearInterval(interval);
  }, [text]);
  return <span>{display}</span>;
};

export default App;
