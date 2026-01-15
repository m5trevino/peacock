import React, { useState, useEffect, useRef, useMemo, memo } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { PipelineStage, ModelConfig, StageSettings, CallTelemetry, OwlFile, PromptAsset, SessionData } from './types';
import { audioService } from './services/audioService';

// ============================================================ 
// ⚡ V25.5 ORBITAL STRIKE DOCTRINE
// ============================================================ 
const THEME = {
  void: '#0A0B0D',
  surface: '#121418',
  elevated: '#1A1D23',
  border: '#1E2227',
  text: '#E5E7EB',
  muted: '#4B5563',
  matrix: '#00FF41',
  voltage: '#FFD700',
  purple: '#BC13FE',
  cyan: '#00FFFF',
  error: '#FF3131',
  gold: 'rgba(255, 215, 0, 0.4)'
};

const STAGES = [
  { id: PipelineStage.SPARK, label: 'SPARK', color: THEME.voltage, video: '/assets/images/spark.webm' },
  { id: PipelineStage.FALCON, label: 'FALCON', color: THEME.cyan, video: '/assets/images/falcon.webm' },
  { id: PipelineStage.EAGLE, label: 'EAGLE', color: THEME.purple, video: '/assets/images/eagle.webm' },
  { id: PipelineStage.OWL, label: 'OWL', color: THEME.matrix, video: '/assets/images/owl.webm' },
  { id: PipelineStage.HAWK, label: 'HAWK', color: THEME.matrix, video: '/assets/images/hawk.webm' }
];

const ENGINE_URL = 'http://localhost:8888/v1';

// --- SHARED UTILS ---
const DescrambleText = ({ text }: { text?: string }) => {
  const [display, setDisplay] = useState('');
  useEffect(() => {
    if (!text) return;
    let iteration = 0;
    const interval = setInterval(() => {
      setDisplay(text.split('').map((c, i) => i < iteration ? text[i] : "$#@%&*"[Math.floor(Math.random() * 6)]).join(''));
      if (iteration >= text.length) clearInterval(interval);
      iteration += 1 / 2;
    }, 20);
    return () => clearInterval(interval);
  }, [text]);
  return <span>{display || '---'}</span>;
};

// --- SUB-COMPONENT: BLACK BOX CLI ---
const VerbatimCLI = memo(({ height, onMouseDown }: { height: number, onMouseDown: () => void }) => {
  const [logs, setLogs] = useState<string[]>([]);
  useEffect(() => {
    const poll = setInterval(async () => {
      try {
        const res = await axios.get(`${ENGINE_URL}/logs`);
        if (res.data) setLogs(res.data);
      } catch (e) {}
    }, 1000);
    return () => clearInterval(poll);
  }, []);

  return (
    <footer className="w-full bg-void border-t border-border z-[100] flex flex-col shrink-0 overflow-hidden" style={{ height }}>
      <div className="h-1.5 bg-border hover:bg-matrix cursor-ns-resize transition-all" onMouseDown={onMouseDown} />
      <div className="h-10 bg-surface/50 border-b border-border flex justify-between items-center px-10">
        <span className="text-[10px] font-black text-matrix animate-pulse uppercase tracking-[0.4em]">Black_Box_Verbatim_Link</span>
        <span className="text-muted text-[9px] mono font-bold uppercase tracking-widest">Buffer_Synced // TOC_Active</span>
      </div>
      <div className="flex-1 overflow-y-auto p-8 font-mono text-[12px] space-y-1 custom-scrollbar bg-void/90">
        {logs.map((log, i) => (
          <div key={i} className="flex gap-6 text-muted hover:text-zinc-200 transition-all">
            <span className="opacity-20 shrink-0 w-12 text-right">{(i+1).toString().padStart(4,'0')}</span>
            <span className={`tracking-tight break-all`}>{log}</span>
          </div>
        ))}
        <div className="text-matrix opacity-20 animate-pulse mt-4 text-xs">_SYSTEM_AWAITING_INPUT_COMMAND...</div>
      </div>
    </footer>
  );
});

const App: React.FC = () => {
  // --- STATE ---
  const [sessionId, setSessionId] = useState<string>(`OP_${Date.now()}`);
  const [sessionName, setSessionName] = useState<string>('NEW_WAR_OP');
  const [activeStageId, setActiveStageId] = useState<PipelineStage>(PipelineStage.SPARK);
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [dossierOpen, setDossierOpen] = useState(false);
  
  const [inputs, setInputs] = useState<Record<string, string>>({ spark: '', falcon: '', eagle: '', owl: '', hawk: '' });
  const [outputs, setOutputs] = useState<Record<string, string>>({ spark: '', falcon: '', eagle: '', owl: '', hawk: '' });
  const [telemetry, setTelemetry] = useState<Record<string, CallTelemetry>>({
    spark: { status: 'idle' }, falcon: { status: 'idle' }, eagle: { status: 'idle' }, owl: { status: 'idle' }, hawk: { status: 'idle' }
  });
  
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [arsenal, setArsenal] = useState<Record<string, PromptAsset[]>>({ spark: [], falcon: [], eagle: [], owl: [], hawk: [] });
  const [activePrompts, setActivePrompts] = useState<Record<string, string>>({});
  
  const [startFiles, setStartFiles] = useState<any[]>([]);
  const [sessionFiles, setSessionFiles] = useState<any[]>([]);
  const [expandedControl, setExpandedControl] = useState<'payload' | 'prompt' | null>(null);
  const [cliHeight, setCliHeight] = useState(180);
  const [isDraggingCli, setIsDraggingCli] = useState(false);
  const [mouseInConvenienceZone, setMouseInConvenienceZone] = useState(false);

  const [stageSettings, setStageSettings] = useState<Record<string, StageSettings>>({
    spark: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
    falcon: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.5 },
    eagle: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.3 },
    owl: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.2 },
    hawk: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.4 }
  });

  const activeStage = useMemo(() => STAGES.find(s => s.id === activeStageId)!, [activeStageId]);

  // --- ENGINE SYNC ---
  const sync = async () => {
    try {
      const [start, sessions, modelsRes] = await Promise.all([
        axios.get(`${ENGINE_URL}/fs/start`), axios.get(`${ENGINE_URL}/fs/sessions`), axios.get(`${ENGINE_URL}/models`)
      ]);
      setStartFiles(start.data); setSessionFiles(sessions.data); setModels(modelsRes.data);
      const phases = [PipelineStage.SPARK, PipelineStage.FALCON, PipelineStage.EAGLE, PipelineStage.OWL, PipelineStage.HAWK];
      const newArsenal: any = {};
      const newActive: any = { ...activePrompts };
      for (const p of phases) {
        const res = await axios.get(`${ENGINE_URL}/fs/prompts/${p}`);
        newArsenal[p] = res.data;
        if (!newActive[p] && res.data.length > 0) newActive[p] = res.data[0].name;
      }
      setArsenal(newArsenal); setActivePrompts(newActive);
    } catch (e) {}
  };

  useEffect(() => { sync(); }, []);

  const saveSession = async () => {
    const fileName = `${new Date().toLocaleDateString().replace(/\//g,'-')}.${sessionName}.session.json`;
    await axios.post(`${ENGINE_URL}/fs/sessions`, { name: fileName, data: { inputs, outputs, telemetry, activePrompts, name: sessionName, id: sessionId } });
    sync();
  };

  const loadSession = async (f: string) => {
    const res = await axios.get(`${ENGINE_URL}/fs/sessions/${f}`);
    const s: SessionData = res.data;
    setInputs(s.inputs); setOutputs(s.outputs); setTelemetry(s.telemetry); setActivePrompts(s.activePrompts || {});
    setSessionName(s.name || f.split('.')[1]); setSessionId(s.id); setArchiveOpen(false); audioService.playSuccess();
  };

  const executeStrike = async (stageId: PipelineStage) => {
    setTelemetry(prev => ({ ...prev, [stageId]: { status: 'loading' } }));
    try {
      const prompt = arsenal[stageId]?.find(p => p.name === activePrompts[stageId])?.content || inputs[stageId];
      const res = await axios.post(`${ENGINE_URL}/strike`, { modelId: stageSettings[stageId].model, prompt, temp: stageSettings[stageId].temperature });
      setOutputs(prev => ({ ...prev, [stageId]: res.data.content }));
      setTelemetry(prev => ({ ...prev, [stageId]: { status: 'success' } }));
      setDossierOpen(true);
      if (stageId === PipelineStage.SPARK) setInputs(v => ({ ...v, falcon: res.data.content }));
      if (stageId === PipelineStage.FALCON) setInputs(v => ({ ...v, eagle: res.data.content }));
      if (stageId === PipelineStage.OWL) setInputs(v => ({ ...v, hawk: res.data.content }));
      saveSession();
    } catch (e) { setTelemetry(prev => ({ ...prev, [stageId]: { status: 'error' } })); }
  };

  const proceedToNext = () => {
    const nextMap: any = { [PipelineStage.SPARK]: PipelineStage.FALCON, [PipelineStage.FALCON]: PipelineStage.EAGLE, [PipelineStage.EAGLE]: PipelineStage.OWL, [PipelineStage.OWL]: PipelineStage.HAWK };
    if (nextMap[activeStageId]) setActiveStageId(nextMap[activeStageId]);
    setDossierOpen(false);
    audioService.playSuccess();
  };

  const handleMouseMove = (e: MouseEvent) => {
    if (!isDraggingCli) return;
    setCliHeight(Math.max(40, window.innerHeight - e.clientY));
  };

  useEffect(() => {
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', () => setIsDraggingCli(false));
    return () => { window.removeEventListener('mousemove', handleMouseMove); };
  }, [isDraggingCli]);

  // --- UI COMPONENTS ---
  const MiniMap = () => (
    <div className="w-full flex flex-col items-center gap-8 py-12 bg-void/40 border-b border-border relative overflow-hidden shrink-0">
      <div className="absolute inset-0 opacity-10 pointer-events-none bg-[radial-gradient(circle_at_center,rgba(0,255,65,0.15),transparent)]" />
      <div className="flex flex-col items-center z-10">
        <span className="text-[10px] text-muted font-black uppercase tracking-[0.6em] mb-3">Mission_Log</span>
        <h2 className="text-4xl font-black text-white italic tracking-tighter uppercase border-x-2 border-white/5 px-10">
          <DescrambleText text={sessionName} />
        </h2>
      </div>
      
      <div className="relative w-[1000px] h-24 flex justify-between items-center px-20">
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <defs><filter id="minimap-glow"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
          <path d="M 150 48 H 325" stroke={outputs.spark ? THEME.voltage : '#1a1a1a'} strokeWidth="3" filter="url(#minimap-glow)" className="transition-all duration-700" />
          <path d="M 325 48 H 500" stroke={outputs.falcon ? THEME.cyan : '#1a1a1a'} strokeWidth="3" filter="url(#minimap-glow)" className="transition-all duration-700" />
          <path d="M 500 48 H 675" stroke={outputs.eagle ? THEME.purple : '#1a1a1a'} strokeWidth="3" filter="url(#minimap-glow)" className="transition-all duration-700" />
          <path d="M 675 48 H 850" stroke={outputs.owl ? THEME.matrix : '#1a1a1a'} strokeWidth="3" filter="url(#minimap-glow)" className="transition-all duration-700" />
          {outputs.spark && <circle r="3" fill="#fff" filter="url(#minimap-glow)"><animateMotion dur="3s" repeatCount="indefinite" path="M 150 48 H 325" /></circle>}
          {outputs.falcon && <circle r="3" fill="#fff" filter="url(#minimap-glow)"><animateMotion dur="3s" repeatCount="indefinite" path="M 325 48 H 500" /></circle>}
          {outputs.eagle && <circle r="3" fill="#fff" filter="url(#minimap-glow)"><animateMotion dur="3s" repeatCount="indefinite" path="M 500 48 H 675" /></circle>}
          {outputs.owl && <circle r="3" fill="#fff" filter="url(#minimap-glow)"><animateMotion dur="2s" repeatCount="indefinite" path="M 675 48 H 850" /></circle>}
        </svg>
        
        {STAGES.map((s) => {
          const done = !!outputs[s.id];
          const current = activeStageId === s.id;
          return (
            <div key={s.id} className="relative z-10 flex flex-col items-center gap-3">
              <div className={`w-14 h-14 rounded-xl border-2 flex items-center justify-center transition-all duration-700 cursor-pointer ${done ? 'bg-void border-white shadow-[0_0_20px_rgba(255,255,255,0.3)]' : current ? 'border-voltage shadow-[0_0_20px_rgba(255,215,0,0.2)]' : 'border-border grayscale opacity-30'}`} onClick={() => { setActiveStageId(s.id); setExpandedControl(null); }}>
                <img src={s.video.replace('.webm', '.png')} className="w-8 h-8 object-contain" />
              </div>
              <span className={`text-[10px] font-black tracking-widest ${done ? 'text-white' : current ? 'text-voltage' : 'text-zinc-800'}`}>{s.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );

  const TacticalChamber = () => {
    const isLoading = telemetry[activeStageId].status === 'loading';
    const done = !!outputs[activeStageId];
    
    const getStartButtonLabel = () => {
      if (activeStageId === PipelineStage.SPARK) return "Start";
      const prevIdx = STAGES.findIndex(s => s.id === activeStageId) - 1;
      return `${STAGES[prevIdx].label} Output`;
    };

    return (
      <div className="flex-1 flex flex-col items-center p-12 overflow-y-auto custom-scrollbar">
        <div className="flex flex-col items-center gap-10 w-full max-w-6xl">
          {/* THE SPOTLIGHT ICON */}
          <motion.div 
            key={activeStageId}
            initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
            className="w-[350px] h-[350px] relative flex items-center justify-center"
          >
            <div className={`absolute inset-0 rounded-full blur-[100px] opacity-20 transition-all duration-1000 ${isLoading ? 'bg-voltage scale-125' : done ? 'bg-matrix' : 'bg-white/5'}`} />
            <video key={activeStage.video} src={activeStage.video} autoPlay loop muted playsInline className="w-full h-full object-contain relative z-10 mix-blend-screen" />
            <span className="absolute bottom-[-20px] z-20 text-xl font-black text-white italic tracking-[0.5em] uppercase">{activeStage.label}</span>
          </motion.div>

          {/* MARVELOUS BUTTONS */}
          <div className="flex flex-col gap-8 items-center w-full mt-10">
            <div className="flex gap-6 w-full justify-center">
              <button 
                onClick={() => setExpandedControl(expandedControl === 'payload' ? null : 'payload')}
                className={`w-64 py-5 rounded-2xl font-black text-xs uppercase tracking-widest transition-all border-2 shadow-2xl
                  ${expandedControl === 'payload' ? 'bg-white text-void border-white' : 'bg-surface text-muted border-border hover:text-white'}
                `}
              >
                {getStartButtonLabel()}
              </button>
              <button 
                onClick={() => setExpandedControl(expandedControl === 'prompt' ? null : 'prompt')}
                className={`w-64 py-5 rounded-2xl font-black text-xs uppercase tracking-widest transition-all border-2 shadow-2xl
                  ${expandedControl === 'prompt' ? 'bg-white text-void border-white' : 'bg-surface text-muted border-border hover:text-white'}
                `}
              >
                Prompt
              </button>
            </div>

            {/* EXPANDED LISTING / PEEK ZONE */}
            <div 
              className="w-[800px] relative"
              onMouseEnter={() => setMouseInConvenienceZone(true)}
              onMouseLeave={() => setMouseInConvenienceZone(false)}
            >
              <AnimatePresence>
                {(expandedControl || (mouseInConvenienceZone && !dossierOpen)) && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="bg-surface border-2 border-border rounded-[2.5rem] overflow-hidden shadow-[0_0_100px_rgba(0,0,0,0.5)] mb-10">
                    <div className="p-10 max-h-[400px] overflow-y-auto custom-scrollbar space-y-3">
                      {expandedControl === 'payload' && activeStageId === 'spark' && startFiles.map(f => (
                        <button key={f.name} onClick={() => { axios.get(`${ENGINE_URL}/fs/start/${f.name}`).then(r => setInputs(v=>({...v, spark: r.data.content}))); setSessionName(f.name.replace(/\.(md|txt)/, '')); setExpandedControl(null); }} className="w-full text-left p-6 bg-void/50 border border-border rounded-2xl hover:border-matrix transition-all">
                          <div className="flex justify-between items-center mb-2"><span className="text-white font-bold text-sm">{f.name}</span><span className="text-[9px] text-muted uppercase font-bold">Modified: {new Date(f.modified).toLocaleDateString()}</span></div>
                          <span className="text-[8px] text-zinc-700 uppercase tracking-widest">Created: {new Date(f.created).toLocaleDateString()}</span>
                        </button>
                      ))}
                      {expandedControl === 'payload' && activeStageId !== 'spark' && (
                        <div className="p-8 bg-void/50 border border-border rounded-[2rem] relative overflow-hidden group">
                          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-matrix/5 to-transparent animate-[shimmer_3s_infinite] pointer-events-none" />
                          <span className="text-[10px] font-black text-matrix uppercase tracking-widest mb-6 block">Guest_Of_Honor // Pipeline_DNA</span>
                          <div className="text-[16px] mono text-zinc-400 line-clamp-10 leading-relaxed italic">{inputs[activeStageId] || "NO_DNA_LOADED"}</div>
                        </div>
                      )}
                      {expandedControl === 'prompt' && arsenal[activeStageId]?.map(p => (
                        <button key={p.name} onClick={() => { setActivePrompts(v=>({...v, [activeStageId]: p.name})); setExpandedControl(null); }} className={`w-full text-left p-6 border rounded-2xl transition-all ${activePrompts[activeStageId] === p.name ? 'bg-matrix/10 border-matrix/40 text-white shadow-xl' : 'bg-void/50 border-border text-muted hover:text-white'}`}>{p.name.toUpperCase()}</button>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* OMEGA STRIKE BUTTON */}
              <button 
                onClick={() => executeStrike(activeStageId)}
                className={`w-full py-8 rounded-[2.5rem] font-black text-lg uppercase tracking-[0.6em] transition-all shadow-2xl border-4
                  ${isLoading ? 'bg-zinc-800 text-zinc-600 animate-pulse border-zinc-700' : 'bg-voltage text-void border-voltage hover:bg-white hover:scale-[1.02]'}
                `}
              >
                {isLoading ? "CONDUCTING_STRIKE" : `EXECUTE_${activeStage.label}_DRIVE`}
              </button>
            </div>

            {/* INTELLIGENCE PLATES (GUEST OF HONOR) */}
            <div className="grid grid-cols-2 gap-10 w-full mt-12 pb-20">
              <div className="bg-surface/50 border-2 border-border rounded-[3rem] overflow-hidden flex flex-col shadow-inner">
                <div className="px-10 py-4 bg-void/50 border-b border-border flex justify-between items-center">
                  <span className="text-[10px] font-bold text-muted uppercase tracking-widest">Active_Payload</span>
                  <div className="w-2 h-2 rounded-full bg-cyan shadow-[0_0_10px_#00FFFF]" />
                </div>
                <div className="flex-1 p-10 text-[15px] mono text-muted h-[300px] overflow-y-auto custom-scrollbar italic whitespace-pre-wrap leading-relaxed bg-[radial-gradient(circle_at_top_right,rgba(0,255,255,0.02),transparent)]">
                  {inputs[activeStageId] || "AWAITING_DATA_INJECTION..."}
                </div>
              </div>
              <div className="bg-surface/50 border-2 border-border rounded-[3rem] overflow-hidden flex flex-col shadow-inner">
                <div className="px-10 py-4 bg-void/50 border-b border-border flex justify-between items-center">
                  <span className="text-[10px] font-bold text-muted uppercase tracking-widest">Selected_Profile</span>
                  <div className="w-2 h-2 rounded-full bg-purple shadow-[0_0_10px_#BC13FE]" />
                </div>
                <div className="flex-1 p-10 text-[15px] mono text-muted h-[300px] overflow-y-auto custom-scrollbar whitespace-pre-wrap leading-relaxed">
                  {arsenal[activeStageId]?.find(p => p.name === activePrompts[activeStageId])?.content || "NO_MISSION_PROFILE_ARMED"}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="h-screen bg-void text-text font-inter flex flex-col relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none z-[100] opacity-[0.05] bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_3px,3px_100%]" />
      
      <header className="px-10 h-24 flex justify-between items-center border-b border-border bg-surface z-[60] shrink-0 shadow-2xl">
        <div className="flex items-center gap-8">
          <div className="w-16 h-16 bg-matrix flex items-center justify-center text-void font-black text-4xl rounded-xl shadow-[0_0_30px_rgba(0,255,65,0.3)]">P</div>
          <div><h1 className="text-4xl font-black text-white italic tracking-tighter">PEACOCK<span className="text-matrix">_V25.5</span></h1><p className="text-[10px] font-bold text-muted uppercase italic tracking-[0.5em] mt-2 italic">Anti-Vibe Coding App // Orbital_Strike</p></div>
        </div>
        <div className="flex gap-6">
          <button onClick={() => setArchiveOpen(true)} className="px-10 py-3 border border-border text-xs font-black uppercase hover:border-matrix hover:text-white transition-all bg-void rounded shadow-xl">Archive</button>
          <button onClick={() => window.location.reload()} className="px-10 py-3 bg-matrix/10 text-matrix border border-matrix/20 text-xs font-black uppercase tracking-widest rounded shadow-xl hover:bg-matrix hover:text-void transition-all">Re-Boot</button>
        </div>
      </header>

      <main className="flex-1 flex flex-col min-h-0 bg-[#0B0D10] relative">
        <MiniMap />
        <TacticalChamber />
      </main>

      <VerbatimCLI height={cliHeight} onMouseDown={() => setIsDraggingCli(true)} />

      {/* ARCHIVE MODAL */}
      <AnimatePresence>
        {archiveOpen && (
          <div className="fixed inset-0 z-[300] flex items-center justify-center p-20 bg-void/98 backdrop-blur-3xl">
            <div className="w-full max-w-7xl h-full flex flex-col gap-12">
              <div className="flex justify-between items-center border-b border-white/5 pb-10">
                <div><span className="text-[14px] font-black text-matrix tracking-[0.6em] uppercase italic">Mission_Logs</span><h3 className="text-6xl font-black text-white italic uppercase tracking-tighter mt-4">Operational_Archive</h3></div>
                <button onClick={() => setArchiveOpen(false)} className="text-zinc-500 hover:text-white text-7xl">✕</button>
              </div>
              <div className="flex-1 overflow-y-auto custom-scrollbar grid grid-cols-3 gap-10 pr-10">
                {sessionFiles.map(f => (
                  <button key={f.name} onClick={() => loadSession(f.name)} className="group text-left p-12 bg-surface border-2 border-border rounded-[4rem] hover:border-matrix transition-all shadow-2xl flex flex-col gap-8">
                    <span className="text-muted text-[11px] font-black uppercase tracking-widest">Modified: {new Date(f.modified).toLocaleDateString()}</span>
                    <h4 className="text-3xl font-black text-zinc-400 group-hover:text-matrix transition-colors uppercase italic tracking-tighter">{f.name.split('.')[1]}</h4>
                    <div className="mt-auto pt-8 border-t border-white/5 flex justify-between items-center"><span className="text-[10px] font-bold text-zinc-700 uppercase italic">REHYDRATION_READY</span><span className="text-matrix group-hover:translate-x-2 transition-all">▶▶</span></div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
      </AnimatePresence>

      {/* SUCCESS DOSSIER */}
      <AnimatePresence>{dossierOpen && (
        <div className="fixed inset-0 z-[200] flex items-center justify-center p-12 bg-black/95 backdrop-blur-3xl">
          <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="w-full max-w-7xl aspect-video bg-surface border-2 border-border rounded-[4.5rem] p-20 flex flex-col gap-12 shadow-2xl relative overflow-hidden">
            <h2 className="text-7xl font-black text-white italic uppercase tracking-tighter border-b border-white/5 pb-12">SYNC_COMPLETE</h2>
            <div className="flex-1 grid grid-cols-2 gap-16 min-h-0">
              <div className="bg-void border border-border rounded-[3rem] overflow-hidden flex flex-col shadow-inner"><div className="px-12 py-5 bg-surface/50 border-b border-border text-muted font-bold text-[13px] uppercase tracking-widest italic">Instruction_Set</div><div className="flex-1 p-12 text-[15px] mono text-muted overflow-y-auto custom-scrollbar italic whitespace-pre-wrap leading-relaxed">{inputs[activeStageId]}</div></div>
              <div className="bg-void border border-matrix/20 rounded-[3rem] overflow-hidden flex flex-col shadow-inner"><div className="px-12 py-5 bg-surface/50 border-b border-border text-matrix font-bold text-[13px] uppercase tracking-widest italic">Extracted_Intel</div><div className="flex-1 p-12 text-[15px] mono text-matrix/90 overflow-y-auto custom-scrollbar whitespace-pre-wrap leading-relaxed">{outputs[activeStageId]}</div></div>
            </div>
            <button onClick={proceedToNext} className="w-full py-12 bg-matrix text-void font-black uppercase text-2xl tracking-[0.6em] rounded-3xl hover:bg-white transition-all shadow-2xl">PROCEED ▶▶</button>
          </motion.div>
        </div>
      )}</AnimatePresence>

      <style>{`
        @keyframes shimmer { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }
        body { font-family: 'Inter', sans-serif; background: #0D0F12; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .custom-scrollbar::-webkit-scrollbar { width: 6px; height: 6px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #252930; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #00FF41; }
        ::selection { background: #00FF41; color: #000; }
      `}</style>
    </div>
  );
};

export default App;