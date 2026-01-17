import React, { useState, useEffect, useRef, useMemo, memo } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { PipelineStage, ModelConfig, StageSettings, CallTelemetry, OwlFile, PromptAsset, SessionData } from './types';
import { audioService } from './services/audioService';

// ============================================================ 
// ⚡ AVIARY V26.2: 2027 FRONTIER SPEC HUD
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

const CustomDropdown = ({ value, options, onChange, label }: { value: string, options: ModelConfig[], onChange: (v: string) => void, label: string }) => {
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const clickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setIsOpen(false);
    };
    document.addEventListener('mousedown', clickOutside);
    return () => document.removeEventListener('mousedown', clickOutside);
  }, []);

  return (
    <div className="relative w-full" ref={containerRef}>
      <span className="text-[8px] font-black text-muted uppercase tracking-[0.3em] mb-2 block pl-1">{label}</span>
      <button 
        onClick={() => setIsOpen(!isOpen)}
        className="w-full bg-void border border-white/5 rounded-lg p-3 text-[10px] mono text-white font-black uppercase flex justify-between items-center hover:border-voltage transition-all shadow-inner"
      >
        <span className="truncate">{value.toUpperCase()}</span>
        <span className={`transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`}>▼</span>
      </button>
      <AnimatePresence>
        {isOpen && (
          <motion.div 
            initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 5 }}
            className="absolute bottom-full left-0 w-full mb-2 bg-elevated border border-white/10 rounded-xl overflow-hidden shadow-[0_20px_50px_rgba(0,0,0,0.8)] z-[200] max-h-64 overflow-y-auto custom-scrollbar"
          >
            {options.map(opt => (
              <button 
                key={opt.id}
                onClick={() => { onChange(opt.id); setIsOpen(false); }}
                className={`w-full text-left px-4 py-3 text-[9px] mono font-bold uppercase transition-all flex justify-between items-center border-b border-white/5 hover:bg-matrix/10 hover:text-matrix ${value === opt.id ? 'text-matrix bg-matrix/5' : 'text-white/60'}`}
              >
                <span>{opt.id.toUpperCase()}</span>
                {value === opt.id && <span className="text-matrix">●</span>}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const App: React.FC = () => {
  const [sessionId, setSessionId] = useState<string>(`OP_${Date.now()}`);
  const [sessionName, setSessionName] = useState<string>('AVIARY');
  const [activeStageId, setActiveStageId] = useState<PipelineStage>(PipelineStage.SPARK);
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [dossierOpen, setDossierOpen] = useState(false);
  
  const [inputs, setInputs] = useState<Record<string, string>>({ spark: '', falcon: '', eagle: '', owl: '', hawk: '' });
  const [outputs, setOutputs] = useState<Record<string, string>>({ spark: '', falcon: '', eagle: '', owl: '', hawk: '' });
  const [telemetry, setTelemetry] = useState<Record<string, CallTelemetry>>({
    spark: { status: 'idle' }, falcon: { status: 'idle' }, eagle: { status: 'idle' }, owl: { status: 'idle' }, hawk: { status: 'idle' }
  });
  
  const [owlQueue, setOwlQueue] = useState<OwlFile[]>([]);
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [arsenal, setArsenal] = useState<Record<string, PromptAsset[]>>({ spark: [], falcon: [], eagle: [], owl: [], hawk: [] });
  const [activePrompts, setActivePrompts] = useState<Record<string, string>>({});
  
  const [startFiles, setStartFiles] = useState<any[]>([]);
  const [sessionFiles, setSessionFiles] = useState<any[]>([]);
  const [expandedControl, setExpandedControl] = useState<'hub' | null>(null);
  const [cliHeight, setCliHeight] = useState(180);
  const [isDraggingCli, setIsDraggingCli] = useState(false);
  const [leftPanelTab, setLeftPanelTab] = useState<'data' | 'prompts'>('prompts');
  const [previewContent, setPreviewContent] = useState<string>('');
  const [lockedPayloads, setLockedPayloads] = useState<Record<string, string>>({});
  const [lockedPrompts, setLockedPrompts] = useState<Record<string, string>>({});

  const [stageSettings, setStageSettings] = useState<Record<string, StageSettings>>({
    spark: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
    falcon: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.5 },
    eagle: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.3 },
    owl: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.2 },
    hawk: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.4 }
  });

  const sync = async () => {
    try {
      const [startRes, sessionsRes, modelsRes] = await Promise.all([
        axios.get(`${ENGINE_URL}/fs/start`),
        axios.get(`${ENGINE_URL}/fs/sessions`), 
        axios.get(`${ENGINE_URL}/models`)
      ]);
      setStartFiles(startRes.data);
      setSessionFiles(sessionsRes.data); 
      setModels(modelsRes.data);
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
    await axios.post(`${ENGINE_URL}/fs/sessions`, { name: fileName, data: { inputs, outputs, telemetry, activePrompts, owlQueue, name: sessionName, id: sessionId } });
    sync();
  };

  const loadSession = async (f: string) => {
    const res = await axios.get(`${ENGINE_URL}/fs/sessions/${f}`);
    const s: SessionData = res.data;
    setInputs(s.inputs); setOutputs(s.outputs); setTelemetry(s.telemetry); setActivePrompts(s.activePrompts || {});
    setOwlQueue(s.owlQueue || []);
    const locked: any = {};
    STAGES.forEach(bird => { if(s.outputs[bird.id]) locked[bird.id] = s.outputs[bird.id]; });
    setLockedPayloads(locked);
    setSessionName(s.name || f.split('.')[1]); setSessionId(s.id); setArchiveOpen(false); audioService.playSuccess();
  };

  const executeStrike = async (stageId: PipelineStage) => {
    if (telemetry[stageId].status === 'loading') return;
    setTelemetry(prev => ({ ...prev, [stageId]: { status: 'loading' } }));
    try {
      const promptAsset = arsenal[stageId]?.find(p => p.name === activePrompts[stageId]);
      let finalPrompt = promptAsset ? promptAsset.content.replace('{input}', inputs[stageId]) : inputs[stageId];
      const res = await axios.post(`${ENGINE_URL}/strike`, { modelId: stageSettings[stageId].model, prompt: finalPrompt, temp: stageSettings[stageId].temperature });
      const output = res.data.content;
      setOutputs(prev => ({ ...prev, [stageId]: output }));
      setTelemetry(prev => ({ ...prev, [stageId]: { status: 'success' } }));
      const nextMap: any = { [PipelineStage.SPARK]: PipelineStage.FALCON, [PipelineStage.FALCON]: PipelineStage.EAGLE, [PipelineStage.EAGLE]: PipelineStage.OWL, [PipelineStage.OWL]: PipelineStage.HAWK };
      const nextStage = nextMap[stageId];
      if (nextStage) {
        setInputs(v => ({ ...v, [nextStage]: output }));
        setLockedPayloads(v => ({ ...v, [nextStage]: output }));
      }
      if (stageId === PipelineStage.EAGLE) {
        const fileRegex = /cat\s+<<\s*['"]?(PEACOCK_EOF)['"]?\s*>\s*(.*?)\n([\s\S]*?)PEACOCK_EOF/g;
        const matches = [...output.matchAll(fileRegex)];
        setOwlQueue(matches.map((m, i) => ({ id: `file-${i}`, path: m[2].trim(), skeleton: m[3], directives: "Implement per EAGLE contract.", status: 'pending' })));
      }
      setDossierOpen(true);
      saveSession();
    } catch (e) { setTelemetry(prev => ({ ...prev, [stageId]: { status: 'error' } })); }
  };

  const strikeOwlFile = async (file: OwlFile) => {
    setOwlQueue(q => q.map(f => f.id === file.id ? { ...f, status: 'pending' } : f));
    try {
      const p = arsenal[PipelineStage.OWL]?.find(p => p.name === activePrompts[PipelineStage.OWL]);
      const prompt = p ? p.content.replace('{skeleton}', file.skeleton).replace('{directives}', file.directives).replace('{path}', file.path) : file.skeleton;
      const res = await axios.post(`${ENGINE_URL}/strike`, { modelId: stageSettings.owl.model, prompt, temp: stageSettings.owl.temperature });
      setOwlQueue(q => q.map(f => f.id === file.id ? { ...f, status: 'completed', output: res.data.content } : f));
      saveSession();
      audioService.playSuccess();
    } catch (e) {}
  };

  const omegaOverwrite = () => {
    const completed = owlQueue.filter(f => f.status === 'completed');
    if (completed.length === 0) return;
    const script = ["#!/bin/bash", "# 💀 PEACOCK OMEGA OVERWRITE SCRIPT", ...completed.map(f => f.output)].join('\n\n');
    navigator.clipboard.writeText(script);
    audioService.playSuccess();
    alert("OMEGA PAYLOAD SECURED.");
  };

  const proceedToNext = () => {
    const nextMap: any = { [PipelineStage.SPARK]: PipelineStage.FALCON, [PipelineStage.FALCON]: PipelineStage.EAGLE, [PipelineStage.EAGLE]: PipelineStage.OWL, [PipelineStage.OWL]: PipelineStage.HAWK };
    if (nextMap[activeStageId]) setActiveStageId(nextMap[activeStageId]);
    setDossierOpen(false);
    audioService.playSuccess();
  };

  useEffect(() => {
    const move = (e: MouseEvent) => { if (isDraggingCli) setCliHeight(Math.max(40, window.innerHeight - e.clientY)); };
    const up = () => setIsDraggingCli(false);
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
    return () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up); };
  }, [isDraggingCli]);

  // --- UI COMPONENTS ---
  const MiniMap = () => (
    <div className="w-full flex flex-col items-center gap-2 py-2 bg-void border-b border-border relative overflow-hidden shrink-0">
      <h2 className="text-2xl font-black text-matrix mono italic tracking-[0.1em] uppercase drop-shadow-[0_0_10px_rgba(0,255,65,0.2)]">
        <DescrambleText text={sessionName} />
      </h2>
      <div className="relative w-[900px] h-10 flex justify-between items-center px-20">
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <defs><filter id="minimap-glow"><feGaussianBlur stdDeviation="2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
          <path d="M 150 20 H 325" stroke={outputs.spark ? THEME.voltage : '#1a1a1a'} strokeWidth="1.5" filter="url(#minimap-glow)" />
          <path d="M 325 20 H 500" stroke={outputs.falcon ? THEME.cyan : '#1a1a1a'} strokeWidth="1.5" filter="url(#minimap-glow)" />
          <path d="M 500 20 H 675" stroke={outputs.eagle ? THEME.purple : '#1a1a1a'} strokeWidth="1.5" filter="url(#minimap-glow)" />
          <path d="M 675 20 H 850" stroke={outputs.owl ? THEME.matrix : '#1a1a1a'} strokeWidth="1.5" filter="url(#minimap-glow)" />
        </svg>
        {STAGES.map((s) => {
          const done = !!outputs[s.id];
          const current = activeStageId === s.id;
          return (
            <div key={s.id} className="relative z-10 flex flex-col items-center gap-1" onClick={() => { setActiveStageId(s.id); setExpandedControl(null); }}>
              <div className={`w-8 h-8 rounded border flex items-center justify-center transition-all duration-700 cursor-pointer ${done ? 'bg-matrix border-white shadow-[0_0_15px_#00FF41]' : current ? 'border-voltage shadow-[0_0_10px_rgba(255,215,0,0.1)]' : 'border-border grayscale opacity-30'}`}>
                <img src={s.video.replace('.webm', '.png')} className={`w-5 h-5 object-contain ${done ? 'brightness-0' : ''}`} />
              </div>
              <span className={`text-[7px] font-black tracking-widest ${done ? 'text-matrix' : current ? 'text-voltage' : 'text-zinc-800'}`}>{s.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );

  const TacticalChamber = () => {
    const scrollRef = useRef<HTMLDivElement>(null);
    useEffect(() => { if (expandedControl || activeStageId) scrollRef.current?.scrollTo({ top: 0, behavior: 'smooth' }); }, [expandedControl, activeStageId]);
    const s = STAGES.find(stage => stage.id === activeStageId)!;
    const isCompleted = !!outputs[s.id];
    const isLoading = telemetry[s.id]?.status === 'loading';
    const isArmed = lockedPayloads[s.id] && lockedPrompts[s.id];

    return (
      <div ref={scrollRef} className="flex-1 flex flex-col items-center p-0 overflow-y-auto custom-scrollbar pb-40 scroll-smooth">
        <div className="w-full flex flex-col gap-12 pt-12 items-center">
          <AnimatePresence mode="wait">
            <motion.div key={s.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="w-full flex flex-col items-center">
              <div className="flex items-center justify-center gap-12 mt-4 w-full max-w-6xl relative z-20 h-40">
                <AnimatePresence>
                  {lockedPayloads[s.id] ? (
                    <motion.button 
                      initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
                      onClick={() => { setPreviewContent(lockedPayloads[s.id]); setDossierOpen(true); }}
                      className="w-56 h-14 bg-void/80 backdrop-blur-md border border-matrix/30 rounded-xl text-matrix font-black text-[10px] tracking-[0.3em] uppercase shadow-[0_10px_30px_rgba(0,0,0,0.5),inset_0_1px_1px_rgba(255,255,255,0.05)] hover:bg-matrix hover:text-void transition-all"
                    >
                      [ PAYLOAD_LOADED ]
                    </motion.button>
                  ) : <div className="w-56 h-14 border border-dashed border-border rounded-xl opacity-10" />}
                </AnimatePresence>
                <div className="w-32 h-32 relative flex items-center justify-center">
                  <div className={`absolute inset-0 rounded-full blur-[30px] opacity-10 transition-all duration-1000 ${isLoading ? 'bg-voltage scale-110' : isCompleted ? 'bg-matrix' : 'bg-white/5'}`} />
                  <StaggeredVideo src={s.video} active={true} done={isCompleted} />
                  <span className="absolute bottom-[-5px] z-20 text-[10px] font-black text-white italic tracking-[0.3em] uppercase opacity-40">{s.label}</span>
                </div>
                <AnimatePresence>
                  {lockedPrompts[s.id] ? (
                    <motion.button 
                      initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
                      onClick={() => { setPreviewContent(lockedPrompts[s.id]); setDossierOpen(true); }}
                      className="w-56 h-14 bg-void/80 backdrop-blur-md border border-matrix/30 rounded-xl text-matrix font-black text-[10px] tracking-[0.3em] uppercase shadow-[0_10px_30px_rgba(0,0,0,0.5),inset_0_1px_1px_rgba(255,255,255,0.05)] hover:bg-matrix hover:text-void transition-all"
                    >
                      [ PROMPT_ARMED ]
                    </motion.button>
                  ) : <div className="w-56 h-14 border border-dashed border-border rounded-xl opacity-10" />}
                </AnimatePresence>
              </div>

              <div className="flex flex-col items-center w-full mt-6 z-20 gap-6">
                <div className="relative group">
                  <div className="absolute -inset-[1px] bg-gradient-to-b from-matrix/20 to-transparent rounded-xl blur-sm opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                  <button 
                    onClick={() => { setLeftPanelTab('prompts'); setExpandedControl(expandedControl === 'hub' ? null : 'hub'); }}
                    className={`relative w-80 h-14 rounded-xl font-black text-[10px] uppercase tracking-[0.4em] transition-all duration-300 border border-white/5 shadow-[0_10px_30px_rgba(0,0,0,0.5),inset_0_1px_1px_rgba(255,255,255,0.02)] flex items-center justify-center gap-3 ${expandedControl === 'hub' ? 'bg-matrix text-void border-matrix shadow-[0_0_30px_rgba(0,255,65,0.2)]' : 'bg-void/80 backdrop-blur-md text-white/60 hover:text-matrix hover:border-matrix/30'}`}
                  >
                    <div className={`w-1 h-1 rounded-full animate-pulse ${expandedControl === 'hub' ? 'bg-void' : 'bg-matrix'}`} />
                    {s.id === PipelineStage.SPARK ? 'FILES' : 'PROMPTS'}
                  </button>
                </div>

                <AnimatePresence>
                  {expandedControl === 'hub' && (
                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="w-full max-w-7xl flex justify-between bg-surface border border-white/5 overflow-hidden shadow-[0_30px_60px_rgba(0,0,0,0.8)] z-30 min-h-[450px] rounded-2xl backdrop-blur-xl">
                      <div className="w-1/2 flex flex-col border-r border-white/5">
                        <div className="flex border-b border-white/5 bg-void/30">
                          <button onClick={() => setLeftPanelTab('data')} className={`flex-1 py-4 text-[10px] font-black tracking-[0.3em] uppercase transition-colors ${leftPanelTab === 'data' ? 'bg-matrix text-void' : 'text-muted hover:text-white'}`}>[ {s.id === PipelineStage.SPARK ? 'START_DIR' : 'SESSIONS'} ]</button>
                          <button onClick={() => setLeftPanelTab('prompts')} className={`flex-1 py-4 text-[10px] font-black tracking-[0.3em] uppercase transition-colors ${leftPanelTab === 'prompts' ? 'bg-matrix text-void' : 'text-muted hover:text-white'}`}>[ PROMPTS ]</button>
                        </div>
                        <div className="p-6 max-h-[450px] overflow-y-auto custom-scrollbar space-y-3">
                          {leftPanelTab === 'data' && (s.id === PipelineStage.SPARK ? startFiles : sessionFiles).map(f => (
                            <button key={f.name} onClick={() => axios.get(`${ENGINE_URL}/fs/${s.id === PipelineStage.SPARK ? 'start' : 'sessions'}/${f.name}`).then(r => setPreviewContent(s.id === PipelineStage.SPARK ? r.data.content : JSON.stringify(r.data, null, 2)))}" className="w-full text-left p-4 bg-void/40 border border-white/5 rounded-lg hover:border-matrix/40 transition-all group flex justify-between items-center shadow-inner"><span className="text-white/80 font-bold group-hover:text-matrix transition-colors text-xs">{f.name}</span><span className="text-[8px] text-muted font-black tracking-widest uppercase italic">Inspect</span></button>
                          ))}
                          {leftPanelTab === 'prompts' && arsenal[s.id]?.map(p => (
                            <button key={p.name} onClick={() => setPreviewContent(p.content)} className={`w-full text-left p-4 border rounded-lg transition-all text-xs font-bold shadow-inner ${previewContent === p.content ? 'bg-matrix/10 border-matrix/40 text-white' : 'bg-void/40 border-white/5 text-muted hover:text-white'}`}>{p.name.toUpperCase()}</button>
                          ))}
                        </div>
                      </div>
                      <div className="w-1/2 bg-void/20 flex flex-col h-[500px] relative">
                        {previewContent ? (
                          <>
                            <div className="px-6 py-3 bg-void/50 border-b border-white/5 text-[9px] font-black text-matrix tracking-widest uppercase italic">Data_Preview // Intelligence_Link</div>
                            <div className="flex-1 p-6 text-xs mono text-white/60 overflow-y-auto custom-scrollbar italic whitespace-pre-wrap leading-relaxed">{previewContent}</div>
                            <button onClick={() => { if (leftPanelTab === 'data') { if(s.id === PipelineStage.SPARK) setLockedPayloads(v => ({...v, [s.id]: previewContent})); else { const sData = JSON.parse(previewContent); setLockedPayloads(v => ({...v, [s.id]: JSON.stringify(sData.outputs, null, 2)})); } } else setLockedPrompts(v => ({...v, [s.id]: previewContent})); setExpandedControl(null); setPreviewContent(''); audioService.playSuccess(); }} className="w-full py-6 bg-matrix text-void font-black text-[11px] uppercase tracking-[0.4em] hover:bg-white transition-all shadow-[0_-10px_30px_rgba(0,255,65,0.1)]">[ ACCEPT & LOCK IN ]</button>
                          </>
                        ) : <div className="flex-1 flex items-center justify-center text-[9px] text-muted font-bold uppercase tracking-[0.3em] italic opacity-20">Awaiting_Mission_Intelligence...</div>}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                <div className="flex items-center gap-10 w-full max-w-4xl justify-center mt-2 pb-16">
                  <div className="w-80 p-6 bg-void/80 backdrop-blur-md border border-white/5 rounded-2xl shadow-[0_10px_30px_rgba(0,0,0,0.5),inset_0_1px_1px_rgba(255,255,255,0.02)]">
                    <CustomDropdown 
                      label="Node_Selection // Artillery_Link" 
                      value={stageSettings[s.id].model} 
                      options={models} 
                      onChange={(v) => setStageSettings(prev => ({ ...prev, [s.id]: { ...prev[s.id], model: v } }))} 
                    />
                  </div>
                  <div className={`relative w-[400px] h-24 p-[1px] rounded-2xl transition-all duration-1000 ${isLoading ? 'bg-matrix shadow-[0_0_30px_#00FF41]' : 'bg-white/5'} ${!isArmed && 'opacity-20'}`}>
                    <button 
                      disabled={!isArmed || isLoading} 
                      onClick={() => executeStrike(s.id)}
                      className={`w-full h-full bg-void rounded-2xl font-black text-xl uppercase tracking-[0.6em] transition-all flex flex-col items-center justify-center gap-1 border border-white/5 shadow-[inset_0_1px_1px_rgba(255,255,255,0.05)] ${isArmed ? 'text-matrix hover:bg-matrix hover:text-void' : 'text-white/20'}`}
                    >
                      {isLoading ? <DescrambleText text="CONDUCTING_STRIKE" /> : `EXECUTE_${s.label}_DRIVE`}
                      {isLoading && <div className="w-48 h-0.5 bg-matrix/20 rounded-full mt-1 overflow-hidden"><div className="h-full bg-matrix w-full animate-[shimmer_1s_infinite]" /></div>}
                    </button>
                  </div>
                </div>
              </div>

              {isCompleted && (
                <div className="grid grid-cols-2 gap-8 w-[90%] max-w-6xl mt-4">
                  <div className="bg-surface/40 backdrop-blur-md border border-white/5 rounded-2xl overflow-hidden flex flex-col shadow-2xl">
                    <div className="px-6 py-3 bg-void/50 border-b border-white/5 text-[9px] font-bold text-muted uppercase tracking-widest italic">Instruction_Set</div>
                    <div className="flex-1 p-6 text-xs mono text-white/40 h-40 overflow-y-auto custom-scrollbar italic whitespace-pre-wrap leading-relaxed">{inputs[s.id]}</div>
                  </div>
                  <div className="bg-surface/40 backdrop-blur-md border border-matrix/20 rounded-2xl overflow-hidden flex flex-col shadow-2xl">
                    <div className="px-6 py-3 bg-void/50 border-b border-white/5 text-matrix font-bold text-[10px] uppercase tracking-widest italic">Extracted_Intel</div>
                    <div className="flex-1 p-6 text-xs mono text-matrix/60 h-40 overflow-y-auto custom-scrollbar whitespace-pre-wrap leading-relaxed">{outputs[s.id]}</div>
                  </div>
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    );
  };

  return (
    <div className="h-screen bg-void text-text font-inter flex flex-col relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none z-[100] opacity-[0.03] bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_3px,3px_100%]" />
      <header className="px-8 h-20 flex justify-between items-center border-b border-white/5 bg-void z-[60] shrink-0 shadow-2xl">
        <div className="flex items-center gap-6"><div className="w-12 h-12 bg-matrix flex items-center justify-center text-void font-black text-2xl rounded-xl shadow-[0_0_20px_rgba(0,255,65,0.2)]">P</div><div><h1 className="text-3xl font-black text-white italic tracking-tighter">PEACOCK<span className="text-matrix">_V26.2</span></h1><p className="text-[8px] font-bold text-muted uppercase italic tracking-[0.4em] mt-1">Anti-Vibe Coding App // Orbital_Strike</p></div></div>
        <div className="flex gap-4"><button onClick={() => setArchiveOpen(true)} className="px-8 py-2.5 border border-white/5 text-[10px] font-black uppercase hover:border-matrix hover:text-white transition-all bg-void/50 rounded-lg shadow-xl">Archive</button><button onClick={() => window.location.reload()} className="px-8 py-2.5 bg-matrix/10 text-matrix border border-matrix/20 text-[10px] font-black uppercase tracking-widest rounded-lg shadow-xl hover:bg-matrix hover:text-void transition-all">Re-Boot</button></div>
      </header>
      <main className="flex-1 flex flex-col min-h-0 bg-[#0B0D10] relative"><MiniMap /><TacticalChamber /></main>
      <VerbatimCLI height={cliHeight} onMouseDown={() => setIsDraggingCli(true)} />
      <AnimatePresence>{archiveOpen && (<div className="fixed inset-0 z-[300] flex items-center justify-center p-20 bg-void/98 backdrop-blur-3xl"><div className="w-full max-w-7xl h-full flex flex-col gap-10"><div className="flex justify-between items-center border-b border-white/5 pb-8"><div><span className="text-[12px] font-black text-matrix tracking-[0.5em] uppercase italic">Mission_Logs</span><h3 className="text-5xl font-black text-white italic uppercase tracking-tighter mt-2">Operational_Archive</h3></div><button onClick={() => setArchiveOpen(false)} className="text-zinc-500 hover:text-white text-6xl">✕</button></div><div className="flex-1 overflow-y-auto custom-scrollbar grid grid-cols-3 gap-8 pr-10">{sessionFiles.map(f => (<button key={f.name} onClick={() => loadSession(f.name)} className="group text-left p-10 bg-surface/40 backdrop-blur-md border border-white/5 rounded-2xl hover:border-matrix transition-all shadow-2xl flex flex-col gap-6 relative overflow-hidden shadow-inner"><div className="absolute top-0 right-0 w-24 h-24 bg-matrix/5 blur-3xl" /><span className="text-muted text-[10px] font-black uppercase tracking-widest">Modified: {new Date(f.modified).toLocaleDateString()}</span><h4 className="text-2xl font-black text-white/40 group-hover:text-matrix transition-colors uppercase italic tracking-tighter">{f.name.split('.')[1]}</h4><div className="mt-auto pt-6 border-t border-white/5 flex justify-between items-center"><span className="text-[9px] font-bold text-zinc-700 uppercase italic">REHYDRATION_READY</span><span className="text-matrix group-hover:translate-x-2 transition-all">▶▶</span></div></button>))}</div></div></div>)}</AnimatePresence>
      <AnimatePresence>{dossierOpen && (<div className="fixed inset-0 z-[200] flex items-center justify-center p-12 bg-black/95 backdrop-blur-3xl"><motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="w-full max-w-7xl h-[85vh] bg-surface border border-white/5 rounded-[3rem] p-12 flex flex-col gap-6 shadow-2xl relative overflow-hidden shadow-inner"><h2 className="text-2xl font-black text-white italic uppercase tracking-widest border-b border-white/5 pb-6">MISSION_SYNC_COMPLETE</h2><div className="flex-1 grid grid-cols-2 gap-8 min-h-0"><div className="bg-void/50 border border-white/5 rounded-2xl overflow-hidden flex flex-col"><div className="px-8 py-3 bg-void border-b border-white/5 text-muted font-black text-[10px] uppercase tracking-widest italic">Instruction_Set</div><div className="flex-1 p-8 text-xs mono text-white/40 overflow-y-auto custom-scrollbar italic whitespace-pre-wrap leading-relaxed">{inputs[activeStageId]}</div></div><div className="bg-void/50 border border-matrix/20 rounded-2xl overflow-hidden flex flex-col"><div className="px-8 py-3 bg-void border-b border-white/5 text-matrix font-black text-[10px] uppercase tracking-widest italic">Extracted_Intel</div><div className="flex-1 p-8 text-xs mono text-matrix/60 overflow-y-auto custom-scrollbar whitespace-pre-wrap leading-relaxed">{outputs[activeStageId]}</div></div></div><button onClick={proceedToNext} className="w-full py-6 bg-matrix text-void font-black uppercase text-xs tracking-[0.5em] rounded-xl hover:bg-white transition-all shadow-[0_15px_40px_rgba(0,255,65,0.2)]">PROCEED TO NEXT DRIVE ▶▶</button></motion.div></div>)}</AnimatePresence>
      <style>{`
        @keyframes shimmer { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }
        body { font-family: 'Inter', sans-serif; background: #0D0F12; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .custom-scrollbar::-webkit-scrollbar { width: 4px; height: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #252930; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #00FF41; }
        ::selection { background: #00FF41; color: #000; }
      `}</style>
    </div>
  );
};

export default App;