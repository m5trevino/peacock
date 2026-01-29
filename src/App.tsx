import React, { useState, useEffect } from 'react';
import { PipelineStage, CallTelemetry, StageSettings, CasinoSettings, PromptAsset, OwlFile } from './types.ts';
import { useModelRegistry } from './hooks/useModelRegistry.ts';
import { api } from './services/api.ts';
import { audioService } from './services/audioService.ts';
import { parseEagleResponse, cleanStrikeContent, extractProjectName } from './utils/engineUtils.ts';
import { PROTOCOLS } from './config/protocols.ts';
import { db } from './services/db.ts';

// Components
import { OwlHangar } from './components/views/OwlHangar.tsx';
import { SettingsDeck } from './components/views/SettingsDeck.tsx';
import { TacticalModelPicker } from './components/ui/TacticalModelPicker.tsx';

// UI
import { EditorOverlay } from './components/ui/EditorOverlay.tsx';
import { IntelHub } from './components/layout/IntelHub.tsx';
import { SessionManager } from './components/views/SessionManager.tsx';
import { MiniMap } from './components/ui/MiniMap.tsx';
import { MatrixText } from './components/ui/MatrixText.tsx';
import { BackgroundTerminal } from './components/ui/BackgroundTerminal.tsx';

// --- CONFIG ---
const STAGE_CONFIG = {
    [PipelineStage.SPARK]: { color: '#FFD700', icon: '⚡', label: 'SPARK' },
    [PipelineStage.FALCON]: { color: '#00FFFF', icon: '🦅', label: 'FALCON' },
    [PipelineStage.EAGLE]: { color: '#FF00FF', icon: '🦅', label: 'EAGLE' },
    [PipelineStage.OWL]: { color: '#9D00FF', icon: '🦉', label: 'OWL' },
    [PipelineStage.HAWK]: { color: '#00FF41', icon: '🦅', label: 'HAWK' },
};

function App() {
    // --- STATE ---
    const { models } = useModelRegistry();
    const [activeStageId, setActiveStageId] = useState<PipelineStage>(PipelineStage.SPARK);
    const [pendingStageId, setPendingStageId] = useState<PipelineStage | null>(null);
    const [settingsOpen, setSettingsOpen] = useState(false);
    const [pickerOpen, setPickerOpen] = useState(false);
    const [casinoSettings, setCasinoSettings] = useState<CasinoSettings>({ enabled: true, audio: true, volume: 0.5 });

    // Core Data
    const [inputs, setInputs] = useState<Record<string, string>>({});
    const [outputs, setOutputs] = useState<Record<string, string>>({});
    const [telemetry, setTelemetry] = useState<Record<string, CallTelemetry>>({
        spark: { status: 'idle' }, falcon: { status: 'idle' }, eagle: { status: 'idle' }, owl: { status: 'idle' }, hawk: { status: 'idle' }
    });
    const [lastCallTime, setLastCallTime] = useState<number>(Date.now());
    const [strikeTimer, setStrikeTimer] = useState<string>('00:00');

    // DEFAULT TO MOONSHOT KIMI K2 (0905)
    const [stageSettings, setStageSettings] = useState<Record<string, StageSettings>>({
        spark: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        falcon: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        eagle: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        owl: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        hawk: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
    });

    // Vitals Logic
    const [proxyIP, setProxyIP] = useState('127.0.0.1');

    // Modals & Panels
    const [editorOpen, setEditorOpen] = useState(false);
    const [editorType, setEditorType] = useState<'input' | 'prompt'>('input');
    const [hubOpen, setHubOpen] = useState(false);
    const [hubTab, setHubTab] = useState<'DATA' | 'PROMPTS'>('DATA');
    const [sessionOpen, setSessionOpen] = useState(false);
    const [currentSessionId, setCurrentSessionId] = useState<number | null>(null);
    const [showFlare, setShowFlare] = useState(false);
    const [isConsoleExpanded, setConsoleExpanded] = useState(false);
    const [manifestContent, setManifestContent] = useState<string>('');
    const [manifestOpen, setManifestOpen] = useState(false);
    const [lastRawOwl, setLastRawOwl] = useState<string>('');

    // Assets
    const [startFiles, setStartFiles] = useState<string[]>([]);
    const [activePrompts, setActivePrompts] = useState<Record<string, string>>({});
    const [arsenal, setArsenal] = useState<Record<string, PromptAsset[]>>({});

    // Owl
    const [owlQueue, setOwlQueue] = useState<OwlFile[]>([]);
    const [rawResponses, setRawResponses] = useState<Record<string, any>>({});

    // Telemetry Ghost Stream
    const [telemetryLogs, setTelemetryLogs] = useState<{ id: string, text: string, timestamp: number }[]>([]);
    const [terminalFocused, setTerminalFocused] = useState(false);

    const addLog = (text: string) => {
        setTelemetryLogs(prev => {
            const newLogs = [...prev, { id: crypto.randomUUID(), text: `[${new Date().toLocaleTimeString()}] ${text}`, timestamp: Date.now() }];
            return newLogs.slice(-1000);
        });
    };

    // --- EFFECTS ---
    useEffect(() => {
        if (casinoSettings.enabled && casinoSettings.audio) audioService.startHum();
        else audioService.stopHum();
        return () => audioService.stopHum();
    }, [casinoSettings.enabled, casinoSettings.audio]);

    useEffect(() => {
        const timer = setInterval(() => {
            const diff = Math.floor((Date.now() - lastCallTime) / 1000);
            const m = Math.floor(diff / 60).toString().padStart(2, '0');
            const s = (diff % 60).toString().padStart(2, '0');
            setStrikeTimer(`${m}:${s}`);
        }, 1000);
        return () => clearInterval(timer);
    }, [lastCallTime]);

    useEffect(() => {
        const interval = setInterval(() => {
            setProxyIP(`192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`);
        }, 5000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        const loadAssets = async () => {
            const files = await api.fetchStartFiles();
            setStartFiles(files);
            const stages = Object.keys(STAGE_CONFIG);
            const newArsenal: Record<string, PromptAsset[]> = {};
            const newActivePrompts: Record<string, string> = {};

            await Promise.all(stages.map(async (stage) => {
                const prompts = await api.fetchPrompts(stage);
                if (prompts && prompts.length > 0) {
                    newArsenal[stage] = prompts;
                    newActivePrompts[stage] = prompts[0].name;
                } else {
                    const fallbackContent = PROTOCOLS[stage as keyof typeof PROTOCOLS] || '';
                    newArsenal[stage] = [{ id: `${stage}_default`, name: 'DEFAULT', content: fallbackContent }];
                    newActivePrompts[stage] = 'DEFAULT';
                }
            }));
            setArsenal(newArsenal);
            setActivePrompts(newActivePrompts);
            addLog(`[SYS] :: GHOST_STREAM_ONLINE... PROMPT_ARSENAL_LOADED`);
        };
        loadAssets();
    }, []);

    useEffect(() => {
        const autoSave = async () => {
            if (Object.keys(inputs).length === 0 && !currentSessionId) return;

            const snapshot = {
                inputs, outputs, telemetry, activePrompts, owlQueue, activeStageId, pendingStageId
            };

            const sessionData = {
                name: inputs[PipelineStage.SPARK]?.split('\n')[0]?.substring(0, 30) || 'Active Operation',
                timestamp: Date.now(),
                lastUpdated: Date.now(),
                data: JSON.stringify(snapshot)
            };

            if (currentSessionId) {
                await db.sessions.update(currentSessionId, sessionData);
            } else {
                const id = await db.sessions.add(sessionData);
                setCurrentSessionId(id as number);
            }
        };

        const timeoutId = setTimeout(autoSave, 2000);
        return () => clearTimeout(timeoutId);
    }, [inputs, outputs, telemetry, activePrompts, owlQueue, activeStageId, pendingStageId, currentSessionId]);

    // --- HANDLERS ---
    const triggerHardwareShift = () => {
        setShowFlare(true);
        if (casinoSettings.audio) audioService.playBriefcaseAhhh();
        setTimeout(() => setShowFlare(false), 200);
    };

    const handleNewSession = () => {
        setCurrentSessionId(null);
        setInputs({}); setOutputs({}); setOwlQueue([]); setPendingStageId(null);
    };

    const handleLoadSession = (session: any) => {
        const data = JSON.parse(session.data);
        setInputs(data.inputs || {}); setOutputs(data.outputs || {});
        setTelemetry(data.telemetry || {}); setOwlQueue(data.owlQueue || []);
        setActivePrompts(data.activePrompts || {});
        setCurrentSessionId(session.id!);
        if (data.activeStageId) setActiveStageId(data.activeStageId);
        if (data.pendingStageId) setPendingStageId(data.pendingStageId);
    };

    const handleStrike = async () => {
        const payload = inputs[activeStageId];
        const settings = stageSettings[activeStageId];
        const activePromptName = activePrompts[activeStageId];
        const systemPrompt = arsenal[activeStageId]?.find(p => p.name === activePromptName)?.content || '';

        if (!payload || !settings.model) return;

        if (casinoSettings.audio) audioService.playBriefcaseAhhh();
        setShowFlare(true);
        setTimeout(() => setShowFlare(false), 150);
        setLastCallTime(Date.now());

        addLog(`[API] :: SHUFFLING_MODEL_DECK... SELECTING_DEALER: "${settings.model.split('/').pop()?.toUpperCase()}"`);

        const fullPrompt = systemPrompt ? `${systemPrompt}\n\n${payload}` : payload;
        setTelemetry(prev => ({ ...prev, [activeStageId]: { status: 'loading' } }));

        try {
            const startTime = Date.now();
            const isEagle = activeStageId === PipelineStage.EAGLE;

            const result = await api.executeStrike({
                modelId: settings.model, prompt: fullPrompt, temp: settings.temperature,
                format_mode: isEagle ? 'eagle_scaffold' : undefined
            });

            const latency = Date.now() - startTime;
            setRawResponses(prev => ({ ...prev, [activeStageId]: result.content }));

            let finalResponse = typeof result.content === 'object' ? JSON.stringify(result.content, null, 2) : String(result.content);

            triggerHardwareShift();

            if (isEagle) {
                const newQueue = parseEagleResponse(result.content);
                if (newQueue.length) {
                    setOwlQueue(newQueue);
                    setPendingStageId(PipelineStage.OWL);
                    finalResponse = `EAGLE_SCAFFOLD_RECEIVED // ${newQueue.length} FILES QUEUED`;
                }
            } else {
                const stages = Object.values(PipelineStage);
                const nextStageIndex = stages.indexOf(activeStageId) + 1;
                const nextStage = stages[nextStageIndex];
                if (nextStage) {
                    setInputs(prev => ({ ...prev, [nextStage]: finalResponse }));
                    setPendingStageId(nextStage as PipelineStage);
                }
            }

            setConsoleExpanded(false);
            if (casinoSettings.audio) audioService.playSurgeArc();

            setOutputs(prev => ({ ...prev, [activeStageId]: finalResponse }));
            setTelemetry(prev => ({ ...prev, [activeStageId]: { status: 'success', latency, exitIP: result.ipUsed, key: result.keyUsed } }));
        } catch (error) {
            setTelemetry(prev => ({ ...prev, [activeStageId]: { status: 'error' } }));
            if (casinoSettings.audio) audioService.playError();
        }
    };

    const handleOwlStrike = async (fileId: string) => {
        const file = owlQueue.find(f => f.id === fileId);
        if (!file || !stageSettings.owl.model) return;

        setOwlQueue(prev => prev.map(f => f.id === fileId ? { ...f, status: 'loading' } : f));
        setLastCallTime(Date.now());

        const fileIndex = owlQueue.findIndex(f => f.id === fileId);
        if (casinoSettings.audio) audioService.playSymphony(fileIndex);

        try {
            const result = await api.executeStrike({
                modelId: stageSettings.owl.model,
                prompt: `ACT AS OWL. FLESH OUT THIS SKELETON PER THE DIRECTIVES.
                
                STRICT_RULES:
                1. YOUR OUTPUT MUST BE VALID JSON MATCHING THE SCHEMA.
                2. THE 'code' PROPERTY MUST CONTAIN PURE SOURCE CODE ONLY.
                3. NO GREETINGS, NO EXPLANTIONS, NO HOOTING, NO MARKDOWN FENCES INSIDE THE JSON.
                4. ZERO CONVERSATIONAL FILLER. SILENCE IS MANDATORY.

                FILE_PATH: ${file.path}
                DIRECTIVES: ${file.directives}
                SKELETON_CODE:
                ${file.skeleton}`,
                temp: stageSettings.owl.temperature,
                response_format: {
                    type: "json_schema",
                    json_schema: {
                        name: "owl_flesh_out",
                        schema: {
                            type: "object",
                            properties: {
                                path: { type: "string" },
                                code: { type: "string" }
                            },
                            required: ["path", "code"],
                            additionalProperties: false
                        },
                        strict: false
                    }
                }
            });

            triggerHardwareShift();
            addLog(`[OWL] :: SLOT_${fileId.substring(0, 4)}... WRITING_${file.path.split('/').pop()?.toUpperCase()}...`);

            let finalCode = "";
            try {
                const parsed = JSON.parse(result.content);
                finalCode = parsed.code || parsed.content || result.content;
            } catch (e) {
                finalCode = cleanStrikeContent(result.content);
                addLog(`[SYS] :: OWL_JSON_PARSE_FAILED... FALLING_BACK_TO_CLEAN_STREAM`);
            }

            setLastRawOwl(finalCode);
            setOwlQueue(prev => prev.map(f => f.id === fileId ? {
                ...f, status: 'completed', output: finalCode
            } : f));

            setTelemetry(prev => ({ ...prev, owl: { status: 'success', exitIP: result.ipUsed, key: result.keyUsed } }));
        } catch (error) {
            setOwlQueue(prev => prev.map(f => f.id === fileId ? { ...f, status: 'error' } : f));
            if (casinoSettings.audio) audioService.playError();
        }
    };

    const handleGenerateManifest = () => {
        const completedFiles = owlQueue.filter(f => f.status === 'completed');
        if (completedFiles.length === 0) return;

        const projectName = extractProjectName(inputs[PipelineStage.SPARK] || "");

        let script = "#!/bin/bash\n\n";
        script += "# PEACOCK_V26_ORCHESTRA_DEPLOYMENT_MANIFEST_V5\n";
        script += `# Project: ${projectName}\n`;
        script += `# Generated: ${new Date().toLocaleString()}\n\n`;

        script += `echo "INITIATING_MISSION: ${projectName}"\n`;
        script += `mkdir -p ${projectName} && cd ${projectName} && chmod 755 .\n\n`;

        completedFiles.forEach(file => {
            if (!file.output) return;
            const dir = file.path.includes('/') ? file.path.split('/').slice(0, -1).join('/') : '';

            if (dir) script += `mkdir -p ${dir} && chmod 755 ${dir}\n`;
            script += `cat << 'PEACOCK_DEPLOY_BLOCK' > ${file.path}\n`;
            script += file.output;
            script += "\nPEACOCK_DEPLOY_BLOCK\n";
            script += `chmod 644 ${file.path}\n\n`;
        });

        script += `echo "DEVELOPMENT_ASSETS_DEPLOYED_TO: ${projectName}"\n`;
        script += "echo \"DEPLOYMENT_COMPLETE // ENJOY_THE_VIBE\"\n";
        setManifestContent(script);
        setManifestOpen(true);
        if (casinoSettings.audio) audioService.playSymphony(7);
    };

    const handleWipeStage = () => {
        if (!confirm("AUTHORIZATION REQUIRED: PURGE STAGE TELEMETRY?")) return;
        setOutputs(prev => {
            const n = { ...prev };
            delete n[activeStageId];
            return n;
        });
        setTelemetry(prev => ({ ...prev, [activeStageId]: { status: 'idle' } }));
        setPendingStageId(null);
        if (activeStageId === PipelineStage.EAGLE) setOwlQueue([]);
        if (casinoSettings.audio) audioService.playError();
    };

    // --- SMART RAILS LOGIC ---
    const showLeftRail = owlQueue.length > 0;
    const showRightRail = outputs[activeStageId] && outputs[activeStageId] !== "AWAITING_MISSION_TELEMETRY...";

    // --- CLEAR-SPEAK TERMINOLOGY ---
    const getInformativeStatus = () => {
        if (telemetry[activeStageId].status === 'loading') return 'EXECUTING_STRIKE_API_UPLINK...';
        if (telemetry[activeStageId].status === 'success') return `MISSION_COMPLETE // READY_FOR_${pendingStageId?.toUpperCase()}_SURGE`;

        switch (activeStageId) {
            case PipelineStage.SPARK: return 'MISSION_SETUP: RAW_INPUT -> ARCHITECTURE_SPEC';
            case PipelineStage.FALCON: return 'TECHNICAL_ARCHITECTURE_REFINEMENT_PHASE';
            case PipelineStage.EAGLE: return 'SKELETON_GENERATION_&_DIRECTIVE_ROUTING';
            case PipelineStage.OWL: return 'ORCHESTRA_FLESH-OUT_&_CODE_DELIVERY';
            case PipelineStage.HAWK: return 'STRATEGIC_QA_&_VALIDATION_STRIKE';
            default: return 'ACTIVE_MISSION_READY';
        }
    };

    return (
        <div className="h-screen w-screen flex flex-col p-1 bg-void overflow-hidden relative font-mono text-white selection:bg-voltage selection:text-void uppercase tracking-widest">
            <div className="crt-overlay" />
            {showFlare && <div className="strike-flare" />}

            {/* HUD VITALS */}
            <div className="flex justify-between items-center px-10 py-5 border-b border-white/10 bg-void/98 tactical-glass mb-1 shrink-0 z-50">
                <div className="flex gap-24 font-black">
                    <div className="flex flex-col">
                        <span className="text-[10px] text-white/40 tracking-[0.6em] mb-2">Proxy_Tunnel_Active</span>
                        <span className="text-xl text-matrix shadow-matrix-glow font-mono tracking-tighter"><MatrixText text={proxyIP} /></span>
                    </div>
                    <div className="flex flex-col border-l border-white/10 pl-6">
                        <span className="text-[10px] text-white/40 tracking-[0.6em] mb-2">Armed_Intelligence_Unit</span>
                        <button
                            onClick={() => { setPickerOpen(true); if (casinoSettings.audio) audioService.playFlyoutSnap(); }}
                            className="text-[14px] text-voltage shadow-voltage-glow font-mono bg-voltage/5 px-4 py-2 border border-voltage/40 rounded-sm hover:bg-voltage/20 transition-all uppercase tracking-[0.2em] relative group"
                        >
                            {stageSettings[activeStageId].model.split('/').pop()}
                            <span className="absolute -right-2 -top-2 w-5 h-5 bg-void border border-voltage/60 rounded-full flex items-center justify-center text-[11px] text-voltage group-hover:scale-125 transition-transform font-black">?</span>
                        </button>
                    </div>
                </div>
                <div className="flex items-center gap-10">
                    <div className="text-right">
                        <p className="text-[11px] text-white/30 tracking-[0.8em] font-black mb-2">Peacock_V26.5_Tactical_Core</p>
                        <div className="flex gap-3 justify-end items-center">
                            {Object.values(PipelineStage).map(s => (
                                <div key={s} className={`w-12 h-3.5 rounded-none transition-all duration-300 ${telemetry[s].status === 'success' ? 'bg-matrix shadow-[0_0_20px_var(--matrix-glow)]' : s === activeStageId ? 'bg-voltage animate-pulse shadow-[0_0_25px_var(--voltage-glow)] scale-y-125 translate-y-[-1px]' : 'bg-white/5 border border-white/10'}`} />
                            ))}
                        </div>
                    </div>
                    <button onClick={() => setSettingsOpen(true)} className="w-14 h-14 border border-white/20 bg-white/5 flex items-center justify-center hover:bg-white/10 transition-all text-2xl rounded-sm shadow-2xl group"><span className="group-hover:rotate-90 transition-transform duration-500">⚙</span></button>
                </div>
            </div>

            {/* CONTENT AREA */}
            <div className="flex-1 relative overflow-hidden flex flex-col items-center justify-center bg-black/60">
                {!isConsoleExpanded ? (
                    <div className="w-full h-full flex items-center justify-center">
                        <MiniMap
                            telemetry={telemetry}
                            activeStageId={activeStageId}
                            pendingStageId={pendingStageId}
                            setActiveStageId={(id) => {
                                setActiveStageId(id);
                                setPendingStageId(null);
                                setConsoleExpanded(true);
                                if (casinoSettings.audio) audioService.playSymphony(0);
                            }}
                        />
                    </div>
                ) : (
                    <div className="absolute inset-0 z-20 flex flex-col p-6 animate-in fade-in slide-in-from-bottom-20 duration-700 bg-void/95">
                        <div className="absolute inset-0 cursor-zoom-out" onClick={() => setConsoleExpanded(false)} />

                        <div className="relative z-30 flex-1 flex gap-6 overflow-hidden pointer-events-auto">
                            {showLeftRail && (
                                <div className="w-[480px] flex flex-col border border-white/20 bg-void/98 tactical-glass p-8 shrink-0 shadow-2xl overflow-hidden">
                                    <div className="flex justify-between items-center mb-10 px-1 border-b border-white/10 pb-6 uppercase italic tracking-[0.8em] font-black shrink-0">
                                        <span className="text-white/40 text-[14px]">Orchestra_Drive</span>
                                        <span className="text-matrix shadow-matrix-glow text-[14px]">{owlQueue.length}</span>
                                    </div>
                                    <div className="flex-1 overflow-y-auto custom-scrollbar-voltage pr-2">
                                        <OwlHangar
                                            queue={owlQueue}
                                            executeStrike={handleOwlStrike}
                                            stageSettings={stageSettings}
                                            onInspect={(id) => {
                                                const f = owlQueue.find(x => x.id === id);
                                                if (f && f.output) {
                                                    setEditorType('input');
                                                    setInputs(prev => ({ ...prev, owl_inspect: f.output || '' }));
                                                    setEditorOpen(true);
                                                }
                                            }}
                                            onRewrite={(id) => handleOwlStrike(id)}
                                            onCopyEOF={(id) => {
                                                const f = owlQueue.find(x => x.id === id);
                                                if (f && f.output) {
                                                    const dir = f.path.includes('/') ? f.path.split('/').slice(0, -1).join('/') : '';
                                                    const fileName = f.path.split('/').pop();
                                                    let cmd = `echo "AUTONOMOUS_DEPLOY_START: ${fileName}"\n`;
                                                    if (dir) cmd += `mkdir -p ${dir} && chmod 755 ${dir} && `;
                                                    cmd += `cat << 'PEACOCK_DEPLOY_BLOCK' > ${f.path}\n${f.output}\nPEACOCK_DEPLOY_BLOCK\nchmod 644 ${f.path}\necho "DEPLOY_SUCCESS: ${f.path}"`;
                                                    navigator.clipboard.writeText(cmd);
                                                    addLog(`[UI] :: EOF_PROTOCOL_COPIED_TO_CLIPBOARD: ${fileName}`);
                                                }
                                            }}
                                            onGenerateManifest={handleGenerateManifest}
                                            rawEagleResponse={rawResponses[PipelineStage.EAGLE]}
                                            audioEnabled={casinoSettings.audio}
                                        />
                                    </div>
                                </div>
                            )}

                            <div className="flex-1 flex flex-col gap-6 min-w-0 h-full">
                                <div className="flex gap-6 h-[55%] shrink-0">
                                    <div className="flex-1 border border-white/20 bg-black/98 p-10 flex flex-col group hover:border-voltage/50 transition-all shadow-2xl overflow-hidden">
                                        <div className="flex justify-between items-center mb-8">
                                            <span className="text-[12px] text-white/40 tracking-[1em] font-black">Mission_Payload</span>
                                            <button onClick={() => { setHubTab('DATA'); setHubOpen(true); }} className="px-6 py-2 bg-voltage text-void text-[12px] font-black tracking-widest hover:brightness-125">SLOT_DNA</button>
                                        </div>
                                        <textarea
                                            className="flex-1 bg-transparent text-[18px] text-white/90 font-mono focus:outline-none resize-none custom-scrollbar leading-relaxed"
                                            value={inputs[activeStageId] || ''}
                                            onChange={(e) => setInputs(prev => ({ ...prev, [activeStageId]: e.target.value }))}
                                            placeholder="AWAITING_CORE_INPUT..."
                                        />
                                    </div>
                                    <div className="flex-1 border border-white/20 bg-black/98 p-10 flex flex-col group hover:border-voltage/50 transition-all shadow-2xl overflow-hidden">
                                        <div className="flex justify-between items-center mb-8">
                                            <span className="text-[12px] text-white/40 tracking-[1em] font-black">Stage_Strategy</span>
                                            <button onClick={() => { setHubTab('PROMPTS'); setHubOpen(true); }} className="px-6 py-2 bg-voltage text-void text-[12px] font-black tracking-widest hover:brightness-125">ARM_STRATEGY</button>
                                        </div>
                                        <div className="flex-1 overflow-auto custom-scrollbar italic text-white/60 font-mono leading-relaxed">
                                            {arsenal[activeStageId]?.find(p => p.name === activePrompts[activeStageId])?.content || 'STRIKE_CORE_READY...'}
                                        </div>
                                    </div>
                                </div>

                                <div className="flex-1 bg-black/80 border border-white/30 flex flex-col items-center justify-center p-20 shadow-inner relative">
                                    <div className="text-3xl font-mono font-black text-matrix shadow-matrix-glow mb-12 uppercase">
                                        <MatrixText text={getInformativeStatus()} />
                                    </div>

                                    <button
                                        onClick={handleStrike}
                                        disabled={!inputs[activeStageId] || telemetry[activeStageId].status === 'loading'}
                                        className={`w-[600px] h-40 bg-void border-2 border-voltage/40 flex flex-col items-center justify-center relative briefcase-glow hover:border-voltage transition-all ${!inputs[activeStageId] ? 'opacity-20' : ''}`}
                                    >
                                        <span className="text-2xl font-black text-white tracking-[0.5em]">EXECUTE_STRIKE</span>
                                        <span className="text-[10px] text-voltage shadow-voltage-glow tracking-[0.3em] font-black mt-4">INITIATE_{activeStageId.toUpperCase()}_UPLINK</span>
                                        <div className="absolute inset-x-0 top-0 h-1 bg-voltage animate-pulse shadow-voltage-glow" />
                                    </button>

                                    {telemetry[activeStageId].status !== 'idle' && (
                                        <button onClick={handleWipeStage} className="mt-8 text-[10px] text-error hover:underline tracking-widest">WIPE_PHASE_TELEMETRY</button>
                                    )}
                                </div>
                            </div>

                            {showRightRail && (
                                <div className="w-[480px] border border-white/30 bg-void/98 tactical-glass flex flex-col p-10 shrink-0 shadow-2xl overflow-hidden">
                                    <span className="text-[18px] text-voltage shadow-voltage-glow uppercase tracking-[1.8em] font-black mb-12 italic border-b border-white/20 pb-8">
                                        {activeStageId === PipelineStage.OWL ? 'RAW_FILE_OUTPUT' : 'Mission_Telemetry'}
                                    </span>
                                    <div className="flex-1 bg-black/98 p-10 overflow-auto custom-scrollbar-voltage text-[16px] text-matrix font-mono shadow-inner border border-matrix/10">
                                        <pre className="whitespace-pre-wrap leading-relaxed italic">
                                            {activeStageId === PipelineStage.OWL ? (lastRawOwl || 'AWAITING_FILE_EXECUTION...') : outputs[activeStageId]}
                                        </pre>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>

            {/* OVERLAYS */}
            <TacticalModelPicker isOpen={pickerOpen} onClose={() => setPickerOpen(false)} models={models} selectedModel={stageSettings[activeStageId].model} onSelect={(m) => setStageSettings(prev => ({ ...prev, [activeStageId]: { ...prev[activeStageId], model: m } }))} />
            <EditorOverlay isOpen={editorOpen} title="PAYLOAD EDITOR" content={editorType === 'input' ? inputs[activeStageId] || '' : arsenal[activeStageId]?.find(p => p.name === activePrompts[activeStageId])?.content || ''} onSave={(val) => editorType === 'input' && setInputs(prev => ({ ...prev, [activeStageId]: val }))} onClose={() => setEditorOpen(false)} />
            <IntelHub isOpen={hubOpen} onClose={() => setHubOpen(false)} activeStageId={activeStageId} startFiles={startFiles} arsenal={arsenal} activePrompts={activePrompts} setInputs={setInputs} setActivePrompts={setActivePrompts} executeStrike={handleStrike} sessionOutputs={outputs} initialTab={hubTab} addLog={addLog} />
            <SessionManager isOpen={sessionOpen} onClose={() => setSessionOpen(false)} currentSessionId={currentSessionId} onLoadSession={handleLoadSession} onNewSession={handleNewSession} />
            <SettingsDeck isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} stageSettings={stageSettings} setStageSettings={setStageSettings} casinoSettings={casinoSettings} setCasinoSettings={setCasinoSettings} />
            <BackgroundTerminal logs={telemetryLogs} isFocused={terminalFocused} />
            <EditorOverlay isOpen={manifestOpen} title="MISSION_DEPLOYMENT_MANIFEST (SH_SCRIPT)" content={manifestContent} onSave={() => { }} onClose={() => setManifestOpen(false)} />
        </div>
    );
}

export default App;
