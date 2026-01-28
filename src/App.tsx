import React, { useState, useEffect } from 'react';
import { PipelineStage, CallTelemetry, StageSettings, CasinoSettings, PromptAsset, OwlFile, LogEntry } from './types';
import { useModelRegistry } from './hooks/useModelRegistry';
import { api } from './services/api';
import { db, Session } from './services/db';
import { STAGE_HEADERS, PROTOCOLS } from './config/protocols';
import { parseEagleResponse } from './utils/engineUtils';
import { audioService } from './services/audioService';

// Components
import { CommandHUD } from './components/layout/CommandHUD';
import { StageConsole } from './components/views/StageConsole';
import { OwlHangar } from './components/views/OwlHangar';
import { SettingsDeck } from './components/views/SettingsDeck';

// UI
import { EditorOverlay } from './components/ui/EditorOverlay';
import { IntelHub } from './components/layout/IntelHub';
import { SessionManager } from './components/views/SessionManager';
import { MiniMap } from './components/ui/MiniMap';

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
    const [settingsOpen, setSettingsOpen] = useState(false);
    const [casinoSettings, setCasinoSettings] = useState<CasinoSettings>({ enabled: true, audio: true, volume: 0.5 });

    // Core Data
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [inputs, setInputs] = useState<Record<string, string>>({});
    const [outputs, setOutputs] = useState<Record<string, string>>({});
    const [telemetry, setTelemetry] = useState<Record<string, CallTelemetry>>({
        spark: { status: 'idle' }, falcon: { status: 'idle' }, eagle: { status: 'idle' }, owl: { status: 'idle' }, hawk: { status: 'idle' }
    });
    const [lastCallMeta, setLastCallMeta] = useState<any>(null);
    const [timeSinceCall, setTimeSinceCall] = useState<string>('00:00');
    const [stageSettings, setStageSettings] = useState<Record<string, StageSettings>>({
        spark: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        falcon: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        eagle: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        owl: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        hawk: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
    });

    // Modals
    const [editorOpen, setEditorOpen] = useState(false);
    const [editorType, setEditorType] = useState<'input' | 'prompt'>('input');
    const [hubOpen, setHubOpen] = useState(false);
    const [hubTab, setHubTab] = useState<'DATA' | 'PROMPTS'>('DATA');
    const [sessionOpen, setSessionOpen] = useState(false);
    const [currentSessionId, setCurrentSessionId] = useState<number | null>(null);

    // Assets
    const [startFiles, setStartFiles] = useState<string[]>([]);
    const [activePrompts, setActivePrompts] = useState<Record<string, string>>({});
    const [arsenal, setArsenal] = useState<Record<string, PromptAsset[]>>({});

    // Owl
    const [owlQueue, setOwlQueue] = useState<OwlFile[]>([]);
    const [eagleRawContent, setEagleRawContent] = useState<string>("NO_DATA_YET");

    // --- EFFECTS ---
    useEffect(() => {
        if (casinoSettings.enabled && casinoSettings.audio) audioService.startHum();
        else audioService.stopHum();
        return () => audioService.stopHum();
    }, [casinoSettings.enabled, casinoSettings.audio]);

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
        };
        loadAssets();
    }, []);

    // --- HANDLERS ---
    const handleNewSession = () => {
        setCurrentSessionId(null);
        setInputs({}); setOutputs({}); setOwlQueue([]);
        setLogs(prev => [...prev, { id: crypto.randomUUID(), timestamp: Date.now(), message: `NEW OPERATION INITIALIZED`, type: 'info' }]);
    };

    const handleLoadSession = (session: Session) => {
        const data = JSON.parse(session.data);
        setInputs(data.inputs || {}); setOutputs(data.outputs || {});
        setTelemetry(data.telemetry || {}); setOwlQueue(data.owlQueue || []);
        setActivePrompts(data.activePrompts || {});
        setCurrentSessionId(session.id!);
    };

    // THE STRIKE LOGIC (Keep intact)
    const handleStrike = async () => {
        const payload = inputs[activeStageId];
        const settings = stageSettings[activeStageId];
        const activePromptName = activePrompts[activeStageId];
        const systemPrompt = arsenal[activeStageId]?.find(p => p.name === activePromptName)?.content || '';

        if (!payload || !settings.model) return alert("ARMAMENT REQUIRED");
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
            let finalResponse = typeof result.content === 'object' ? JSON.stringify(result.content, null, 2) : String(result.content);

            // Logic: Porting
            if (isEagle) {
                const newQueue = parseEagleResponse(result.content);
                if (newQueue.length) {
                    setOwlQueue(newQueue);
                    setActiveStageId(PipelineStage.OWL);
                    finalResponse = `EAGLE_SCAFFOLD_RECEIVED // ${newQueue.length} FILES QUEUED`;
                }
            } else {
                const stages = Object.values(PipelineStage);
                const nextStage = stages[stages.indexOf(activeStageId) + 1] as string;
                if (nextStage) {
                    setInputs(prev => ({ ...prev, [nextStage]: finalResponse }));
                    setActiveStageId(nextStage as PipelineStage);
                }
            }

            setOutputs(prev => ({ ...prev, [activeStageId]: finalResponse }));
            setTelemetry(prev => ({ ...prev, [activeStageId]: { status: 'success', latency, exitIP: result.ipUsed, key: result.keyUsed } }));

            if (activeStageId === PipelineStage.HAWK) {
                if (casinoSettings.audio) audioService.playJackpot();
            } else if (casinoSettings.audio) {
                audioService.playSuccess();
            }
        } catch (error) {
            console.error(error);
            setTelemetry(prev => ({ ...prev, [activeStageId]: { status: 'error' } }));
            if (casinoSettings.audio) audioService.playError();
        }
    };

    // Derived
    const activePromptName = activePrompts[activeStageId];
    const promptContent = arsenal[activeStageId]?.find(p => p.name === activePromptName)?.content || '';

    // --- RENDER (THE BOX) ---
    return (
        <div className="the-box">
            {/* BACKGROUND SCANLINES */}
            <div className="fixed inset-0 pointer-events-none z-0 opacity-10 scanline" />

            {/* COL 1: SIDEBAR (Command) - REDUCED TO UTILITIES */}
            <div className="fixed left-4 top-1/2 -translate-y-1/2 flex flex-col items-center gap-6 z-50">
                <button onClick={() => setSessionOpen(true)} className="w-12 h-12 rounded-xl tactical-glass border border-white/10 hover:border-matrix/50 flex items-center justify-center text-xl hover:shadow-[0_0_15px_var(--matrix-glow)] transition-all">
                    🕒
                </button>
                <button onClick={() => setSettingsOpen(true)} className="w-12 h-12 rounded-xl tactical-glass border border-white/10 hover:border-voltage/50 flex items-center justify-center text-xl hover:shadow-[0_0_15px_var(--voltage-glow)] transition-all">
                    ⚙️
                </button>
            </div>

            {/* MAIN CONTENT AREA */}
            <div className="flex-1 relative z-10 flex flex-col h-full overflow-hidden items-center pt-6 px-10">
                {/* HEADER: STATUS BAR */}
                <div className="w-full flex justify-between items-center text-[10px] font-black uppercase tracking-[0.2em] mb-4 text-muted/60 px-4">
                    <div className="flex gap-8">
                        <span className="text-matrix flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-matrix animate-pulse" />
                            PEACOCK_V21_ONLINE
                        </span>
                        <span>NODE_LATENCY: {telemetry[activeStageId].latency || 0}MS</span>
                    </div>
                    <span>SYSTEM_TIME: {timeSinceCall}</span>
                </div>

                {/* THE MIND MAP (CENTRAL NAVIGATION) */}
                <div className="w-full h-40 mb-2 mt-4 flex justify-center">
                    <MiniMap
                        telemetry={telemetry}
                        activeStageId={activeStageId}
                        setActiveStageId={setActiveStageId}
                    />
                </div>

                {/* CONTENT AREA */}
                <div className="flex-1 overflow-hidden relative">
                    {activeStageId === PipelineStage.OWL ? (
                        <OwlHangar
                            queue={owlQueue}
                            executeStrike={() => { }}
                            stageSettings={stageSettings}
                            onInspect={() => { }}
                            rawEagleResponse={eagleRawContent}
                            audioEnabled={casinoSettings.audio}
                        />
                    ) : (
                        <StageConsole
                            activeStageId={activeStageId}
                            activeStageConfig={STAGE_CONFIG[activeStageId]}
                            inputs={inputs}
                            sessionOutputs={outputs}
                            telemetry={telemetry}
                            models={models}
                            stageSettings={stageSettings}
                            setStageSettings={setStageSettings}
                            handleStrike={handleStrike}
                            openEditor={(type) => { setEditorType(type); setEditorOpen(true); }}
                            setHubOpen={(val) => {
                                if (typeof val === 'string') { setHubTab(val); setHubOpen(true); }
                                else setHubOpen(val);
                            }}
                            isArmed={!!stageSettings[activeStageId].model}
                            promptContent={arsenal[activeStageId]?.find(p => p.name === activePrompts[activeStageId])?.content || ''}
                            onInputUpdate={(val) => setInputs(prev => ({ ...prev, [activeStageId]: val }))}
                        />
                    )}
                </div>
            </div>

            {/* OVERLAYS */}
            <EditorOverlay isOpen={editorOpen} title="PAYLOAD EDITOR" content={editorType === 'input' ? inputs[activeStageId] || '' : promptContent} onSave={(val) => {
                if (editorType === 'input') setInputs(prev => ({ ...prev, [activeStageId]: val }));
                // Note: Prompt saving would need extra wiring in App.tsx if desired
            }} onClose={() => setEditorOpen(false)} />
            <IntelHub isOpen={hubOpen} onClose={() => setHubOpen(false)} activeStageId={activeStageId} startFiles={startFiles} arsenal={arsenal} activePrompts={activePrompts} setInputs={setInputs} setActivePrompts={setActivePrompts} executeStrike={handleStrike} sessionOutputs={outputs} initialTab={hubTab} />
            <SessionManager isOpen={sessionOpen} onClose={() => setSessionOpen(false)} currentSessionId={currentSessionId} onLoadSession={handleLoadSession} onNewSession={handleNewSession} />
            <SettingsDeck isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} stageSettings={stageSettings} setStageSettings={setStageSettings} casinoSettings={casinoSettings} setCasinoSettings={setCasinoSettings} />
        </div>
    );
}

export default App;
