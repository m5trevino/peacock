import React, { useState, useEffect } from 'react';
import { PipelineStage, CallTelemetry, StageSettings, CasinoSettings, PromptAsset, OwlFile, LogEntry } from './types';
import { useModelRegistry } from './hooks/useModelRegistry';
import { api } from './services/api';
import { db, Session } from './services/db';
import { STAGE_HEADERS, PROTOCOLS } from './config/protocols';
import { generateOverwriteScript, generateFullDeployScript } from './utils/scriptGenerators';
import { parseEagleResponse } from './utils/engineUtils';
import { audioService } from './services/audioService';

// Components
import { CommandHUD } from './components/layout/CommandHUD';
import { StageConsole } from './components/views/StageConsole';
import { OwlHangar } from './components/views/OwlHangar';
import { SettingsDeck } from './components/views/SettingsDeck';

// UI
import { IdentityNode } from './components/layout/IdentityNode';
import { EditorOverlay } from './components/ui/EditorOverlay';
import { IntelHub } from './components/layout/IntelHub';
import { MatrixTerminal } from './components/ui/MatrixTerminal';
import { SessionManager } from './components/views/SessionManager';

const STAGE_CONFIG = {
    [PipelineStage.SPARK]: { color: '#FFD700', icon: '⚡', label: 'SPARK' },
    [PipelineStage.FALCON]: { color: '#00FFFF', icon: '🦅', label: 'FALCON' },
    [PipelineStage.EAGLE]: { color: '#FF00FF', icon: '🦅', label: 'EAGLE' },
    [PipelineStage.OWL]: { color: '#9D00FF', icon: '🦉', label: 'OWL' },
    [PipelineStage.HAWK]: { color: '#00FF41', icon: '🦅', label: 'HAWK' },
};

function App() {
    const { models, loading: modelsLoading } = useModelRegistry();
    const [activeStageId, setActiveStageId] = useState<PipelineStage>(PipelineStage.SPARK);

    // Settings State
    const [settingsOpen, setSettingsOpen] = useState(false);
    // Casino / V21 Doctrine State
    const [casinoSettings, setCasinoSettings] = useState<CasinoSettings>({
        enabled: true,
        audio: true,
        volume: 0.5
    });

    // Audio Loop: Turbine Hum
    useEffect(() => {
        if (casinoSettings.enabled && casinoSettings.audio) {
            audioService.startHum();
        } else {
            audioService.stopHum();
        }
        return () => audioService.stopHum();
    }, [casinoSettings.enabled, casinoSettings.audio]);

    // State
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [inputs, setInputs] = useState<Record<string, string>>({});
    const [outputs, setOutputs] = useState<Record<string, string>>({});
    const [telemetry, setTelemetry] = useState<Record<string, CallTelemetry>>({
        spark: { status: 'idle' },
        falcon: { status: 'idle' },
        eagle: { status: 'idle' },
        owl: { status: 'idle' },
        hawk: { status: 'idle' },
    });

    // Telemetry State
    const [lastCallMeta, setLastCallMeta] = useState<{
        timestamp: number;
        key: string;
        ip: string;
        model: string;
    } | null>(null);

    // Timer Logic
    const [timeSinceCall, setTimeSinceCall] = useState<string>('00:00');

    useEffect(() => {
        if (!lastCallMeta) return;
        const interval = setInterval(() => {
            const diff = Math.floor((Date.now() - lastCallMeta.timestamp) / 1000);
            const m = Math.floor(diff / 60).toString().padStart(2, '0');
            const s = (diff % 60).toString().padStart(2, '0');
            setTimeSinceCall(`${m}:${s}`);
        }, 1000);
        return () => clearInterval(interval);
    }, [lastCallMeta]);

    const [stageSettings, setStageSettings] = useState<Record<string, StageSettings>>({
        spark: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        falcon: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        eagle: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        owl: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
        hawk: { model: 'moonshotai/kimi-k2-instruct-0905', temperature: 0.7 },
    });

    // Editor State
    const [editorOpen, setEditorOpen] = useState(false);
    const [editorType, setEditorType] = useState<'input' | 'prompt'>('input');

    // Intel Hub State
    const [hubOpen, setHubOpen] = useState(false);
    const [hubTab, setHubTab] = useState<'DATA' | 'PROMPTS'>('DATA');

    const handleHubOpen = (val: boolean | 'DATA' | 'PROMPTS') => {
        if (typeof val === 'boolean') {
            setHubOpen(val);
        } else {
            setHubTab(val);
            setHubOpen(true);
        }
    };
    const [startFiles, setStartFiles] = useState<string[]>([]);

    // Session State
    const [sessionOpen, setSessionOpen] = useState(false);
    const [currentSessionId, setCurrentSessionId] = useState<number | null>(null);

    const handleLoadSession = (session: Session) => {
        try {
            const data = JSON.parse(session.data);
            setInputs(data.inputs || {});
            setOutputs(data.outputs || {});
            setTelemetry(data.telemetry || {});
            setOwlQueue(data.owlQueue || []);
            setActivePrompts(data.activePrompts || {});
            setCurrentSessionId(session.id!);

            // Also load stage settings if we want to restore models
            if (data.stageSettings) setStageSettings(data.stageSettings);

            setLogs(prev => [...prev, {
                id: crypto.randomUUID(),
                timestamp: Date.now(),
                message: `SESSION RESTORED // OP_ID: ${session.id}`,
                type: 'success'
            }]);
        } catch (e) {
            console.error("Failed to load session data", e);
        }
    };

    const handleNewSession = () => {
        setCurrentSessionId(null);
        setInputs({});
        setOutputs({});
        setOwlQueue([]);
        // We might want to keep models/prompts selection? 
        // For a true "New Operation", maybe clear inputs/outputs but keep arsenal.
        setLogs(prev => [...prev, {
            id: crypto.randomUUID(),
            timestamp: Date.now(),
            message: `NEW OPERATION INITIALIZED`,
            type: 'info'
        }]);
    };

    const saveSessionSnapshot = async () => {
        const snapshot = {
            inputs, outputs, telemetry, owlQueue, activePrompts, stageSettings
        };
        const dataStr = JSON.stringify(snapshot);
        const timestamp = Date.now();

        let sessionId = currentSessionId;

        if (!sessionId) {
            // Create New
            sessionId = await db.sessions.add({
                name: `OP_${timestamp}`, // Default name, maybe prompt inputs later
                timestamp: timestamp,
                lastUpdated: timestamp,
                data: dataStr
            }) as number;
            setCurrentSessionId(sessionId);
        } else {
            // Update Existing
            await db.sessions.update(sessionId, {
                lastUpdated: timestamp,
                data: dataStr
            });
        }
        return sessionId;
    };

    // Prompts Management
    const [activePrompts, setActivePrompts] = useState<Record<string, string>>({});
    const [arsenal, setArsenal] = useState<Record<string, PromptAsset[]>>({});

    // Load Protocols and Files
    // Load Protocols and Files
    useEffect(() => {
        const loadAssets = async () => {
            // 1. Load Start Files
            const files = await api.fetchStartFiles();
            setStartFiles(files);

            // 2. Load Prompts for all stages
            const stages = Object.keys(STAGE_CONFIG); // spark, falcon, eagle, owl, hawk
            const newArsenal: Record<string, PromptAsset[]> = {};
            const newActivePrompts: Record<string, string> = {};

            await Promise.all(stages.map(async (stage) => {
                const prompts = await api.fetchPrompts(stage);
                if (prompts && prompts.length > 0) {
                    newArsenal[stage] = prompts;

                    // Check for saved default
                    const savedPromptId = localStorage.getItem(`default_prompt_${stage}`);
                    const defaultPrompt = prompts.find(p => p.name === savedPromptId) || prompts[0];

                    newActivePrompts[stage] = defaultPrompt.name;
                    // setInputs(prev => ({ ...prev, [stage]: defaultPrompt.content })); // REMOVED: Do not auto-fill Payload with Prompt
                } else {
                    // Fallback to PROTOCOLS if no file found (Safety net)
                    console.warn(`No prompts found for ${stage}, using fallback.`);
                    const fallbackContent = PROTOCOLS[stage as keyof typeof PROTOCOLS] || '';
                    newArsenal[stage] = [{ id: `${stage}_default`, name: 'DEFAULT', content: fallbackContent }];
                    newActivePrompts[stage] = 'DEFAULT';
                    // setInputs(prev => ({ ...prev, [stage]: fallbackContent })); // REMOVED
                }
            }));

            setArsenal(newArsenal);
            setActivePrompts(newActivePrompts);
        };

        loadAssets();
    }, []);

    const handleStrike = async () => {
        const payload = inputs[activeStageId];
        const settings = stageSettings[activeStageId];

        // Retrieve System Prompt Logic
        const activePromptName = activePrompts[activeStageId];
        const systemPrompt = arsenal[activeStageId]?.find(p => p.name === activePromptName)?.content || '';

        if (!payload || !settings.model) {
            alert("ARMAMENT REQUIRED: Select Model & Payload");
            return;
        }

        const fullPrompt = systemPrompt ? `${systemPrompt}\n\n${payload}` : payload;

        // 1. Lock UI
        setTelemetry(prev => ({ ...prev, [activeStageId]: { status: 'loading' } }));

        // Auto-Save Session Start
        const sessionId = await saveSessionSnapshot();

        try {
            const startTime = Date.now();
            const isEagle = activeStageId === PipelineStage.EAGLE;
            const isOwl = activeStageId === PipelineStage.OWL; // Note: Owl might need specific handling if it's a queue item strike

            // 2. Execute Strike (API)
            const result = await api.executeStrike({
                modelId: settings.model,
                prompt: fullPrompt,
                temp: settings.temperature,
                format_mode: isEagle ? 'eagle_scaffold' : undefined
            });

            // V21 SAFETY: Ensure response is string. 
            // If backend returns JSON Object, we must stringify it for the Console View.
            let responseString = "";
            if (typeof result.content === 'object' && result.content !== null) {
                responseString = JSON.stringify(result.content, null, 2);
            } else {
                responseString = String(result.content);
            }

            // Keep the raw object for parsing if needed, but 'response' const usually implies prompt/text.
            // Let's use `responseString` for display/logs, but pass result.content to parser.
            const rawContent = result.content;

            const keyUsed = result.keyUsed || 'UNKNOWN_KEY';

            const ipUsed = result.ipUsed || 'ROTATING_PROXY'; // Placeholder until backend specific

            const latency = Date.now() - startTime;
            let finalResponse = responseString;

            // Set Last Call Metadata
            setLastCallMeta({
                timestamp: Date.now(),
                key: keyUsed,
                ip: ipUsed,
                model: settings.model
            });

            // 3. Logic: Handle Eagle Scaffold -> Owl Queue

            // 3. Logic: Handle Eagle Scaffold -> Owl Queue
            if (isEagle) {
                try {
                    // V21: Capture Raw Content for User Inspection
                    setEagleRawContent(typeof rawContent === 'string' ? rawContent : JSON.stringify(rawContent, null, 2));

                    // Pass RAW content (might be Object) to parser
                    const newQueue = parseEagleResponse(rawContent);

                    if (newQueue.length > 0) {
                        // Update Queue and Telemetry
                        setOwlQueue(newQueue);
                        setActiveStageId(PipelineStage.OWL); // Auto-switch to Hangar
                        finalResponse = `EAGLE_SCAFFOLD_RECEIVED // ${newQueue.length} FILES QUEUED`;
                        // Optimistic success, queue parsed
                        setTelemetry(prev => ({ ...prev, [activeStageId]: { status: 'success', latency } }));
                    } else {
                        // No files parsed, but maybe response is valid text
                        finalResponse = responseString;
                        // ALERT USER
                        try { audioService.playError(); } catch (e) { console.warn("Audio Error", e); }
                        setLogs(prev => [...prev, {
                            id: crypto.randomUUID(),
                            timestamp: Date.now(),
                            message: `ALERT: EAGLE PARSED 0 FILES. CHECK RAW OUTPUT.`,
                            type: 'error'
                        }]);
                    }
                } catch (e) {
                    console.error("Failed to parse Eagle Scaffold", e);
                    finalResponse = responseString; // Fallback to raw text
                }
            } else {
                // AUTO-PORTING (CHAINING) Logic for non-Eagle stages
                // Determine Next Stage
                const stages = Object.values(PipelineStage);
                const currentIndex = stages.indexOf(activeStageId);
                const nextStage = stages[currentIndex + 1];

                if (nextStage) {
                    // Port the response to the next stage's INPUT
                    // V21 LOGIC: Overwrite the payload directly.
                    // "Spark Output" becomes "Falcon Payload".
                    const targetStage = nextStage as string;
                    setInputs(prev => ({
                        ...prev,
                        [targetStage]: finalResponse
                    }));

                    // AUTO-SWITCH STAGE
                    setActiveStageId(nextStage as PipelineStage);
                    if (casinoSettings.audio && casinoSettings.enabled) audioService.playSuccess();

                    setLogs(prev => [...prev, {
                        id: crypto.randomUUID(),
                        timestamp: Date.now(),
                        message: `AUTO-PORTING // ${activeStageId.toUpperCase()} -> ${targetStage.toUpperCase()} // PAYLOAD INJECTED`,
                        type: 'info'
                    }]);
                }
            }

            // 4. Save to DB
            await db.logs.add({
                timestamp: startTime,
                modelId: settings.model,
                prompt: fullPrompt,
                response: typeof finalResponse === 'string' ? finalResponse : JSON.stringify(finalResponse),
                latency: latency,
                status: 'success',
                sessionId: sessionId
            });

            setLogs(prev => [...prev, {
                id: crypto.randomUUID(),
                timestamp: Date.now(),
                message: `STRIKE CONFIRMED // ${activeStageId.toUpperCase()} // ${latency}ms // ${settings.model}`,
                type: 'success'
            }]);

            if (casinoSettings.audio && casinoSettings.enabled) audioService.playSuccess(); // AUDITORY CONFIRMATION

            // 5. Update Output
            setOutputs(prev => ({ ...prev, [activeStageId]: typeof finalResponse === 'string' ? finalResponse : JSON.stringify(finalResponse, null, 2) }));
            setTelemetry(prev => ({ ...prev, [activeStageId]: { status: 'success', latency } }));

        } catch (error) {
            console.error(error);
            setTelemetry(prev => ({ ...prev, [activeStageId]: { status: 'error' } }));
            if (casinoSettings.audio && casinoSettings.enabled) audioService.playError();
            setLogs(prev => [...prev, {
                id: crypto.randomUUID(),
                timestamp: Date.now(),
                message: `STRIKE FAILURE // ${activeStageId.toUpperCase()} // ${error}`,
                type: 'error'
            }]);
        }
    };

    // Owl State
    const [owlQueue, setOwlQueue] = useState<OwlFile[]>([]);
    const [eagleRawContent, setEagleRawContent] = useState<string>("NO_DATA_YET"); // V21 Raw Intel State

    const openEditorHandler = (type: 'input' | 'prompt') => {
        setEditorType(type);
        setEditorOpen(true);
    };

    const handleInspectOwl = (fileId: string) => {
        const file = owlQueue.find(f => f.id === fileId);
        if (!file) return;

        const prompt = inputs[PipelineStage.OWL] || PROTOCOLS.owl;
        const payload = `
CONTEXT_FILE: ${file.path}
DIRECTIVES: ${file.directives}
SKELETON_CODE:
${file.skeleton}
`;
        const fullContent = `${prompt}\n\n${payload}`;

        // Hijack the Editor Overlay to show this Read-Only content
        // We set inputs[OWL] temporarily? No, better to have a special mode.
        // But for MVP, let's just use the 'input' editor type and set the content.
        // Wait, 'getEditorContent' pulls from inputs[active].
        // So we can set inputs[OWL] to this content? 
        // OR we add a specialized state for "Inspector Content".

        // Let's use a temporary override for viewer.
        setInputs(prev => ({ ...prev, [PipelineStage.OWL]: fullContent }));
        setEditorType('input');
        setEditorOpen(true);
    };

    const executeOwlStrike = async (fileId: string) => {
        const file = owlQueue.find(f => f.id === fileId);
        if (!file) return;

        // V21: Retrieve System Prompt from Arsenal (using Active Prompt selection)
        const activePromptName = activePrompts[PipelineStage.OWL];
        const systemPrompt = arsenal[PipelineStage.OWL]?.find(p => p.name === activePromptName)?.content || PROTOCOLS.owl;

        // V21: Symbol Table (Global Signatures)
        // Collect exports/signatures from all other files to give Owl context
        const globalSignatures = owlQueue
            .filter(f => f.id !== fileId) // Exclude self
            .map(f => `FILE: ${f.path}\n${f.skeleton.split('\n').filter(l => l.includes('export') || l.includes('interface') || l.includes('type')).join('\n')}`)
            .join('\n\n');

        // Construct Payload for Owl
        const payload = `
CONTEXT_FILE: ${file.path}

GLOBAL_SIGNATURES:
${globalSignatures}

DIRECTIVES: ${file.directives}

SKELETON_CODE:
${file.skeleton}
`;
        const fullPrompt = `${systemPrompt}\n\n${payload}`;
        const settings = stageSettings[PipelineStage.OWL];

        // Optimistic Update
        setOwlQueue(prev => prev.map(f => f.id === fileId ? { ...f, status: 'pending' } : f)); // Keep as pending but maybe add 'processing' state if we had it
        // Note: OwlHangar uses 'pending' vs 'completed'. We might want a 'loading' state.
        // For now, let's assume 'pending' means not done.

        try {
            // We can use the main strike API
            // Or maybe we want to track this specifically.
            const response = await api.executeStrike({
                modelId: settings.model,
                prompt: fullPrompt,
                temp: settings.temperature
            });

            // V21: Update Telemetry for Batch Ops
            setLastCallMeta({
                timestamp: Date.now(),
                key: response.keyUsed || 'BATCH_KEY',
                ip: response.ipUsed || 'BATCH_PROXY',
                model: settings.model
            });

            // Update Queue with Result
            setOwlQueue(prev => prev.map(f => f.id === fileId ? {
                ...f,
                status: 'completed',
                output: response.content || (typeof response === 'string' ? response : JSON.stringify(response))
            } : f));

            // Musical Scale Feedback
            const fileIndex = owlQueue.findIndex(f => f.id === fileId);
            if (fileIndex !== -1 && casinoSettings.audio && casinoSettings.enabled) {
                audioService.playScaleNote(fileIndex);
            }

        } catch (e) {
            console.error("Owl Strike Failed", e);
            // Handle error state?
        }
    };

    const handleEditorSave = (val: string) => {
        if (editorType === 'input') {
            setInputs(prev => ({ ...prev, [activeStageId]: val }));
        } else {
            // Update Prompt in Arsenal (Memory)
            const promptName = activePrompts[activeStageId];
            if (promptName && arsenal[activeStageId]) {
                setArsenal(prev => ({
                    ...prev,
                    [activeStageId]: prev[activeStageId].map(p =>
                        p.name === promptName ? { ...p, content: val } : p
                    )
                }));
            }
        }
        setEditorOpen(false);
    };

    const getEditorContent = () => {
        if (editorType === 'input') {
            return inputs[activeStageId] || '';
        } else {
            // PROMPT EDITING
            const promptName = activePrompts[activeStageId];
            const promptAsset = arsenal[activeStageId]?.find(p => p.name === promptName);
            return promptAsset?.content || '';
        }
    };

    return (
        <div className="min-h-screen bg-[#050505] text-white font-mono flex flex-col overflow-hidden selection:bg-[#00FF41] selection:text-black relative">

            {/* MATRIX TERMINAL BACKGROUND */}
            <MatrixTerminal logs={logs} casinoMode={casinoSettings.enabled} />

            <div className="fixed inset-0 pointer-events-none z-50">
                <div className="absolute inset-0 animate-scanline scanline"></div>
            </div>

            <CommandHUD
                onReset={handleNewSession}
                onSettings={() => setSettingsOpen(true)}
            />

            <main className="flex-1 flex overflow-hidden">
                {/* ARCHIVE RAIL */}
                <div className="w-16 border-r border-gray-800 flex flex-col items-center py-4 space-y-4">
                    <button
                        onClick={() => setSessionOpen(true)}
                        className="w-10 h-10 rounded-lg border border-white/10 text-gray-500 hover:text-white hover:border-white/30 flex items-center justify-center transition-all mb-4"
                        title="TIMELINE"
                    >
                        <span className="text-lg">🕒</span>
                    </button>

                    <div className="w-8 h-[1px] bg-white/10 mb-4" />

                    {Object.keys(STAGE_CONFIG).map((stage) => (
                        <button
                            key={stage}
                            onClick={() => setActiveStageId(stage as PipelineStage)}
                            className={`w-10 h-10 rounded-lg border flex items-center justify-center transition-all ${activeStageId === stage
                                ? `border-[${STAGE_CONFIG[stage].color}] text-[${STAGE_CONFIG[stage].color}] bg-white/5`
                                : 'border-white/10 text-gray-600 hover:text-gray-400'
                                }`}
                            style={{ borderColor: activeStageId === stage ? STAGE_CONFIG[stage].color : '' }}
                        >
                            {STAGE_CONFIG[stage].icon}
                        </button>
                    ))}
                </div>

                {/* MAIN STAGE */}
                <div className="flex-1 p-8 flex justify-center overflow-y-auto">
                    {activeStageId === PipelineStage.OWL ? (
                        <OwlHangar
                            queue={owlQueue}
                            executeStrike={executeOwlStrike} // V21: Correct Handler
                            stageSettings={stageSettings}
                            onInspect={(id) => { console.log("Inspect", id); }}
                            rawEagleResponse={eagleRawContent} // V21: Direct State Injection
                            audioEnabled={casinoSettings.audio && casinoSettings.enabled}
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
                            openEditor={openEditorHandler}
                            setHubOpen={handleHubOpen}
                            isArmed={!!stageSettings[activeStageId].model}
                            promptContent={arsenal[activeStageId]?.find(p => p.name === activePrompts[activeStageId])?.content || ''}
                            onInputUpdate={(val) => setInputs(prev => ({ ...prev, [activeStageId]: val }))}
                        />
                    )}
                </div>
            </main>

            {/* FOOTER: LIVE CLI TELEMETRY DECK */}
            <div className="h-12 bg-black border-t border-matrix/30 flex items-center px-4 md:px-8 font-mono text-xs relative overflow-hidden">
                <div className="absolute inset-0 scanlines opacity-30 pointer-events-none" />

                <div className="flex-1 flex gap-8 z-10">
                    {/* MODE SWITCHER Logic */}
                    {activeStageId === PipelineStage.OWL && owlQueue.length > 0 ? (
                        // OWL MODE: BATCH TELEMETRY
                        <>
                            <div className="flex gap-2 items-center">
                                <span className="text-muted font-bold">BATCH_OPS:</span>
                                <span className="text-matrix font-bold animate-pulse">
                                    {owlQueue.filter(f => f.status === 'completed').length} / {owlQueue.length} FILES
                                </span>
                            </div>

                            <div className="flex gap-2 items-center">
                                <span className="text-muted font-bold">IMPULSE_TIMER:</span>
                                {/* Impulse timer resets on each strike - driven by inputs updates */}
                                <span className="text-white font-mono">{timeSinceCall}s</span>
                            </div>

                            {lastCallMeta && (
                                <>
                                    <div className="flex gap-2 items-center">
                                        <span className="text-muted font-bold">EXIT_NODE:</span>
                                        <span className="text-voltage font-mono">{lastCallMeta.ip}</span>
                                    </div>
                                    <div className="flex gap-2 items-center">
                                        <span className="text-muted font-bold">ORDNANCE_KEY:</span>
                                        <span className="text-voltage font-mono">
                                            {lastCallMeta.key.startsWith('sk-')
                                                ? `${lastCallMeta.key.substring(0, 8)}...${lastCallMeta.key.slice(-4)}`
                                                : lastCallMeta.key}
                                        </span>
                                    </div>
                                    <div className="flex gap-2 items-center">
                                        <span className="text-muted font-bold">PROXY_STATE:</span>
                                        <span className="text-matrix font-bold blink">ROTATING</span>
                                    </div>
                                </>
                            )}
                        </>
                    ) : (
                        // STANDARD MODE (Spark/Falcon/Eagle/Hawk)
                        <>
                            <div className="flex gap-2 items-center">
                                <span className="text-muted font-bold">STATUS:</span>
                                <span className={`font-bold ${telemetry[activeStageId].status === 'error' ? 'text-red-500 blink' :
                                    telemetry[activeStageId].status === 'success' ? 'text-matrix' :
                                        telemetry[activeStageId].status === 'loading' ? 'text-voltage animate-pulse' : 'text-gray-500'}`}>
                                    {telemetry[activeStageId].status.toUpperCase()}
                                </span>
                            </div>

                            {lastCallMeta && (
                                <>
                                    <div className="flex gap-2 items-center">
                                        <span className="text-muted font-bold">NODE_IP:</span>
                                        <span className="text-matrix font-mono">{lastCallMeta.ip}</span>
                                    </div>
                                    <div className="flex gap-2 items-center">
                                        <span className="text-muted font-bold">KEY_ID:</span>
                                        <span className="text-voltage font-mono">
                                            {lastCallMeta.key.startsWith('sk-')
                                                ? `..${lastCallMeta.key.slice(-4)}`
                                                : 'UNKNOWN'}
                                        </span>
                                    </div>
                                </>
                            )}

                            <div className="flex gap-2 items-center">
                                <span className="text-muted font-bold">TIMER:</span>
                                <span className="text-white font-mono">{timeSinceCall}</span>
                            </div>

                            {lastCallMeta && (
                                <>
                                    <div className="flex gap-2 items-center">
                                        <span className="text-muted font-bold">EXIT_NODE:</span>
                                        <span className="text-matrix font-mono">{lastCallMeta.ip}</span>
                                    </div>
                                    <div className="flex gap-2 items-center">
                                        <span className="text-muted font-bold">LAST_LATENCY:</span>
                                        <span className="text-white font-mono">{telemetry[activeStageId].latency}ms</span>
                                    </div>
                                </>
                            )}
                        </>
                    )}
                </div>

                <div className="z-10 flex gap-4 text-xs font-bold text-gray-600">
                    <span>PEACOCK_V21.4</span>
                    <span>SECURE_CONNECTION</span>
                </div>
            </div>

            {/* OVERLAYS */}
            <EditorOverlay
                isOpen={editorOpen}
                title={`${activeStageId.toUpperCase()} // ${editorType === 'input' ? 'PAYLOAD' : 'PROMPT'}`}
                content={getEditorContent()}
                onSave={handleEditorSave}
                onClose={() => setEditorOpen(false)}
            />

            <IntelHub
                isOpen={hubOpen}
                onClose={() => setHubOpen(false)}
                activeStageId={activeStageId}
                startFiles={startFiles}
                arsenal={arsenal}
                activePrompts={activePrompts}
                setInputs={setInputs}
                setActivePrompts={setActivePrompts}
                executeStrike={(id, content) => {
                    // Optional auto-strike logic from Hub
                }}
            />

            <SessionManager
                isOpen={sessionOpen}
                onClose={() => setSessionOpen(false)}
                currentSessionId={currentSessionId}
                onLoadSession={handleLoadSession}
                onNewSession={handleNewSession}
            />

            <SettingsDeck
                isOpen={settingsOpen}
                onClose={() => setSettingsOpen(false)}
                stageSettings={stageSettings}
                setStageSettings={setStageSettings}
                casinoSettings={casinoSettings}
                setCasinoSettings={setCasinoSettings}
            />
        </div>
    );
}

export default App;
