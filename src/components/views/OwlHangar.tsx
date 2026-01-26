import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { PipelineStage, OwlFile, ModelConfig, StageSettings } from '../../types';
import { audioService } from '../../services/audioService';
import { generateOverwriteScript, generateFullDeployScript } from '../../utils/scriptGenerators';

interface OwlHangarProps {
    queue: OwlFile[];
    executeStrike: (fileId: string) => void;
    stageSettings: Record<string, StageSettings>;
    onInspect: (fileId: string) => void;
    audioEnabled?: boolean;
    rawEagleResponse?: string; // V21: Inject raw response for inspection
}

export const OwlHangar: React.FC<OwlHangarProps> = ({
    queue,
    executeStrike,
    stageSettings,
    onInspect,
    audioEnabled = true,
    rawEagleResponse = "NO_DATA"
}) => {
    // Find the currently active file (first pending or last active)
    const activeFileId = queue.find(f => f.status === 'pending')?.id;
    const completedCount = queue.filter(f => f.status === 'completed').length;
    const isAllComplete = completedCount === queue.length && queue.length > 0;
    const [showRaw, setShowRaw] = React.useState(false);
    const [showRawType, setShowRawType] = React.useState<'global' | 'file'>('global');
    const [showRawFileId, setShowRawFileId] = React.useState<string | null>(null);

    // Calculate progress
    const progress = queue.length > 0 ? (completedCount / queue.length) * 100 : 0;

    return (
        <div className="w-full max-w-[1800px] h-full flex gap-8">

            {/* LEFT RAIL: PRODUCTION QUEUE */}
            <div className="w-96 flex flex-col gap-4 h-full">
                <div className="bg-surface/50 border border-white/10 rounded-2xl p-6 flex flex-col gap-2">
                    <h2 className="text-xl font-black italic text-white tracking-tight uppercase">Owl_Hangar</h2>
                    <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${isAllComplete ? 'bg-matrix shadow-[0_0_10px_#00FF41]' : 'bg-voltage animate-pulse'}`} />
                        <span className="text-[10px] font-bold text-muted uppercase tracking-widest">{isAllComplete ? 'PRODUCTION_COMPLETE' : 'ASSEMBLY_ACTIVE'}</span>
                        <button onClick={() => setShowRaw(!showRaw)} className="ml-auto text-[9px] font-bold text-white/40 hover:text-white uppercase transition-colors">
                            {showRaw ? 'HIDE_INTEL' : 'VIEW_RAW'}
                        </button>
                    </div>

                    {/* PROGRESS BADGE */}
                    <div className="mt-4 relative h-24 bg-void border border-white/10 rounded-xl flex items-center justify-center overflow-hidden">
                        <div className="absolute inset-0 bg-matrix/10 z-0" style={{ transform: `scaleX(${progress / 100})`, transformOrigin: 'left', transition: 'transform 1s ease' }} />
                        <div className="z-10 text-center">
                            <span className="text-3xl font-black text-white">{completedCount} <span className="text-white/30">/</span> {queue.length}</span>
                            <span className="block text-[9px] font-bold text-matrix uppercase tracking-widest mt-1">FILES_WRITTEN</span>
                        </div>
                    </div>
                </div>

                <div className="flex-1 bg-void/30 border border-white/5 rounded-2xl p-4 overflow-y-auto custom-scrollbar flex flex-col gap-3">
                    {queue.map((f, i) => {
                        const isActive = f.id === activeFileId;
                        const isDone = f.status === 'completed';

                        return (
                            <div
                                key={f.id}
                                className={`p-4 rounded-xl border transition-all relative overflow-hidden group ${isActive ? 'bg-white/5 border-white/20 shadow-lg' :
                                    isDone ? 'bg-matrix/5 border-matrix/30 opacity-60 hover:opacity-100' :
                                        'bg-void border-white/5 opacity-40'
                                    }`}
                            >
                                <div className="flex justify-between items-start mb-2">
                                    <span className="text-[9px] font-bold text-white/40 uppercase tracking-widest">DOC</span>

                                    <div className="flex gap-2">
                                        <button
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                setShowRawType('file');
                                                setShowRawFileId(f.id);
                                                setShowRaw(true);
                                            }}
                                            className="text-[9px] font-bold text-white/20 hover:text-white uppercase transition-colors"
                                        >
                                            INSPECT
                                        </button>
                                        {isDone && <span className="text-matrix">✓</span>}
                                    </div>
                                </div>
                                <h4 className={`text-sm font-bold truncate mb-3 ${isActive ? 'text-white' : isDone ? 'text-matrix' : 'text-muted'}`}>{f.path.split('/').pop()}</h4>

                                <div className="flex gap-2">
                                    {isDone ? (
                                        <button
                                            onClick={() => { navigator.clipboard.writeText(generateOverwriteScript(f.path, f.output || '')); if (audioEnabled) audioService.playSuccess(); }}
                                            className="flex-1 py-2 bg-matrix text-void text-[10px] font-black uppercase rounded hover:bg-white transition-colors"
                                        >
                                            COPY_WRITTEN_FILE
                                        </button>
                                    ) : (
                                        <button
                                            onClick={() => isActive && executeStrike(f.id)}
                                            disabled={!isActive}
                                            className={`flex-1 py-2 text-[10px] font-black uppercase rounded transition-colors ${isActive ? 'bg-voltage text-void hover:bg-white' : 'bg-white/5 text-white/20 cursor-not-allowed'}`}
                                        >
                                            {isActive ? 'SEND_API_CALL' : 'WAITING'}
                                        </button>
                                    )}
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* CENTER: CONSOLE / MONITORING */}
            <div className="flex-1 bg-surface/30 border border-white/10 rounded-2xl p-8 relative overflow-hidden flex flex-col">
                {/* OVERLAY IF LOCKED */}
                {!activeFileId && !isAllComplete && queue.length > 0 && (
                    <div className="absolute inset-0 z-10 bg-black/50 backdrop-blur-sm flex items-center justify-center">
                        <span className="bg-black/80 border border-white/20 px-6 py-3 rounded-lg text-xs font-mono text-white/60">INITIALIZING_QUEUE...</span>
                    </div>
                )}

                {/* TOP STATS BAR */}
                <div className="flex justify-between items-center mb-8">
                    <div className="flex gap-12">
                        <div className="flex flex-col gap-1">
                            <span className="text-[10px] font-black text-muted uppercase tracking-widest">CONTEXT_PRESSURE</span>
                            <div className="flex gap-1 w-32 h-2">
                                {Array.from({ length: 10 }).map((_, i) => (
                                    <div key={i} className={`flex-1 rounded-sm ${i < 3 ? 'bg-matrix' : 'bg-white/10'}`} />
                                ))}
                            </div>
                        </div>
                        <div className="flex flex-col gap-1">
                            <span className="text-[10px] font-black text-muted uppercase tracking-widest">WEAPON_SELECTION</span>
                            <span className="text-xs font-bold text-white mono">{stageSettings[PipelineStage.OWL].model.split('/').pop()}</span>
                        </div>
                    </div>

                    <div className="flex gap-4">
                        <button className="px-6 py-3 bg-void border border-matrix/30 rounded-lg text-matrix text-[10px] font-black uppercase hover:bg-matrix/10 transition-colors">
                            INTEL_HUB
                        </button>
                        <button className="px-6 py-3 bg-void border border-white/10 rounded-lg text-muted text-[10px] font-black uppercase hover:border-white/30 transition-colors">
                            TELEMETRY
                        </button>
                    </div>
                </div>

                {/* MAIN DISPLAY AREA */}
                {/* MAIN DISPLAY AREA */}
                <div className="flex-1 flex items-center justify-center border border-white/5 rounded-xl bg-void/50 mb-8 relative group">
                    <div className="absolute inset-0 bg-[url('/assets/images/grid.svg')] opacity-10" />

                    {activeFileId && !isAllComplete ? (
                        <div className="text-center">
                            <div className="w-24 h-24 bg-voltage/10 rounded-full flex items-center justify-center mx-auto mb-6 border border-voltage/30 animate-pulse">
                                <span className="text-4xl">⚡</span>
                            </div>
                            <h3 className="text-2xl font-black text-white italic tracking-tight mb-2">TARGET_LOCKED</h3>
                            <p className="text-sm font-mono text-white/50">{queue.find(f => f.id === activeFileId)?.path}</p>
                            <div className="mt-8">
                                <span className="text-[10px] font-black text-voltage uppercase tracking-[0.3em] blink">AWAITING_FIRE_COMMAND</span>
                            </div>
                        </div>
                    ) : isAllComplete ? (
                        <div className="text-center">
                            <div className="w-24 h-24 bg-matrix/10 rounded-full flex items-center justify-center mx-auto mb-6 border border-matrix/30 shadow-[0_0_50px_rgba(0,255,65,0.2)]">
                                <span className="text-4xl text-matrix">✔</span>
                            </div>
                            <h3 className="text-2xl font-black text-white italic tracking-tight mb-2">RUN_COMPLETE</h3>
                            <p className="text-sm font-mono text-white/50">All modules successfully generated.</p>
                        </div>
                    ) : (
                        <span className="text-xs font-mono text-white/20">SYSTEM_IDLE</span>
                    )}

                </div>

                {/* RAW OVERLAY (GLOBAL or PER FILE) */}
                <AnimatePresence>
                    {showRaw && (
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 0.95 }}
                            className="absolute inset-4 z-50 bg-black/95 border border-white/20 rounded-xl p-4 overflow-hidden flex flex-col shadow-2xl"
                        >
                            <div className="flex justify-between items-center mb-2">
                                <h3 className="text-xs font-black text-white uppercase tracking-widest">
                                    {showRawType === 'global' ? 'RAW_EAGLE_INTEL' : `FILE_INTEL: ${queue.find(f => f.id === showRawFileId)?.path}`}
                                </h3>
                                <div className="flex gap-4 items-center">
                                    {showRawType === 'file' && (
                                        <button
                                            onClick={() => {
                                                const f = queue.find(f => f.id === showRawFileId);
                                                if (f) {
                                                    const payload = `CONTEXT_FILE: ${f.path}\nDIRECTIVES: ${f.directives}\nSKELETON_CODE:\n${f.skeleton}`;
                                                    navigator.clipboard.writeText(payload);
                                                }
                                            }}
                                            className="text-[10px] font-bold text-matrix hover:text-white uppercase"
                                        >
                                            COPY_PAYLOAD
                                        </button>
                                    )}
                                    <button onClick={() => { setShowRaw(false); setShowRawType('global'); setShowRawFileId(null); }} className="text-white/50 hover:text-white">✕</button>
                                </div>
                            </div>
                            <pre className="flex-1 overflow-auto text-[10px] font-mono text-white/70 whitespace-pre-wrap srollbar-thin p-4 bg-void/50 border border-white/5 rounded-lg">
                                {showRawType === 'global' ? rawEagleResponse :
                                    (() => {
                                        const f = queue.find(f => f.id === showRawFileId);
                                        return f ? `PATH: ${f.path}\n\n=== DIRECTIVES ===\n${f.directives}\n\n=== SKELETON ===\n${f.skeleton}` : 'FILE_NOT_FOUND';
                                    })()
                                }
                            </pre>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* BIG BUTTON AREA */}
                <button
                    disabled={!activeFileId && !isAllComplete}
                    onClick={() => {
                        if (isAllComplete) {
                            navigator.clipboard.writeText(generateFullDeployScript(queue));
                            if (audioEnabled) audioService.playSuccess();
                        } else if (activeFileId) {
                            executeStrike(activeFileId);
                        }
                    }}
                    className={`w-full h-16 rounded-xl border transition-all relative overflow-hidden group ${activeFileId ? 'bg-void text-white border-white/20 hover:border-voltage hover:text-voltage hover:shadow-[0_0_50px_rgba(255,215,0,0.2)] cursor-pointer' : isAllComplete ? 'bg-void text-white border-white/20 hover:border-matrix hover:text-matrix hover:shadow-[0_0_50px_rgba(0,255,65,0.2)] cursor-pointer' : 'bg-void border-white/5 opacity-50 cursor-not-allowed'}`}
                >
                    <span className={`text-xl font-black tracking-[0.5em] italic transition-colors ${activeFileId ? 'text-white group-hover:text-voltage' : isAllComplete ? 'text-white group-hover:text-matrix' : 'text-white/10'}`}>
                        {isAllComplete ? 'DEPLOY_SYSTEM' : 'FIRE_OWL'}
                    </span>
                </button>

            </div>
        </div >
    );
};
