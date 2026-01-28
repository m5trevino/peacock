import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { OwlFile, StageSettings } from '../../types';
import { MatrixText } from '../ui/MatrixText';

interface OwlHangarProps {
    queue: OwlFile[];
    executeStrike: (fileId: string) => void;
    stageSettings: Record<string, StageSettings>;
    onInspect: (fileId: string) => void;
    onRewrite: (fileId: string) => void;
    onCopyEOF: (fileId: string) => void;
    audioEnabled?: boolean;
    rawEagleResponse?: string;
    onGenerateManifest: () => void;
}

export const OwlHangar: React.FC<OwlHangarProps> = ({
    queue,
    executeStrike,
    onInspect,
    onRewrite,
    onCopyEOF,
    onGenerateManifest
}) => {
    // Determine active file for chasing border
    const activeFileId = queue.find(f => f.status === 'loading')?.id;

    return (
        <div className="flex flex-col h-full overflow-hidden">
            {/* SCROLLABLE LIST */}
            <div className="flex-1 overflow-y-auto custom-scrollbar-voltage pr-2 flex flex-col gap-0.5">
                {queue.length === 0 ? (
                    <div className="p-4 border border-white/5 bg-void text-white/10 italic text-[10px] tracking-widest text-center">
                        AWAITING_BLUEPRINT_SIGNALS...
                    </div>
                ) : queue.map((f, i) => {
                    const isDone = f.status === 'completed';
                    const isLoading = f.status === 'loading';
                    const isError = f.status === 'error';
                    const fileName = f.path.split('/').pop() || "ASSET";

                    return (
                        <div
                            key={f.id}
                            className={`
                                h-[36px] flex items-center px-3 border transition-all duration-300 relative group overflow-hidden
                                ${isLoading ? 'chasing-border bg-voltage/5 border-voltage/20 z-10' : 'bg-void/40 border-white/5'}
                                ${isDone ? 'success-glint border-matrix/20' : ''}
                                ${isError ? 'border-error/20 bg-error/5' : ''}
                                hover:bg-white/5
                            `}
                        >
                            {/* INDEX / STATUS LED */}
                            <div className="w-8 flex items-center justify-center shrink-0 border-r border-white/5 mr-3 h-full">
                                <span className={`text-[8px] font-black ${isDone ? 'text-matrix' : isLoading ? 'text-voltage animate-pulse' : 'text-white/20'}`}>
                                    {i.toString().padStart(2, '0')}
                                </span>
                            </div>

                            {/* FILENAME / PATH */}
                            <div
                                className="flex-1 flex items-center min-w-0 h-full cursor-pointer gap-4"
                                onClick={() => !isLoading && executeStrike(f.id)}
                            >
                                <span className={`text-[10px] font-black tracking-tighter truncate uppercase ${isDone ? 'text-matrix' : isLoading ? 'text-white' : 'text-white/40'}`}>
                                    {fileName}
                                </span>
                                <span className="text-[7px] font-mono text-voltage/40 tracking-[0.2em] font-black">
                                    {(f.directives.length + f.skeleton.length).toLocaleString()}ch
                                </span>
                            </div>

                            {/* ACTIONS (TACTICAL GRID) */}
                            {isDone && (
                                <div className="flex border-l border-white/5 h-full opacity-30 group-hover:opacity-100 transition-opacity">
                                    <button
                                        onClick={(e) => { e.stopPropagation(); onCopyEOF(f.id); }}
                                        className="px-3 h-full border-r border-white/5 hover:bg-voltage/20 hover:text-voltage transition-all text-[7px] font-black tracking-widest text-voltage/50 uppercase"
                                        title="COPY_EOF_PROTOCOL"
                                    >
                                        EOF
                                    </button>
                                    <button
                                        onClick={(e) => { e.stopPropagation(); onInspect(f.id); }}
                                        className="px-3 h-full border-r border-white/5 hover:bg-matrix/20 hover:text-matrix transition-all text-[7px] font-black tracking-widest text-matrix/50 uppercase"
                                        title="INSPECT_SOURCE"
                                    >
                                        VIEW
                                    </button>
                                    <button
                                        onClick={(e) => { e.stopPropagation(); onRewrite(f.id); }}
                                        className="px-3 h-full hover:bg-white/10 hover:text-white transition-all text-[7px] font-black tracking-widest text-white/30 uppercase"
                                        title="TRIGGER_REWRITE"
                                    >
                                        REGEN
                                    </button>
                                </div>
                            )}

                            {/* MINI TELEMETRY */}
                            <div className="flex items-center gap-3 shrink-0 pl-3">
                                <span className="text-[7px] text-white/10 uppercase tracking-widest font-black hidden group-hover:block pointer-events-none">
                                    {f.path}
                                </span>
                                <div className={`w-1.5 h-1.5 rounded-none ${isDone ? 'bg-matrix shadow-[0_0_5px_var(--matrix-glow)]' : isLoading ? 'bg-voltage animate-ping' : 'bg-white/5'}`} />
                            </div>

                            {/* OVERLAY: MATRIX LOCK ON COMPLETE */}
                            {isDone && (
                                <div className="absolute inset-0 bg-matrix/5 pointer-events-none" />
                            )}
                        </div>
                    );
                })}
            </div>

            {/* DEPLOYMENT Manifest Trigger */}
            {queue.some(f => f.status === 'completed') && (
                <div className="mt-4 p-4 border-t border-white/10 bg-void/50 shrink-0">
                    <button
                        onClick={onGenerateManifest}
                        className="w-full py-4 bg-matrix text-void font-black text-[12px] tracking-[0.4em] uppercase hover:brightness-125 transition-all shadow-[0_0_40px_var(--matrix-glow)]"
                    >
                        GENERATE_DEPLOYMENT_SH_SCRIPT
                    </button>
                </div>
            )}
        </div>
    );
};
