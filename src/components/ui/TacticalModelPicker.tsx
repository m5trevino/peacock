import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface ModelInfo {
    id: string;
    gateway: string;
    tier: string;
    note: string;
}

interface TacticalModelPickerProps {
    isOpen: boolean;
    onClose: () => void;
    models: ModelInfo[];
    selectedModel: string;
    onSelect: (model: string) => void;
}

export const TacticalModelPicker: React.FC<TacticalModelPickerProps> = ({
    isOpen,
    onClose,
    models,
    selectedModel,
    onSelect
}) => {
    const [hoverGateway, setHoverGateway] = useState<string | null>(null);
    const [hoverModel, setHoverModel] = useState<ModelInfo | null>(null);

    const gateways = useMemo(() => Array.from(new Set(models.map(m => m.gateway))), [models]);
    const activeModels = useMemo(() => models.filter(m => m.gateway === hoverGateway), [models, hoverGateway]);

    const activeModelInfo = useMemo(() => models.find(m => m.id === selectedModel), [models, selectedModel]);

    return (
        <AnimatePresence>
            {isOpen && (
                <div className="fixed inset-0 z-[300]">
                    <div className="absolute inset-0 bg-void/50 backdrop-blur-sm" onClick={onClose} />

                    {/* LEVEL 1: GATEWAYS */}
                    <motion.div
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -10 }}
                        className="absolute top-16 left-1/4 w-48 bg-gunmetal border border-white/20 shadow-2xl rounded overflow-hidden z-[301]"
                    >
                        <div className="p-2 border-b border-white/10 bg-void/50 text-[10px] font-black text-white/50 tracking-[0.4em] uppercase">Gateway_Links</div>
                        <div className="p-1">
                            {gateways.map(gw => (
                                <div
                                    key={gw}
                                    onMouseEnter={() => setHoverGateway(gw)}
                                    className={`px-3 py-2 rounded mb-0.5 text-[10px] font-black tracking-widest uppercase cursor-pointer transition-all ${hoverGateway === gw ? 'bg-matrix text-void shadow-matrix-glow' : 'text-matrix hover:bg-white/5'}`}
                                >
                                    [{gw.toUpperCase()}_DIRECT]
                                </div>
                            ))}
                        </div>
                    </motion.div>

                    {/* LEVEL 2: MODELS (FLYOUT) */}
                    <AnimatePresence>
                        {hoverGateway && (
                            <motion.div
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                exit={{ opacity: 0, x: -5 }}
                                className="absolute top-16 left-[calc(1/4+12rem+0.5rem)] w-64 bg-gunmetal border border-white/20 shadow-2xl rounded overflow-hidden z-[302]"
                            >
                                <div className="p-2 border-b border-white/10 bg-void/50 text-[10px] font-black text-white/50 tracking-[0.4em] uppercase">Detected_Nodes // {hoverGateway.toUpperCase()}</div>
                                <div className="p-1 max-h-[500px] overflow-y-auto custom-scrollbar-voltage">
                                    {activeModels.map(m => (
                                        <div
                                            key={m.id}
                                            onMouseEnter={() => setHoverModel(m)}
                                            onClick={() => {
                                                onSelect(m.id);
                                                onClose();
                                            }}
                                            className={`px-3 py-1 rounded mb-0.5 text-[8px] font-black tracking-widest uppercase cursor-pointer transition-all border-l-2 ${selectedModel === m.id ? 'border-voltage bg-voltage/10 text-voltage' : hoverModel?.id === m.id ? 'border-white/20 bg-white/5 text-white' : 'border-transparent text-white/40 hover:text-white'}`}
                                        >
                                            {m.id.split('/').pop()}
                                        </div>
                                    ))}
                                </div>
                            </motion.div>
                        )}
                    </AnimatePresence>

                    {/* LEVEL 3: THE FLARE (INTEL) */}
                    <AnimatePresence>
                        {hoverModel && (
                            <motion.div
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                exit={{ opacity: 0, x: -5 }}
                                className="absolute top-16 left-[calc(1/4+12rem+16rem+1rem)] w-72 bg-gunmetal border border-white/20 shadow-2xl rounded overflow-hidden z-[303]"
                            >
                                <div className="p-4 border-b border-white/10 bg-void/50">
                                    <div className="text-[10px] text-voltage font-black tracking-[0.6em] uppercase mb-2">Technical_Intel</div>
                                    <div className="text-[14px] text-white font-black uppercase mb-4 leading-tight">{hoverModel.note}</div>

                                    <div className="grid grid-cols-2 gap-4 mt-6 font-mono">
                                        <div>
                                            <div className="text-[8px] text-white/30 uppercase tracking-widest mb-1">Tier_Protocol</div>
                                            <div className={`text-[9px] font-black uppercase px-2 py-0.5 rounded border inline-block ${hoverModel.tier === 'expensive' ? 'text-red-400 border-red-400/20 bg-red-400/5' : hoverModel.tier === 'cheap' ? 'text-voltage border-voltage/20 bg-voltage/5' : 'text-matrix border-matrix/20 bg-matrix/5'}`}>
                                                {hoverModel.tier.toUpperCase()}_UNIT
                                            </div>
                                        </div>
                                        <div>
                                            <div className="text-[8px] text-white/30 uppercase tracking-widest mb-1">Latency_Rating</div>
                                            <div className="text-[9px] text-matrix font-black">STABLE_ULTRA</div>
                                        </div>
                                    </div>
                                </div>
                                <div className="p-4 bg-void/50">
                                    <div className="text-[8px] text-white/30 uppercase tracking-[0.2em] mb-2 font-black">System_Notes</div>
                                    <div className="text-[9px] text-white/70 italic leading-relaxed">
                                        Optimization locked for {hoverModel.gateway} gateway. Contextual processing active.
                                    </div>
                                </div>
                                <div className="absolute top-0 inset-x-0 h-[1px] bg-voltage shadow-voltage-glow animate-pulse" />
                            </motion.div>
                        )}
                    </AnimatePresence>

                    {/* PERSISTENT [?] ICON FOR ACTIVE INFO */}
                    {activeModelInfo && !hoverModel && (
                        <div
                            className="fixed top-16 left-[calc(1/4-4rem)] bg-voltage/10 border border-voltage/30 p-2 rounded-full cursor-help hover:bg-voltage/20 transition-all group"
                            onMouseEnter={() => setHoverModel(activeModelInfo)}
                        >
                            <span className="text-voltage font-black text-xl leading-none">?</span>
                            <div className="absolute top-full mt-2 left-0 w-max bg-gunmetal border border-white/20 p-2 text-[8px] text-white font-black uppercase tracking-widest opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50">
                                RECALL_ACTIVE_SPECS
                            </div>
                        </div>
                    )}
                </div>
            )}
        </AnimatePresence>
    );
};
