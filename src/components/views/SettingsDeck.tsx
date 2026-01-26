import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useModelRegistry } from '../../hooks/useModelRegistry';
import { StageSettings, CasinoSettings } from '../../types';

interface SettingsDeckProps {
    isOpen: boolean;
    onClose: () => void;
    stageSettings: Record<string, StageSettings>;
    setStageSettings: React.Dispatch<React.SetStateAction<Record<string, StageSettings>>>;
    casinoSettings: CasinoSettings;
    setCasinoSettings: React.Dispatch<React.SetStateAction<CasinoSettings>>;
}

export const SettingsDeck: React.FC<SettingsDeckProps> = ({ isOpen, onClose, stageSettings, setStageSettings, casinoSettings, setCasinoSettings }) => {
    const [activeTab, setActiveTab] = useState<'NODES' | 'PROMPTS' | 'CASINO' | 'ENGINE'>('NODES');

    return (
        <AnimatePresence>
            {isOpen && (
                <div className="fixed inset-0 z-[100] bg-black/90 backdrop-blur-xl flex items-center justify-center p-20">
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.95 }}
                        className="w-full max-w-5xl tactical-glass rounded-2xl flex flex-col h-[70vh] border border-white/10 shadow-2xl relative overflow-hidden"
                    >
                        {/* HEADER */}
                        <div className="flex justify-between items-center p-8 border-b border-white/10 bg-white/5">
                            <h2 className="text-3xl font-black italic tracking-tighter uppercase text-white">
                                SYSTEM_CONFIG_<span className="text-matrix">V21</span>
                            </h2>
                            <button onClick={onClose} className="w-10 h-10 rounded-lg border border-white/10 flex items-center justify-center text-muted hover:text-white hover:border-white/30 transition-all">✕</button>
                        </div>

                        <div className="flex flex-1 overflow-hidden">
                            {/* SIDEBAR TABS */}
                            <div className="w-64 border-r border-white/10 p-6 flex flex-col gap-2 bg-black/20">
                                {['NODES', 'PROMPTS', 'CASINO', 'ENGINE'].map((tab) => (
                                    <button
                                        key={tab}
                                        onClick={() => setActiveTab(tab as any)}
                                        className={`p-4 rounded-xl text-left font-black tracking-widest text-xs border transition-all ${activeTab === tab
                                            ? 'bg-matrix text-black border-matrix shadow-[0_0_20px_rgba(0,255,65,0.4)]'
                                            : 'bg-transparent text-muted border-transparent hover:bg-white/5 hover:text-white'
                                            }`}
                                    >
                                        [{tab}]
                                    </button>
                                ))}
                            </div>

                            {/* CONTENT AREA */}
                            <div className="flex-1 p-10 overflow-y-auto bg-gradient-to-br from-black/50 to-void/50">
                                {activeTab === 'NODES' && (
                                    <div className="space-y-8">
                                        <h3 className="text-xl font-bold text-white mb-6 border-b border-white/10 pb-4">NODE_CONFIGURATION</h3>
                                        <div className="grid grid-cols-1 gap-4">
                                            <div className="p-6 rounded-xl border border-white/10 bg-white/5">
                                                <div className="flex justify-between mb-2">
                                                    <span className="font-bold text-matrix">MOONSHOT_NODE_01</span>
                                                    <span className="text-xs bg-matrix/20 text-matrix px-2 py-1 rounded">ACTIVE</span>
                                                </div>
                                                <div className="text-xs text-muted font-mono">Gateway: api.moonshot.cn/v1</div>
                                            </div>
                                            {/* Expandable node list can go here */}
                                        </div>
                                    </div>
                                )}

                                {activeTab === 'CASINO' && (
                                    <div className="space-y-8">
                                        <h3 className="text-xl font-bold text-white mb-6 border-b border-white/10 pb-4">CASINO_DOCTRINE</h3>

                                        <div className="flex items-center justify-between p-6 rounded-xl border border-white/10 bg-white/5">
                                            <div>
                                                <h4 className="font-bold text-white">VISUAL_FEEDBACK_LOOPS</h4>
                                                <p className="text-xs text-muted mt-1">Enable screen shake, scanlines, and matrix rain.</p>
                                            </div>
                                            <button
                                                onClick={() => setCasinoSettings(prev => ({ ...prev, enabled: !prev.enabled }))}
                                                className={`w-14 h-8 rounded-full p-1 transition-colors ${casinoSettings.enabled ? 'bg-matrix' : 'bg-white/10'}`}
                                            >
                                                <div className={`w-6 h-6 rounded-full bg-white shadow-md transform transition-transform ${casinoSettings.enabled ? 'translate-x-6' : 'translate-x-0'}`} />
                                            </button>
                                        </div>

                                        <div className="flex items-center justify-between p-6 rounded-xl border border-white/10 bg-white/5">
                                            <div>
                                                <h4 className="font-bold text-white">HAPTIC_AUDIO</h4>
                                                <p className="text-xs text-muted mt-1">Enable interface clicks, hums, and success chimes.</p>
                                            </div>
                                            <button
                                                onClick={() => setCasinoSettings(prev => ({ ...prev, audio: !prev.audio }))}
                                                className={`w-14 h-8 rounded-full p-1 transition-colors ${casinoSettings.audio ? 'bg-matrix' : 'bg-white/10'}`}
                                            >
                                                <div className={`w-6 h-6 rounded-full bg-white shadow-md transform transition-transform ${casinoSettings.audio ? 'translate-x-6' : 'translate-x-0'}`} />
                                            </button>
                                        </div>
                                    </div>
                                )}

                                {activeTab === 'PROMPTS' && (
                                    <div className="space-y-8">
                                        <div className="p-10 border border-dashed border-white/20 rounded-2xl flex flex-col items-center justify-center text-center">
                                            <span className="text-4xl mb-4">📂</span>
                                            <h3 className="font-bold text-white">LOCAL_ARSENAL_LINK</h3>
                                            <p className="text-sm text-muted mt-2 max-w-sm">
                                                Prompts are loaded directly from <code className="text-matrix bg-black/50 px-2 py-1 rounded">/home/flintx/peacock/prompts</code>.
                                                <br />
                                                Edit files locally to update the arsenal.
                                            </p>
                                            <button className="mt-6 px-6 py-2 bg-white/10 hover:bg-white/20 rounded-lg text-xs font-bold uppercase tracking-widest transition-colors">
                                                REFRESH_INDEX
                                            </button>
                                        </div>
                                    </div>
                                )}

                                {activeTab === 'ENGINE' && (
                                    <div className="space-y-8">
                                        <div className="p-6 rounded-xl border border-white/10 bg-white/5 font-mono text-xs">
                                            <div className="flex justify-between border-b border-white/5 pb-2 mb-2">
                                                <span className="text-muted">ENGINE_STATUS</span>
                                                <span className="text-matrix">ONLINE (PORT 3099)</span>
                                            </div>
                                            <div className="flex justify-between border-b border-white/5 pb-2 mb-2">
                                                <span className="text-muted">LATENCY</span>
                                                <span className="text-white">12ms</span>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    </motion.div>
                </div>
            )}
        </AnimatePresence>
    );
};
