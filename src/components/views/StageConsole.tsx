import React from 'react';
import { motion } from 'framer-motion';
import { TacticalMinimap } from '../ui/TacticalMinimap';

import { PipelineStage, CallTelemetry, ModelConfig, StageSettings } from '../../types';
import { VUMeter } from '../ui/VUMeter';
import { TacticalDropdown } from '../ui/TacticalDropdown';
import { audioService } from '../../services/audioService';

interface StageConsoleProps {
    activeStageId: PipelineStage;
    activeStageConfig: any;
    inputs: Record<string, string>;
    outputs: Record<string, string>;
    telemetry: Record<string, CallTelemetry>;
    models: ModelConfig[];
    stageSettings: Record<string, StageSettings>;
    setStageSettings: React.Dispatch<React.SetStateAction<Record<string, StageSettings>>>;
    handleStrike: () => void;
    setHubOpen: (v: 'DATA' | 'PROMPTS' | boolean) => void;
    isArmed: boolean;
    promptContent: string;
    rawResponse?: any;
    onInputUpdate: (val: string) => void;
}

export const StageConsole: React.FC<StageConsoleProps> = ({
    activeStageId, activeStageConfig, inputs = {}, outputs = {}, telemetry, models, stageSettings, setStageSettings,
    handleStrike, openEditor, setHubOpen, isArmed, promptContent, rawResponse, onInputUpdate
}) => {
    const [showRaw, setShowRaw] = React.useState(false);
    return (
        <motion.div
            key={activeStageId}
            initial={{ scale: 0.9, opacity: 0, y: 10 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            className="w-full max-w-7xl h-full tactical-glass rounded-3xl p-6 flex flex-col items-center relative border border-white/5 shadow-[0_30px_60px_rgba(0,0,0,0.8)] overflow-y-auto custom-scrollbar"
        >

            {/* TOP ROW: MINIMAPS */}
            <div className="w-full grid grid-cols-2 gap-6 mb-6">
                <div className="relative group">
                    <TacticalMinimap
                        label="ACTIVE_PAYLOAD"
                        type="input"
                        color="white"
                        content={inputs[activeStageId]}
                        onExpand={() => openEditor('input')}
                    />
                </div>
                <TacticalMinimap
                    label="SYSTEM_PROMPT"
                    type="output"
                    color="white"
                    content={promptContent}
                    onExpand={() => openEditor('prompt')}
                />
            </div>

            {/* CENTER STAGE ICON */}
            <div className="w-32 h-32 rounded-3xl border-2 border-dashed border-white/10 flex items-center justify-center mb-6 relative group transition-all duration-500 hover:border-current" style={{ color: activeStageConfig.color }}>
                <div className="absolute inset-0 rounded-3xl blur-3xl opacity-10 group-hover:opacity-30 transition-opacity animate-pulse" style={{ background: activeStageConfig.color }} />
                <span className="text-6xl font-black text-white/10 italic group-hover:text-current transition-all transform group-hover:scale-110 duration-500">{activeStageConfig.icon}</span>
            </div>

            {/* CONTROLS ROW */}
            <div className="w-full flex gap-6 mb-8">
                <div className="flex-1 bg-surface/50 border border-white/10 rounded-2xl p-6 flex flex-col gap-4 shadow-inner">
                    <VUMeter value={Math.floor((inputs[activeStageId]?.length || 0 / 10000) * 100)} label="Context_Pressure" />
                    <TacticalDropdown
                        label="Weapon_Selection"
                        value={stageSettings[activeStageId].model}
                        options={models}
                        onChange={m => setStageSettings(v => ({ ...v, [activeStageId]: { ...v[activeStageId], model: m } }))}
                    />
                </div>
                <div className="w-80 bg-surface/50 border border-white/10 rounded-2xl p-4 flex flex-col justify-center gap-4 shadow-inner">
                    <button onClick={() => setHubOpen('DATA')} className="w-full py-4 bg-void border border-white/5 rounded-xl text-white/40 font-black text-[10px] tracking-[0.3em] uppercase hover:bg-white/5 hover:text-white hover:border-white/20 transition-all flex items-center justify-center gap-4 group">
                        <span className="group-hover:scale-110 transition-transform">🗂️</span> TACTICAL_ASSETS
                    </button>
                    {rawResponse && (
                        <button onClick={() => setShowRaw(!showRaw)} className={`w-full py-2 border rounded-xl font-black text-[9px] tracking-widest uppercase transition-all flex items-center justify-center gap-2 ${showRaw ? 'bg-voltage/20 border-voltage text-voltage' : 'bg-void border-white/5 text-white/40 hover:text-white'}`}>
                            {showRaw ? 'HIDE_RAW_INTEL' : 'VIEW_RAW_INTEL'}
                        </button>
                    )}
                </div>
            </div>

            {/* RAW INTEL MONITOR */}
            {showRaw && rawResponse && (
                <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="w-full mb-6 bg-void border border-voltage/30 rounded-2xl p-4 relative overflow-hidden">
                    <div className="flex justify-between items-center mb-2">
                        <span className="text-[9px] font-black text-voltage uppercase tracking-widest">RAW_API_PAYLOAD_DECODED</span>
                        <span className="text-[8px] font-mono text-white/20 italic">DIRECT_ENGINE_RESPONSE</span>
                    </div>
                    <pre className="text-[10px] font-mono text-voltage/80 whitespace-pre-wrap overflow-y-auto max-h-96 custom-scrollbar-voltage">
                        {JSON.stringify(rawResponse, null, 2)}
                    </pre>
                </motion.div>
            )}

            {/* TACTICAL MONITOR (OUTPUT DISPLAY) */}
            {outputs[activeStageId] && (
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="w-full mb-10 bg-black/50 border border-matrix/30 rounded-2xl p-6 relative overflow-hidden group"
                >
                    <div className="absolute top-0 left-0 w-full h-1 bg-matrix/20" />
                    <div className="flex justify-between items-center mb-4 border-b border-white/5 pb-2">
                        <span className="text-[10px] font-black text-matrix uppercase tracking-widest">Incoming_Transmission</span>
                        <div className="flex gap-2">
                            <button onClick={() => navigator.clipboard.writeText(outputs[activeStageId])} className="text-[9px] text-muted hover:text-white uppercase tracking-wider">Copy</button>
                        </div>
                    </div>
                    <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap max-h-60 overflow-y-auto custom-scrollbar selection:bg-matrix selection:text-black">
                        {outputs[activeStageId]}
                    </pre>
                </motion.div>
            )}

            {/* FIRE BUTTON - V21: STRIKE TRIGGER REDESIGN */}
            <div className="w-full relative group mt-4">
                {/* TRIGGER DECORATION */}
                <div className="absolute -top-4 left-1/2 -translate-x-1/2 flex gap-1 pointer-events-none">
                    <div className={`w-12 h-1 rounded-full transition-all duration-500 ${isArmed ? 'bg-voltage shadow-[0_0_15px_var(--voltage-glow)]' : 'bg-white/5'}`} />
                    <div className={`w-12 h-1 rounded-full transition-all duration-500 delay-75 ${isArmed ? 'bg-voltage shadow-[0_0_15px_var(--voltage-glow)]' : 'bg-white/5'}`} />
                    <div className={`w-12 h-1 rounded-full transition-all duration-500 delay-150 ${isArmed ? 'bg-voltage shadow-[0_0_15px_var(--voltage-glow)]' : 'bg-white/5'}`} />
                </div>

                <button
                    disabled={telemetry[activeStageId].status === 'loading'}
                    onClick={handleStrike}
                    className={`w-full py-14 rounded-2xl font-black tracking-[1em] transition-all relative overflow-hidden flex items-center justify-center border-t border-white/5 ${telemetry[activeStageId].status === 'loading'
                            ? 'bg-void cursor-wait shadow-inner'
                            : isArmed
                                ? 'bg-void text-white border-white/10 hover:border-voltage/40 hover:shadow-[0_0_100px_rgba(255,215,0,0.15)] cursor-pointer active:scale-[0.99] active:bg-voltage/5'
                                : 'bg-void/50 text-white/5 cursor-not-allowed'
                        }`}
                >
                    {/* SURGE LINE */}
                    {isArmed && telemetry[activeStageId].status !== 'loading' && (
                        <motion.div
                            initial={{ x: '-100%' }}
                            animate={{ x: '100%' }}
                            transition={{ repeat: Infinity, duration: 4, ease: 'linear' }}
                            className="absolute inset-y-0 w-60 bg-gradient-to-r from-transparent via-voltage/10 to-transparent skew-x-12"
                        />
                    )}

                    <div className="relative z-10 flex flex-col items-center">
                        <span className={`text-[9px] font-black tracking-[1.2em] mb-3 uppercase transition-all duration-700 ${isArmed ? 'text-voltage opacity-50' : 'text-white/5'}`}>
                            Authorization_Required
                        </span>
                        <span className={`text-5xl font-black tracking-[0.2em] uppercase transition-all duration-500 ${isArmed ? 'text-white drop-shadow-[0_0_15px_rgba(255,255,255,0.3)]' : 'text-white/5'}`}>
                            {telemetry[activeStageId].status === 'loading' ? 'STRIKING...' : activeStageId === PipelineStage.EAGLE && outputs[activeStageId] ? 'SURGE_DEPLOY' : `STRIKE_${activeStageConfig.label}`}
                        </span>
                    </div>

                    {/* SCANLINES OVERLAY */}
                    <div className="absolute inset-0 pointer-events-none opacity-[0.03] scanline-mini" />
                </button>
            </div>

            <div className="absolute -bottom-10 left-0 w-full flex justify-center">
                <span className="text-[9px] font-black text-muted uppercase tracking-[1.5em] opacity-30 animate-pulse">Tactical_Orchestration_Active</span>
            </div>
        </motion.div>
    );
};
