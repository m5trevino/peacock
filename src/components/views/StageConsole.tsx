import React from 'react';
import { motion } from 'framer-motion';
import { TacticalMinimap } from '../ui/TacticalMinimap';
import { StartFileSelector } from '../ui/StartFileSelector';

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
    onInputUpdate: (val: string) => void;
}

export const StageConsole: React.FC<StageConsoleProps> = ({
    activeStageId, activeStageConfig, inputs = {}, outputs = {}, telemetry, models, stageSettings, setStageSettings,
    handleStrike, openEditor, setHubOpen, isArmed, promptContent, onInputUpdate
}) => {
    console.log("StageConsole Mounted", { activeStageId });
    return (
        <motion.div
            key={activeStageId}
            initial={{ scale: 0.9, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            className="w-full max-w-7xl h-full tactical-glass rounded-3xl p-10 flex flex-col items-center relative border border-white/5 shadow-[0_50px_100px_rgba(0,0,0,0.8)] overflow-y-auto custom-scrollbar"
        >

            {/* TOP ROW: MINIMAPS */}
            <div className="w-full grid grid-cols-2 gap-6 mb-6">
                <div className="relative group">
                    {/* V21: SPARK FILE LOADER - ABSOLUTE POSITIONED IN HEADER */}
                    {activeStageId === PipelineStage.SPARK && (
                        <div className="absolute top-2 right-2 z-20">
                            <StartFileSelector onSelect={onInputUpdate} />
                        </div>
                    )}

                    <TacticalMinimap
                        label="ACTIVE_PAYLOAD"
                        type="input"
                        color="white"
                        content={inputs[activeStageId]}
                        onExpand={() => openEditor('input')}
                    />
                    {/* INJECT FILE SELECTOR FOR SPARK ONLY */}
                    {activeStageId === PipelineStage.SPARK && (
                        <div className="absolute top-0 right-0 z-20 transform -translate-y-1/2">
                            <StartFileSelector onSelect={(content) => {
                                onInputUpdate(content);
                            }} />
                        </div>
                    )}
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
            <div className="w-40 h-40 rounded-3xl border-2 border-dashed border-white/10 flex items-center justify-center mb-12 relative group transition-all duration-500 hover:border-current" style={{ color: activeStageConfig.color }}>
                <div className="absolute inset-0 rounded-3xl blur-3xl opacity-10 group-hover:opacity-30 transition-opacity animate-pulse" style={{ background: activeStageConfig.color }} />
                <span className="text-7xl font-black text-white/10 italic group-hover:text-current transition-all transform group-hover:scale-110 duration-500">{activeStageConfig.icon}</span>
            </div>

            {/* CONTROLS ROW */}
            <div className="w-full flex gap-10 mb-16">
                <div className="flex-1 bg-surface/50 border border-white/10 rounded-2xl p-10 flex flex-col gap-8 shadow-inner">
                    <VUMeter value={Math.floor((inputs[activeStageId]?.length || 0 / 10000) * 100)} label="Context_Pressure" />
                    <TacticalDropdown
                        label="Weapon_Selection"
                        value={stageSettings[activeStageId].model}
                        options={models}
                        onChange={m => setStageSettings(v => ({ ...v, [activeStageId]: { ...v[activeStageId], model: m } }))}
                    />
                </div>
                <div className="w-80 bg-surface/50 border border-white/10 rounded-2xl p-8 flex flex-col justify-center gap-6 shadow-inner">
                    <button onClick={() => setHubOpen('DATA')} className="w-full py-6 bg-black/40 border border-matrix/30 rounded-xl text-matrix font-black text-xs tracking-widest uppercase hover:bg-matrix/10 hover:shadow-[0_0_20px_rgba(0,255,65,0.1)] transition-all flex items-center justify-center gap-4 group">
                        <span className="group-hover:scale-110 transition-transform">📂</span> DATA_INTEL
                    </button>
                    <button onClick={() => setHubOpen('PROMPTS')} className="w-full py-6 bg-void border border-white/5 rounded-xl text-muted font-black text-xs tracking-widest uppercase italic hover:border-white/20 transition-all flex items-center justify-center gap-4 group">
                        <span className="group-hover:scale-110 transition-transform">⚡</span> PROMPTS
                    </button>
                </div>
            </div>

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

            {/* FIRE BUTTON */}
            <button disabled={telemetry[activeStageId].status === 'loading'}
                onClick={handleStrike}
                className={`w-full py-20 rounded-3xl font-black text-6xl tracking-[0.5em] italic transition-all border shadow-2xl relative overflow-hidden group ${telemetry[activeStageId].status === 'loading' ? 'system-stress bg-void border-white/5 cursor-wait' : isArmed ? 'bg-void text-white border-white/20 hover:border-matrix hover:text-matrix hover:shadow-[0_0_100px_rgba(0,255,65,0.3)] cursor-pointer active:scale-[0.98]' : 'bg-void text-white/5 border-white/5 cursor-not-allowed'}`}
            >
                <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-transparent via-matrix/40 to-transparent group-hover:via-matrix opacity-0 group-hover:opacity-100 transition-opacity" />
                <span className="relative z-10 transition-transform group-hover:scale-110 inline-block drop-shadow-2xl">
                    {telemetry[activeStageId].status === 'loading' ? 'STRIKING...' : activeStageId === PipelineStage.EAGLE && outputs[activeStageId] ? 'CLIPBOARD_SURGE' : `FIRE_${activeStageConfig.label}`}
                </span>
                {isArmed && telemetry[activeStageId].status !== 'loading' && (
                    <div className="absolute inset-0 bg-matrix/5 opacity-0 group-hover:opacity-100 transition-opacity animate-pulse" />
                )}
            </button>

            <div className="absolute -bottom-10 left-0 w-full flex justify-center">
                <span className="text-[9px] font-black text-muted uppercase tracking-[1.5em] opacity-30 animate-pulse">Tactical_Orchestration_Active</span>
            </div>
        </motion.div>
    );
};
