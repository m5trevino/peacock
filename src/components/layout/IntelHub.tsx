import React from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { PipelineStage, PromptAsset } from '../../types';
import { audioService } from '../../services/audioService';
import { ENGINE_URL, STAGES } from '../../config/constants';
import axios from 'axios';

interface IntelHubProps {
    isOpen: boolean;
    onClose: () => void;
    activeStageId: PipelineStage;
    startFiles: string[];
    arsenal: Record<string, PromptAsset[]>;
    activePrompts: Record<string, string>;
    setInputs: React.Dispatch<React.SetStateAction<Record<string, string>>>;
    setActivePrompts: React.Dispatch<React.SetStateAction<Record<string, string>>>;
    executeStrike: (id: PipelineStage, content?: string) => void;
    sessionOutputs?: Record<string, string>;
    initialTab?: 'DATA' | 'PROMPTS';
    addLog: (text: string) => void;
}

export const IntelHub: React.FC<IntelHubProps> = ({
    isOpen, onClose, activeStageId, startFiles, arsenal, activePrompts,
    setInputs, setActivePrompts, executeStrike, sessionOutputs, initialTab, addLog
}) => {
    const activeStageConfig = STAGES.find(s => s.id === activeStageId)!;
    const [activeTab, setActiveTab] = React.useState<'DATA' | 'PROMPTS'>(initialTab || 'DATA');

    // Calculate Previous Stage
    const stageIds = STAGES.map(s => s.id);
    const currentIndex = stageIds.indexOf(activeStageId);
    const prevStageId = currentIndex > 0 ? stageIds[currentIndex - 1] : undefined;
    const prevStageOutput = prevStageId && sessionOutputs ? sessionOutputs[prevStageId] : undefined;

    return (
        <AnimatePresence>
            {isOpen && (
                <div className="fixed inset-0 z-[100] bg-black/95 backdrop-blur-xl flex items-center justify-center p-20">
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }}
                        className="w-full max-w-6xl tactical-glass rounded-2xl p-14 flex flex-col h-[80vh] border border-white/10 shadow-[0_0_100px_rgba(0,0,0,1)]"
                    >
                        <div className="flex justify-between items-start border-b border-white/5 pb-6 mb-8">
                            <div className="flex items-center gap-4">
                                <div className="p-3 bg-white/5 rounded-lg border border-white/10" style={{ color: activeStageConfig.color }}>
                                    <span className="text-2xl">{activeStageConfig.icon}</span>
                                </div>
                                <div>
                                    <h3 className="text-xl font-black tracking-tight uppercase text-white">Asset_Registry</h3>
                                    <p className="text-[9px] font-bold text-muted uppercase tracking-[0.2em] mt-1">{activeStageConfig.label} // Tactical_Intelligence_Node</p>
                                </div>
                            </div>
                            <button onClick={onClose} className="text-muted hover:text-white text-xl transition-all bg-white/5 w-10 h-10 rounded-lg flex items-center justify-center border border-white/5 hover:bg-error/20 hover:border-error/40">✕</button>
                        </div>

                        {/* TABS HEADER */}
                        <div className="flex gap-8 border-b border-white/10 mb-8">
                            <button onClick={() => setActiveTab('DATA')} className={`pb-4 text-xs font-black uppercase tracking-[0.2em] transition-all border-b-2 ${activeTab === 'DATA' ? 'text-white border-matrix' : 'text-white/30 border-transparent hover:text-white'}`}>
                                DATA_ASSETS
                            </button>
                            <button onClick={() => setActiveTab('PROMPTS')} className={`pb-4 text-xs font-black uppercase tracking-[0.2em] transition-all border-b-2 ${activeTab === 'PROMPTS' ? 'text-white border-matrix' : 'text-white/30 border-transparent hover:text-white'}`}>
                                PROMPT_ARSENAL
                            </button>
                        </div>

                        <div className="flex-1 overflow-y-auto custom-scrollbar pr-4 content-start">

                            {/* DATA TAB */}
                            {activeTab === 'DATA' && (
                                <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
                                    <div className="pb-2 border-b border-white/5 flex items-center gap-4">
                                        <span className="text-xs font-black text-matrix uppercase tracking-[0.3em]">Data_Assets</span>
                                        <span className="text-[10px] text-white/30 font-mono">CONTEXT_LOADER</span>
                                    </div>

                                    {prevStageOutput && (
                                        <button onClick={() => {
                                            setInputs(v => ({ ...v, [activeStageId]: prevStageOutput }));
                                            addLog(`[FS] :: PULLING_DNA_FROM_PREVIOUS_STAGE_OUTPUT... (SIZE: ${prevStageOutput.length})`);
                                            audioService.playSuccess();
                                        }} className="text-left p-6 bg-surface/40 border border-white/5 rounded-xl hover:border-voltage hover:bg-voltage/10 transition-all group flex flex-col gap-2 shadow-sm hover:shadow-[0_0_20px_rgba(0,255,255,0.1)] mb-4">
                                            <div className="flex justify-between items-center">
                                                <span className="text-[9px] font-black text-voltage uppercase tracking-widest">PREVIOUS_STAGE_INTEL</span>
                                                <span className="text-[10px] text-white/20">AUTO_CAPTURED</span>
                                            </div>
                                            <h4 className="text-sm font-black text-white group-hover:text-voltage truncate">LOAD {prevStageId?.toUpperCase()} OUTPUT</h4>
                                            <p className="text-[10px] text-white/40 line-clamp-2 font-mono">{prevStageOutput.substring(0, 100)}...</p>
                                        </button>
                                    )}

                                    {startFiles.map(name => (
                                        <button key={name} onClick={async () => {
                                            const res = await axios.get(`${ENGINE_URL}/fs/start/${name}`);
                                            setInputs(v => ({ ...v, [activeStageId]: res.data.content }));
                                            addLog(`[FS] :: PULLING_DNA_FROM_/home/flintx/peacock/start/${name}...`);
                                            audioService.playSuccess();
                                        }} className="text-left p-6 bg-surface/40 border border-white/5 rounded-xl hover:border-matrix hover:bg-matrix/5 transition-all group flex flex-col gap-2 shadow-sm hover:shadow-[0_0_20px_rgba(0,255,65,0.1)]">
                                            <div className="flex justify-between items-center">
                                                <span className="text-[9px] font-black text-muted uppercase tracking-widest">Start_File</span>
                                                <span className="text-[10px] text-white/20">.MD</span>
                                            </div>
                                            <h4 className="text-sm font-black text-white group-hover:text-matrix truncate">{name}</h4>
                                        </button>
                                    ))}
                                </div>
                            )}

                            {/* PROMPTS TAB */}
                            {activeTab === 'PROMPTS' && (
                                <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
                                    <div className="pb-2 border-b border-white/5 flex items-center gap-4">
                                        <span className="text-xs font-black uppercase tracking-[0.3em]" style={{ color: activeStageConfig.color }}>Prompt_Arsenal</span>
                                        <span className="text-[10px] text-white/30 font-mono">/home/flintx/peacock/prompts/{activeStageId}</span>
                                    </div>

                                    {arsenal[activeStageId]?.map(p => (
                                        <button key={p.id} onClick={() => {
                                            setActivePrompts(v => ({ ...v, [activeStageId]: p.name }));
                                            localStorage.setItem(`default_prompt_${activeStageId}`, p.name);
                                            addLog(`[SYS] :: RE-ARMING_PHASE_${activeStageId.toUpperCase()}... SELECTED_WEAPON: "${p.name}"`);
                                            audioService.playSuccess();
                                        }} className={`text-left p-6 border rounded-xl transition-all group relative flex flex-col gap-2 ${activePrompts[activeStageId] === p.name ? 'border-matrix bg-matrix/10 shadow-[0_0_30px_rgba(0,255,65,0.15)]' : 'bg-surface/40 border-white/5 hover:border-white/20'}`}>
                                            <div className="flex justify-between items-center">
                                                <span className="text-[9px] font-black text-muted uppercase tracking-widest">Strike_Weapon</span>
                                                {activePrompts[activeStageId] === p.name && <span className="text-[9px] font-bold text-matrix animate-pulse">ACTIVE</span>}
                                            </div>
                                            <h4 className={`text-sm font-black truncate ${activePrompts[activeStageId] === p.name ? 'text-matrix' : 'text-white'}`}>{p.name}</h4>
                                        </button>
                                    ))}

                                    {(!arsenal[activeStageId] || arsenal[activeStageId].length === 0) && (
                                        <div className="p-10 text-center text-muted italic border border-dashed border-white/10 rounded-xl">
                                            No prompts found.
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </motion.div>
                </div>
            )}
        </AnimatePresence>
    );
};
