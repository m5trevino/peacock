import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { audioService } from '../../services/audioService';

interface SavePromptModalProps {
    isOpen: boolean;
    onClose: () => void;
    pendingRawData: any;
}

export const SavePromptModal: React.FC<SavePromptModalProps> = ({ isOpen, onClose, pendingRawData }) => {
    return (
        <AnimatePresence>
            {isOpen && (
                <motion.div
                    initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                    className="fixed inset-0 z-[2000] bg-black/90 backdrop-blur-3xl flex items-center justify-center"
                >
                    <div className="w-full max-w-lg tactical-glass border border-matrix/20 rounded-2xl p-10 flex flex-col items-center gap-8 shadow-[0_0_100px_rgba(0,255,65,0.1)]">
                        <div className="w-20 h-20 bg-matrix/10 rounded-full flex items-center justify-center border border-matrix/20">
                            <span className="text-4xl animate-pulse">💾</span>
                        </div>
                        <div className="text-center flex flex-col gap-2">
                            <h3 className="text-2xl font-black italic tracking-tighter text-white uppercase">Eagle_Strike_Secured</h3>
                            <p className="text-[10px] text-muted mono uppercase tracking-widest">Would you like to export the raw API response to your local drive?</p>
                        </div>
                        <div className="grid grid-cols-2 gap-4 w-full">
                            <button
                                onClick={() => {
                                    const blob = new Blob([JSON.stringify(pendingRawData, null, 2)], { type: 'application/json' });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = `RAW_EAGLE_STRIKE_${new Date().getTime()}.json`;
                                    a.click();
                                    onClose();
                                    audioService.playSuccess();
                                }}
                                className="py-4 bg-matrix text-void font-black text-[10px] uppercase rounded-xl hover:bg-white transition-all shadow-[0_0_20px_rgba(0,255,65,0.2)]"
                            >
                                Download_Raw_JSON
                            </button>
                            <button
                                onClick={onClose}
                                className="py-4 bg-white/5 text-white/60 font-black text-[10px] uppercase rounded-xl hover:bg-white/10 transition-all border border-white/5"
                            >
                                Skip_Export
                            </button>
                        </div>
                    </div>
                </motion.div>
            )}
        </AnimatePresence>
    );
};
