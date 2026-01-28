import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { audioService } from '../../services/audioService';

interface EditorOverlayProps {
    isOpen: boolean;
    content: string;
    onSave: (val: string) => void;
    onClose: () => void;
    title: string;
}

export const EditorOverlay: React.FC<EditorOverlayProps> = ({
    isOpen,
    content,
    onSave,
    onClose,
    title
}) => {
    const [val, setVal] = useState(content || '');
    useEffect(() => { setVal(content || ''); }, [content]);

    return (
        <AnimatePresence>
            {isOpen && (
                <motion.div
                    initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                    className="fixed inset-0 z-[1000] bg-void/95 backdrop-blur-2xl flex items-center justify-center p-10"
                >
                    <div className="w-full max-w-6xl h-full flex flex-col border border-white/10 rounded-2xl overflow-hidden shadow-[0_0_100px_rgba(0,0,0,1)] bg-void relative">
                        {/* Background Scanlines for Overlay */}
                        <div className="absolute inset-0 pointer-events-none opacity-5 scanlines z-0" />
                        <div className="h-16 bg-black/50 border-b border-white/5 px-8 flex justify-between items-center">
                            <div className="flex items-center gap-4">
                                <div className="w-2 h-2 rounded-full bg-matrix animate-pulse" />
                                <h3 className="text-[10px] font-black uppercase tracking-[0.4em] text-white/50">{title}</h3>
                            </div>
                            <div className="flex gap-4">
                                <button
                                    onClick={() => {
                                        const blob = new Blob([val], { type: 'text/plain' });
                                        const url = URL.createObjectURL(blob);
                                        const a = document.createElement('a');
                                        a.href = url;
                                        a.download = `artifact_${title.split(' // ')[1]}_${Date.now()}.txt`;
                                        a.click();
                                    }}
                                    className="px-6 py-2 bg-white/5 text-white/60 text-[9px] font-black uppercase rounded-md hover:text-white transition-all"
                                >
                                    Download_Artifact
                                </button>
                                <button onClick={() => { navigator.clipboard.writeText(val); audioService.playSuccess(); }} className="px-6 py-2 bg-white/5 text-white/60 text-[9px] font-black uppercase rounded-md hover:text-white transition-all">Copy</button>
                                <button onClick={() => onSave(val)} className="px-6 py-2 bg-matrix text-void text-[9px] font-black uppercase rounded-md hover:bg-white transition-all">Save_Changes</button>
                                <button onClick={onClose} className="px-6 py-2 bg-white/5 text-white text-[9px] font-black uppercase rounded-md hover:bg-error transition-all">Close</button>
                            </div>
                        </div>
                        <textarea
                            value={val}
                            onChange={(e) => setVal(e.target.value)}
                            style={{ backgroundColor: '#050505', color: '#00FF41', fontFamily: 'monospace' }}
                            className="flex-1 p-10 text-sm outline-none resize-none custom-scrollbar border-none shadow-inner"
                            spellCheck={false}
                        />
                        <div className="h-10 bg-black/50 border-t border-white/5 px-8 flex items-center justify-between">
                            <span className="text-[7px] text-muted mono uppercase">System_Protocol_V26.6</span>
                            <span className="text-[7px] text-muted mono uppercase">{val.length} Chars // {val.split('\n').length} Lines</span>
                        </div>
                    </div>
                </motion.div>
            )}
        </AnimatePresence>
    );
};
