import React, { useState, useEffect } from 'react';
import { PipelineStage } from '../../types';

interface FooterConsoleProps {
    inputs: Record<string, string>;
    outputs: Record<string, string>;
    activeStageId: PipelineStage;
    height: number;
    setHeight: (h: number) => void;
}

export const FooterConsole: React.FC<FooterConsoleProps> = ({ inputs, outputs, activeStageId, height, setHeight }) => {
    const [isDragging, setIsDragging] = useState(false);

    useEffect(() => {
        const move = (e: MouseEvent) => { if (isDragging) setHeight(Math.max(40, window.innerHeight - e.clientY)); };
        const up = () => setIsDragging(false);
        window.addEventListener('mousemove', move);
        window.addEventListener('mouseup', up);
        return () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up); };
    }, [isDragging, setHeight]);

    return (
        <footer className="bg-void border-t border-white/10 relative scanlines overflow-hidden shadow-[0_-10px_40px_rgba(0,0,0,0.8)]" style={{ height }}>
            <div
                className="h-1 w-full bg-white/5 hover:bg-matrix cursor-ns-resize transition-colors"
                onMouseDown={() => setIsDragging(true)}
            />
            <div className="flex h-full divide-x divide-white/10">
                <div className="w-1/2 flex flex-col">
                    <div className="h-10 bg-surface/80 px-6 flex items-center border-b border-white/10 backdrop-blur-md">
                        <span className="text-[10px] font-black uppercase tracking-widest text-muted">Outbound // Wrapped_Payload</span>
                    </div>
                    <div className="flex-1 p-6 overflow-y-auto text-xs text-white/50 whitespace-pre-wrap font-mono leading-relaxed custom-scrollbar">
                        {inputs[activeStageId] || <span className="opacity-20 italic">Awaiting input...</span>}
                    </div>
                </div>
                <div className="w-1/2 flex flex-col bg-matrix/[0.02]">
                    <div className="h-10 bg-surface/80 px-6 flex items-center border-b border-white/10 backdrop-blur-md justify-between">
                        <span className="text-[10px] font-black uppercase tracking-widest text-matrix animate-pulse">Inbound // Token_Waterfall</span>
                        <span className="text-[9px] font-bold text-matrix/50">{outputs[activeStageId]?.length || 0} TOKENS</span>
                    </div>
                    <div className="flex-1 p-6 overflow-y-auto text-xs text-matrix/80 whitespace-pre-wrap font-mono leading-relaxed custom-scrollbar">
                        {outputs[activeStageId] || <span className="opacity-20 italic">Awaiting response...</span>}
                    </div>
                </div>
            </div>
        </footer>
    );
};
