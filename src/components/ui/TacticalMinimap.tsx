import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface TacticalMinimapProps {
    label: string;
    content: string;
    type: 'input' | 'output';
    color: string;
    onExpand: () => void;
}

export const TacticalMinimap: React.FC<TacticalMinimapProps> = ({
    label, content, type, color, onExpand
}) => {
    const isOutput = type === 'output';

    return (
        <div className="flex flex-col gap-2 w-full group">
            <div className="flex justify-between items-center px-1">
                <span className="text-[9px] font-black uppercase tracking-widest text-muted group-hover:text-white transition-colors">
                    {label}
                </span>
                <span className="text-[9px] font-mono text-muted/50">
                    {content?.length || 0} chars
                </span>
            </div>

            <button
                onClick={onExpand}
                className={`relative w-full h-32 rounded-xl border border-white/5 bg-surface/50 overflow-hidden text-left transition-all hover:border-opacity-50 hover:shadow-lg group-hover:border-${isOutput ? 'matrix' : 'white'}/20`}
                style={{ borderColor: isOutput ? undefined : undefined }}
            >
                {/* Mini-map Content */}
                <div className="absolute inset-0 p-3 opacity-50 group-hover:opacity-80 transition-opacity">
                    <pre className="text-[6px] leading-[8px] font-mono text-muted/70 whitespace-pre-wrap overflow-hidden h-full pointer-events-none select-none">
                        {content || "// NO DATA STREAM"}
                    </pre>
                </div>

                {/* Hover Overlay */}
                <div className="absolute inset-0 bg-gradient-to-t from-black/80 to-transparent opacity-0 group-hover:opacity-100 transition-opacity flex items-end justify-center pb-3">
                    <span className="text-[10px] font-bold uppercase tracking-widest text-white border border-white/20 px-3 py-1 rounded-full bg-black/50 backdrop-blur-sm">
                        EXPAND VIEW
                    </span>
                </div>

                {/* Status Indicator */}
                <div className={`absolute top-2 right-2 w-1.5 h-1.5 rounded-full ${content ? 'bg-' + (isOutput ? 'matrix' : 'white') : 'bg-white/10'}`} />
            </button>
        </div>
    );
};
