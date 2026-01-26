import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ModelConfig } from '../../types';

interface TacticalDropdownProps {
    value: string;
    options: ModelConfig[];
    onChange: (v: string) => void;
    label: string;
}

export const TacticalDropdown: React.FC<TacticalDropdownProps> = ({ value, options, onChange, label }) => {
    const [isOpen, setIsOpen] = useState(false);
    const containerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const clickOutside = (e: MouseEvent) => {
            if (containerRef.current && !containerRef.current.contains(e.target as Node)) setIsOpen(false);
        };
        document.addEventListener('mousedown', clickOutside);
        return () => document.removeEventListener('mousedown', clickOutside);
    }, []);

    return (
        <div className="relative w-full" ref={containerRef}>
            <span className="text-[8px] font-black text-muted uppercase tracking-[0.3em] mb-2 block pl-1">{label}</span>
            <button onClick={() => setIsOpen(!isOpen)} className="w-full bg-void border border-white/5 rounded-lg p-3 text-[10px] mono text-white font-black uppercase flex justify-between items-center hover:border-voltage transition-all shadow-inner">
                <span className="truncate">{value.toUpperCase()}</span>
                <span className={`transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`}>▼</span>
            </button>
            <AnimatePresence>
                {isOpen && (
                    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 5 }} className="absolute bottom-full left-0 w-full mb-2 bg-elevated border border-white/10 rounded-xl overflow-hidden shadow-[0_20px_50px_rgba(0,0,0,0.8)] z-[200] max-h-64 overflow-y-auto custom-scrollbar">
                        {options.map(opt => (
                            <button key={opt.id} onClick={() => { onChange(opt.id); setIsOpen(false); }} className={`w-full text-left px-4 py-3 text-[9px] mono font-bold uppercase transition-all flex justify-between items-center border-b border-white/5 hover:bg-matrix/10 hover:text-matrix ${value === opt.id ? 'text-matrix bg-matrix/5' : 'text-white/60'}`}>
                                <span>{opt.id.toUpperCase()}</span>
                                {value === opt.id && <span className="text-matrix">●</span>}
                            </button>
                        ))}
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};
