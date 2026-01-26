import React from 'react';
import { motion } from 'framer-motion';

interface VUMeterProps {
    value: number;
    label: string;
}

export const VUMeter: React.FC<VUMeterProps> = ({ value, label }) => {
    const segments = 20;
    const activeSegments = Math.floor((value / 100) * segments);
    const isRedlining = value > 85;
    return (
        <div className="flex flex-col gap-2 w-full">
            <div className="flex justify-between text-[7px] font-black text-muted uppercase tracking-widest">
                <span>{label}</span>
                <span className={isRedlining ? 'text-error animate-pulse' : 'text-matrix'}>{value}%</span>
            </div>
            <div className="flex gap-[2px] h-4 w-full">
                {Array.from({ length: segments }).map((_, i) => (
                    <motion.div key={i} animate={i < activeSegments && isRedlining ? { x: [0, -1, 1, 0] } : {}} transition={{ repeat: Infinity, duration: 0.1 }}
                        className={`flex-1 rounded-sm transition-all duration-300 ${i >= activeSegments ? 'bg-white/5' : i > segments * 0.85 ? 'bg-error shadow-[0_0_10px_#FF3131]' : i > segments * 0.6 ? 'bg-voltage shadow-[0_0_10px_#FFD700]' : 'bg-matrix shadow-[0_0_10px_#00FF41]'}`}
                    />
                ))}
            </div>
        </div>
    );
};
