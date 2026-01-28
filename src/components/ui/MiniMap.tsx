import React, { useMemo } from 'react';
import { STAGES, THEME } from '../../config/constants';
import { PipelineStage, CallTelemetry } from '../../types';
import { motion } from 'framer-motion';

interface MiniMapProps {
    telemetry: Record<string, CallTelemetry>;
    activeStageId: PipelineStage;
    setActiveStageId: (id: PipelineStage) => void;
}

export const MiniMap: React.FC<MiniMapProps> = ({ telemetry, activeStageId, setActiveStageId }) => {
    // Determine the furthest progress
    const furthestStageIndex = useMemo(() => {
        let maxIdx = 0;
        STAGES.forEach((s, i) => {
            if (telemetry[s.id]?.status === 'success') maxIdx = i + 1;
        });
        return Math.min(maxIdx, STAGES.length - 1);
    }, [telemetry]);

    return (
        <div className="relative w-full max-w-4xl h-48 flex items-center justify-between px-12 mt-10">
            {/* SVG Layer for Connecting Lines */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none overflow-visible">
                {STAGES.map((s, i) => {
                    if (i === STAGES.length - 1) return null;
                    const isCompleted = telemetry[s.id]?.status === 'success';
                    return (
                        <motion.line
                            key={`line-${s.id}`}
                            x1={`${(i / (STAGES.length - 1)) * 100}%`}
                            y1="50%"
                            x2={`${((i + 1) / (STAGES.length - 1)) * 100}%`}
                            y2="50%"
                            stroke={isCompleted ? THEME.matrix : "rgba(255,255,255,0.05)"}
                            strokeWidth="2"
                            strokeDasharray="4 4"
                            initial={{ pathLength: 0 }}
                            animate={{ pathLength: isCompleted ? 1 : 0 }}
                            transition={{ duration: 1.5, ease: "easeInOut" }}
                        />
                    );
                })}
            </svg>

            {/* Nodes Layer */}
            {STAGES.map((s, i) => {
                const isSuccess = telemetry[s.id]?.status === 'success';
                const isActive = activeStageId === s.id;
                const isAvailable = i <= furthestStageIndex;
                const isSparkBoot = s.id === PipelineStage.SPARK && !isSuccess && !isActive;

                // Tactical color logic
                let nodeColor = "rgba(255, 255, 255, 0.05)";
                if (isSuccess) nodeColor = THEME.matrix;
                else if (isActive) nodeColor = THEME.voltage;
                else if (s.id === PipelineStage.SPARK && isAvailable) nodeColor = THEME.voltage;

                return (
                    <div
                        key={s.id}
                        onClick={() => setActiveStageId(s.id)}
                        className={`relative z-10 flex flex-col items-center gap-4 cursor-pointer transition-all duration-500 ${!isAvailable ? 'opacity-20 grayscale cursor-not-allowed' : 'opacity-100 hover:scale-110'}`}
                    >
                        {/* THE NODE */}
                        <motion.div
                            className={`w-14 h-14 rounded-2xl border-2 flex items-center justify-center transition-all duration-700 bg-void/80 backdrop-blur-md ${isSparkBoot ? 'pulse-voltage border-voltage' : isSuccess ? 'border-matrix shadow-[0_0_20px_var(--matrix-glow)]' : isActive ? 'border-voltage shadow-[0_0_15px_var(--voltage-glow)]' : 'border-white/10'}`}
                            animate={isSparkBoot ? { scale: [1, 1.1, 1] } : {}}
                            transition={isSparkBoot ? { repeat: Infinity, duration: 2 } : {}}
                        >
                            <span className={`text-2xl transition-all ${isSuccess ? 'text-matrix' : isActive ? 'text-voltage' : 'text-white/20'}`}>
                                {s.icon}
                            </span>
                        </motion.div>

                        {/* LABEL */}
                        <div className="flex flex-col items-center">
                            <span className={`text-[8px] font-black tracking-[0.3em] uppercase transition-all ${isSuccess ? 'text-matrix' : isActive ? 'text-voltage' : 'text-muted'}`}>
                                {s.label}
                            </span>
                            {isSuccess && (
                                <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-[6px] font-bold text-matrix/50 tracking-tighter mt-1">COMPLETED_ASSET</motion.span>
                            )}
                        </div>

                        {/* ACTIVE GLOW ORB */}
                        {isActive && (
                            <div className="absolute -top-1 left-1/2 -translate-x-1/2 w-8 h-1 bg-voltage shadow-[0_0_10px_var(--voltage-glow)] rounded-full" />
                        )}
                    </div>
                );
            })}
        </div>
    );
};
