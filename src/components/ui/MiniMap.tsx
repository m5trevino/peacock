import React from 'react';
import { motion } from 'framer-motion';
import { PipelineStage } from '../../types.ts';

interface MiniMapProps {
    telemetry: Record<string, any>;
    activeStageId: PipelineStage;
    pendingStageId: PipelineStage | null;
    setActiveStageId: (id: PipelineStage) => void;
}

const STAGES = [
    { id: PipelineStage.SPARK as PipelineStage, label: 'SPARK', color: '#FFD700', icon: '⚡' },
    { id: PipelineStage.FALCON as PipelineStage, label: 'FALCON', color: '#00FFFF', icon: '🦅' },
    { id: PipelineStage.EAGLE as PipelineStage, label: 'EAGLE', color: '#FF00FF', icon: '🦅' },
    { id: PipelineStage.OWL as PipelineStage, label: 'OWL', color: '#9D00FF', icon: '🦉' },
    { id: PipelineStage.HAWK as PipelineStage, label: 'HAWK', color: '#00FF41', icon: '🦅' },
];

const NODE_COORDS: Record<PipelineStage, { x: number, y: number }> = {
    [PipelineStage.SPARK]: { x: 150, y: 300 },
    [PipelineStage.FALCON]: { x: 350, y: 300 },
    [PipelineStage.EAGLE]: { x: 550, y: 300 },
    [PipelineStage.OWL]: { x: 750, y: 300 },
    [PipelineStage.HAWK]: { x: 950, y: 300 },
};

export const MiniMap: React.FC<MiniMapProps> = ({
    telemetry,
    activeStageId,
    pendingStageId,
    setActiveStageId
}) => {
    return (
        <div className="relative w-full h-full flex items-center justify-center p-20 bg-void/50 backdrop-blur-3xl overflow-hidden">
            {/* GRID BACKGROUND */}
            <div className="absolute inset-0 bg-[url('/assets/images/grid-dots.svg')] opacity-[0.05] pointer-events-none" />

            <svg className="absolute inset-0 w-full h-full pointer-events-none">
                {/* STATIC PATH LINES */}
                {STAGES.slice(0, -1).map((stage, i) => {
                    const start = NODE_COORDS[stage.id];
                    const end = NODE_COORDS[STAGES[i + 1].id];
                    return (
                        <line
                            key={`line-${stage.id}`}
                            x1={start.x}
                            y1={start.y}
                            x2={end.x}
                            y2={end.y}
                            stroke="rgba(255,255,255,0.05)"
                            strokeWidth="2"
                        />
                    );
                })}

                {/* HIGH-VOLTAGE SURGE ARC */}
                {pendingStageId && (
                    <motion.line
                        initial={{ pathLength: 0, opacity: 0 }}
                        animate={{ pathLength: 1, opacity: 1 }}
                        transition={{ duration: 1, repeat: Infinity, repeatDelay: 1 }}
                        x1={NODE_COORDS[activeStageId].x}
                        y1={NODE_COORDS[activeStageId].y}
                        x2={NODE_COORDS[pendingStageId].x}
                        y2={NODE_COORDS[pendingStageId].y}
                        stroke="#FFD700"
                        strokeWidth="4"
                        strokeLinecap="round"
                        filter="blur(2px)"
                        className="shadow-voltage-glow"
                    />
                )}
            </svg>

            {/* NODES */}
            <div className="relative z-10 flex gap-40">
                {STAGES.map((stage) => {
                    const status = telemetry[stage.id]?.status || 'idle';
                    const isActive = stage.id === activeStageId;
                    const isPending = stage.id === pendingStageId;
                    const isCompleted = status === 'success';

                    return (
                        <div
                            key={stage.id}
                            className="flex flex-col items-center gap-6"
                        >
                            <motion.button
                                onClick={() => setActiveStageId(stage.id)}
                                whileHover={{ scale: 1.1 }}
                                className={`
                                    w-32 h-32 rounded-[2rem] border-2 flex items-center justify-center relative transition-all duration-500
                                    ${isActive ? 'bg-void border-voltage shadow-[0_0_50px_var(--voltage-glow)]' :
                                        isPending ? 'bg-voltage/20 border-voltage animate-pulse shadow-[0_0_80px_var(--voltage-glow)] scale-110' :
                                            isCompleted ? 'bg-matrix/10 border-matrix shadow-[0_0_30px_var(--matrix-glow)]' :
                                                'bg-void/40 border-white/10 hover:border-white/30'}
                                `}
                            >
                                <span className={`text-4xl transition-all duration-500 ${isCompleted ? 'text-matrix' : isActive || isPending ? 'text-voltage' : 'text-white/20'}`}>
                                    {stage.icon}
                                </span>

                                {/* STATUS GLOW */}
                                {isCompleted && (
                                    <div className="absolute inset-0 rounded-[2rem] bg-matrix/5 blur-xl animate-pulse" />
                                )}
                                {isPending && (
                                    <div className="absolute inset-0 rounded-[2rem] bg-voltage/10 blur-2xl animate-ping" />
                                )}
                            </motion.button>

                            <div className="flex flex-col items-center gap-1">
                                <span className={`text-[12px] font-black tracking-[0.4em] uppercase transition-colors duration-500 ${isCompleted ? 'text-matrix' : isActive || isPending ? 'text-white' : 'text-white/20'}`}>
                                    {stage.label}
                                </span>
                                {isPending ? (
                                    <span className="text-[10px] text-voltage font-black animate-pulse tracking-widest italic">READY_FOR_SURGE</span>
                                ) : (
                                    <span className={`text-[8px] font-mono tracking-tighter uppercase transition-colors duration-500 ${isCompleted ? 'text-matrix/50' : 'text-white/10'}`}>
                                        {status.toUpperCase()}
                                    </span>
                                )}
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* SCANLINE OVERLAY */}
            <div className="absolute inset-0 pointer-events-none opacity-[0.03] scanline" />
        </div>
    );
};
