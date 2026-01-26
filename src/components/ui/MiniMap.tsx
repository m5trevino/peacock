import React from 'react';
import { STAGES } from '../../config/constants';
import { PipelineStage, CallTelemetry } from '../../types';

interface MiniMapProps {
    telemetry: Record<string, CallTelemetry>;
    activeStageId: PipelineStage;
    setActiveStageId: (id: PipelineStage) => void;
}

export const MiniMap: React.FC<MiniMapProps> = ({ telemetry, activeStageId, setActiveStageId }) => {
    return (
        <div className="w-full h-20 bg-void border-b border-white/5 flex items-center justify-center gap-16">
            {STAGES.map((s) => {
                const done = telemetry[s.id]?.status === 'success';
                const active = activeStageId === s.id;
                return (
                    <div key={s.id} onClick={() => setActiveStageId(s.id)} className="flex flex-col items-center gap-2 cursor-pointer group">
                        <div className={`w-8 h-8 border transition-all duration-500 ${done ? 'bg-matrix border-white shadow-[0_0_20px_#00FF41] rounded-sm' : active ? 'bg-void border-voltage shadow-[0_0_10px_#FFD700] rounded-lg' : 'bg-white/5 border-white/10 rounded-lg'}`} />
                        <span className={`text-[7px] font-black tracking-widest uppercase ${done ? 'text-matrix' : active ? 'text-voltage' : 'text-muted'}`}>{s.label}</span>
                    </div>
                );
            })}
        </div>
    );
};
