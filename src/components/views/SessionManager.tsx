import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { db, Session } from '../../services/db';
import { audioService } from '../../services/audioService';

interface SessionManagerProps {
    isOpen: boolean;
    onClose: () => void;
    currentSessionId: number | null;
    onLoadSession: (session: Session) => void;
    onNewSession: () => void;
}

export const SessionManager: React.FC<SessionManagerProps> = ({
    isOpen, onClose, currentSessionId, onLoadSession, onNewSession
}) => {
    const [sessions, setSessions] = useState<Session[]>([]);

    useEffect(() => {
        if (isOpen) {
            loadSessions();
        }
    }, [isOpen]);

    const loadSessions = async () => {
        const all = await db.sessions.orderBy('lastUpdated').reverse().toArray();
        setSessions(all);
    };

    const handleDelete = async (id: number, e: React.MouseEvent) => {
        e.stopPropagation();
        if (confirm('AUTHORIZATION REQUIRED: CONFIRM PURGE?')) {
            await db.sessions.delete(id);
            await db.logs.where('sessionId').equals(id).delete();
            audioService.playError(); // Destruction sound
            loadSessions();
        }
    };

    return (
        <AnimatePresence>
            {isOpen && (
                <div className="fixed inset-0 z-[200] bg-black/80 backdrop-blur-md flex justify-end">
                    <motion.div
                        initial={{ x: '100%' }}
                        animate={{ x: 0 }}
                        exit={{ x: '100%' }}
                        className="w-96 h-full bg-[#0A0B0D] border-l border-white/10 flex flex-col shadow-2xl"
                    >
                        <div className="p-6 border-b border-white/10 flex justify-between items-center bg-white/5">
                            <h2 className="text-xl font-black italic text-white tracking-tight uppercase">TIMELINE</h2>
                            <button onClick={onClose} className="text-muted hover:text-white transition-colors">✕</button>
                        </div>

                        <div className="p-6 border-b border-white/5">
                            <button
                                onClick={() => { onNewSession(); onClose(); }}
                                className="w-full py-4 bg-void border border-matrix/30 text-matrix font-black uppercase tracking-widest hover:bg-matrix/10 hover:shadow-[0_0_20px_rgba(0,255,65,0.1)] transition-all rounded-xl"
                            >
                                + NEW_OPERATION
                            </button>
                        </div>

                        <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-4 custom-scrollbar">
                            {sessions.map(s => (
                                <div
                                    key={s.id}
                                    onClick={() => { onLoadSession(s); onClose(); }}
                                    className={`p-4 rounded-xl border transition-all cursor-pointer group relative ${s.id === currentSessionId ? 'bg-white/10 border-white/30 shadow-lg' : 'bg-void border-white/5 hover:border-white/20'}`}
                                >
                                    <div className="flex justify-between items-start mb-2">
                                        <span className="text-[10px] font-bold text-muted uppercase tracking-widest">OP_ID: {s.id}</span>
                                        <button onClick={(e) => handleDelete(s.id!, e)} className="text-[10px] text-error opacity-0 group-hover:opacity-100 transition-opacity hover:underline">PURGE</button>
                                    </div>
                                    <h4 className="text-sm font-bold text-white mb-1 truncate">{s.name || 'Unknown Operation'}</h4>
                                    <span className="text-[10px] font-mono text-white/30">
                                        {new Date(s.lastUpdated).toLocaleString()}
                                    </span>

                                    {s.id === currentSessionId && (
                                        <div className="absolute right-4 bottom-4 w-2 h-2 bg-matrix rounded-full animate-pulse shadow-[0_0_10px_#00FF41]" />
                                    )}
                                </div>
                            ))}

                            {sessions.length === 0 && (
                                <div className="text-center py-10 text-white/20 text-xs font-mono italic">
                                    // NO_TIMELINE_DATA
                                </div>
                            )}
                        </div>
                    </motion.div>
                </div>
            )}
        </AnimatePresence>
    );
};
