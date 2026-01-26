import React, { useEffect, useState } from 'react';
import { api } from '../services/api';

export const SystemDiagnostics: React.FC = () => {
    const [status, setStatus] = useState<'checking' | 'online' | 'offline'>('checking');

    useEffect(() => {
        const check = async () => {
            const isAlive = await api.checkHealth();
            setStatus(isAlive ? 'online' : 'offline');
        };

        check();
        const interval = setInterval(check, 30000); // Poll every 30s
        return () => clearInterval(interval);
    }, []);

    return (
        <div className={`flex items-center space-x-2 text-xs font-mono border px-2 py-1 rounded ${status === 'online' ? 'border-green-900 bg-green-900/10 text-green-400' :
                status === 'offline' ? 'border-red-900 bg-red-900/10 text-red-400' :
                    'border-gray-800 text-gray-500'
            }`}>
            <div className={`w-2 h-2 rounded-full ${status === 'online' ? 'bg-green-500 animate-pulse' :
                    status === 'offline' ? 'bg-red-500' : 'bg-gray-500'
                }`} />
            <span>
                ENGINE: {status.toUpperCase()}
                {status === 'online' && ' [PORT:3099]'}
            </span>
        </div>
    );
};
