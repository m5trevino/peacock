import Dexie, { Table } from 'dexie';

export interface StrikeLog {
    id?: number;
    timestamp: number;
    modelId: string;
    prompt: string;
    response: string;
    latency?: number;
    status: 'success' | 'error';
    sessionId?: number;
}

export interface Session {
    id?: number;
    name: string;
    timestamp: number;
    lastUpdated: number;
    data: string; // JSON snapshot of full state
}

class PeacockDB extends Dexie {
    logs!: Table<StrikeLog>;
    sessions!: Table<Session>;

    constructor() {
        super('PeacockDB_V21');
        this.version(1).stores({
            logs: '++id, timestamp, modelId, status'
        });

        this.version(2).stores({
            logs: '++id, timestamp, modelId, status, sessionId',
            sessions: '++id, timestamp, lastUpdated'
        });
    }
}

export const db = new PeacockDB();
