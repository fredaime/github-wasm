import React, { useState, useRef, useEffect, useCallback } from 'react';
import { ContainerStatus, LogType } from '../types';
import type { LogEntry } from '../types';

const PlayIcon = () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>;
const BuildIcon = () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>;
const StopIcon = () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect></svg>;
const SpinnerIcon = () => <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>;

const initialDockerfile = `
# Use a small, alpine-based image
FROM alpine:latest

# Install a shell and some common tools
RUN apk add --no-cache bash curl

# Set the working directory
WORKDIR /app

# A simple command to show it's working
CMD ["echo", "Hello from the real Docker container! Run 'bash' for an interactive shell."]
`.trim();

const BACKEND_URL = 'http://localhost:3001';
const WS_URL = 'ws://localhost:3001';

export default function DockerTerminal() {
    const [dockerfile, setDockerfile] = useState<string>(initialDockerfile);
    const [status, setStatus] = useState<ContainerStatus>(ContainerStatus.IDLE);
    const [imageId, setImageId] = useState<string | null>(null);
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [command, setCommand] = useState<string>('');
    const [isProcessingCommand, setIsProcessingCommand] = useState<boolean>(false);
    
    const terminalEndRef = useRef<HTMLDivElement>(null);
    const ws = useRef<WebSocket | null>(null);

    const addLog = useCallback((content: string, type: LogType) => {
        const timestamp = new Date().toLocaleTimeString();
        // Don't add timestamp to raw terminal output
        const logTypeForTimestamp = type === LogType.OUTPUT ? '' : timestamp;
        setLogs(prev => [...prev, { content, type, timestamp: logTypeForTimestamp }]);
    }, []);

    useEffect(() => {
        terminalEndRef.current?.scrollIntoView({ behavior: 'auto' });
    }, [logs]);
    
    // Cleanup WebSocket on unmount
    useEffect(() => {
        return () => {
            ws.current?.close();
        };
    }, []);

    const handleBuild = useCallback(async () => {
        setStatus(ContainerStatus.BUILDING);
        setImageId(null);
        setLogs([]);
        addLog("Connecting to build server...", LogType.SYSTEM);

        try {
            const response = await fetch(`${BACKEND_URL}/build`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ dockerfile }),
            });

            if (!response.body) throw new Error("Response has no body");

            const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
            
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                // Process server-sent events
                const lines = value.split('\n\n');
                for (const line of lines) {
                    if (line.startsWith('data:')) {
                        try {
                            const data = JSON.parse(line.substring(5));
                            if (data.type === 'log') {
                                addLog(data.content, LogType.OUTPUT);
                            } else if (data.type === 'success') {
                                addLog(`Successfully built image: ${data.imageId}`, LogType.SUCCESS);
                                setImageId(data.imageId);
                                setStatus(ContainerStatus.BUILD_SUCCESS);
                            } else if (data.type === 'error') {
                                addLog(data.content, LogType.ERROR);
                                setStatus(ContainerStatus.ERROR);
                            }
                        } catch(e) {
                            // Ignore parsing errors for incomplete stream data
                        }
                    }
                }
            }
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            addLog(`Build failed: Could not connect to backend. Is it running?`, LogType.ERROR);
            setStatus(ContainerStatus.ERROR);
        }
    }, [dockerfile, addLog]);

    const handleRun = useCallback(() => {
        if (!imageId) return;

        setStatus(ContainerStatus.RUNNING);
        setLogs([]); // Clear build logs for clean terminal
        addLog(`Starting container for image ${imageId}...`, LogType.SYSTEM);

        ws.current = new WebSocket(WS_URL);
        ws.current.onopen = () => {
            addLog("WebSocket connected. Initializing container...", LogType.SUCCESS);
            ws.current?.send(JSON.stringify({ type: 'run', imageId }));
        };
        ws.current.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.type === 'log') {
                    addLog(data.content, LogType.OUTPUT);
                } else if(data.type === 'exit') {
                    addLog(data.content, LogType.SYSTEM);
                    setStatus(ContainerStatus.BUILD_SUCCESS);
                    ws.current?.close();
                    ws.current = null;
                }
            } catch(e) {
                addLog('Received malformed data from server.', LogType.ERROR);
            }
        };
        ws.current.onerror = (event) => {
            addLog(`WebSocket error. Is the backend server running?`, LogType.ERROR);
            setStatus(ContainerStatus.ERROR);
        };
        ws.current.onclose = () => {
            if (status === ContainerStatus.RUNNING) { // Only show if not stopped manually
                addLog("WebSocket disconnected.", LogType.SYSTEM);
                setStatus(ContainerStatus.BUILD_SUCCESS);
            }
        };
    }, [imageId, addLog, status]);

    const handleStop = useCallback(() => {
        ws.current?.close();
        ws.current = null;
        addLog("Container stopped by user.", LogType.SYSTEM);
        setStatus(ContainerStatus.BUILD_SUCCESS);
    }, []);
    
    const handleCommandSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!command.trim() || !ws.current || ws.current.readyState !== WebSocket.OPEN) return;
        
        ws.current.send(JSON.stringify({ type: 'command', command: command + '\n' }));
        setCommand('');
    };

    const isBuilding = status === ContainerStatus.BUILDING;
    const isRunning = status === ContainerStatus.RUNNING;
    const isIdle = status === ContainerStatus.IDLE || status === ContainerStatus.ERROR;
    const canRun = status === ContainerStatus.BUILD_SUCCESS;

    return (
        <div className="w-full max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6 h-[720px]">
            {/* Control Panel */}
            <div className="bg-gray-800 rounded-lg shadow-lg p-5 flex flex-col gap-4">
                <h2 className="text-xl font-semibold text-gray-200 border-b border-gray-700 pb-2">Control Panel</h2>
                <div className="flex space-x-2">
                    <button onClick={handleBuild} disabled={isBuilding || isRunning} className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md font-semibold hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors">
                        <BuildIcon /> {isBuilding ? 'Building...' : 'Build Image'}
                    </button>
                    <button onClick={handleRun} disabled={!canRun} className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2 bg-green-600 text-white rounded-md font-semibold hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors">
                        <PlayIcon /> Run
                    </button>
                     <button onClick={handleStop} disabled={!isRunning} className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2 bg-red-600 text-white rounded-md font-semibold hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors">
                        <StopIcon /> Stop
                    </button>
                </div>

                <div className="flex flex-col flex-grow min-h-0">
                    <label htmlFor="dockerfile" className="block text-sm font-medium text-gray-300 mb-1">Dockerfile</label>
                    <textarea 
                        id="dockerfile"
                        value={dockerfile}
                        onChange={(e) => setDockerfile(e.target.value)}
                        disabled={isBuilding || isRunning}
                        className="w-full flex-grow p-3 font-mono text-sm bg-gray-900 text-gray-300 border border-gray-700 rounded-md focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 transition-colors disabled:bg-gray-700"
                        spellCheck="false"
                    />
                </div>
            </div>

            {/* Terminal */}
            <div className="lg:col-span-2 bg-black rounded-lg shadow-lg flex flex-col h-full">
                <div className="bg-gray-800 p-3 border-b border-gray-700 rounded-t-lg">
                    <h2 className="text-xl font-semibold text-gray-200">Terminal</h2>
                </div>
                <div className="flex-grow min-h-0 p-4 overflow-y-auto font-mono text-sm leading-6 whitespace-pre-wrap">
                     {logs.map((log, index) => {
                        let colorClass = 'text-gray-300';
                        if (log.type === LogType.INPUT) colorClass = 'text-green-400';
                        if (log.type === LogType.SYSTEM) colorClass = 'text-yellow-400';
                        if (log.type === LogType.ERROR) colorClass = 'text-red-400';
                        if (log.type === LogType.SUCCESS) colorClass = 'text-cyan-400';
                        
                        return log.type === LogType.OUTPUT ? (
                            <span key={index} className={colorClass}>{log.content}</span>
                        ) : (
                             <div key={index}>
                                <span className="text-gray-500 mr-2">{log.timestamp}</span>
                                <span className={colorClass}>{log.content}</span>
                            </div>
                        );
                    })}
                    <div ref={terminalEndRef}></div>
                </div>
                <div className="p-2 border-t border-gray-700">
                    <form onSubmit={handleCommandSubmit} className="flex items-center gap-2">
                        <span className="text-green-400 font-bold">{'>'}</span>
                        <input
                            type="text"
                            value={command}
                            onChange={(e) => setCommand(e.target.value)}
                            disabled={!isRunning || isProcessingCommand}
                            className="flex-1 bg-transparent text-gray-200 font-mono focus:outline-none"
                            placeholder={isRunning ? "Enter a command and press Enter..." : "Start a container to run commands"}
                            autoFocus
                        />
                         {isProcessingCommand && <SpinnerIcon />}
                    </form>
                </div>
            </div>
        </div>
    );
}