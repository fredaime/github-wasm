import http from 'http';
import express from 'express';
import cors from 'cors';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { promises as fs } from 'fs';
import os from 'os';
import { WebSocketServer } from 'ws';
import pty from 'node-pty';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = 3001;

app.use(cors());
app.use(express.json());

// Endpoint to check if the server is running
app.get('/', (req, res) => {
    res.send('Docker Terminal Backend is running.');
});

// --- BUILD ENDPOINT (STREAMING) ---
app.post('/build', async (req, res) => {
    const { dockerfile } = req.body;
    if (!dockerfile) {
        return res.status(400).send('Dockerfile content is required.');
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const sendEvent = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

    let buildDir;
    try {
        buildDir = await fs.mkdtemp(join(os.tmpdir(), 'docker-build-'));
        await fs.writeFile(join(buildDir, 'Dockerfile'), dockerfile);
        
        const imageTag = `docker-terminal-app:${Date.now()}`;
        const buildProcess = spawn('docker', ['build', '-t', imageTag, '.'], { cwd: buildDir });

        const handleData = (data) => {
            sendEvent({ type: 'log', content: data.toString() });
        };

        buildProcess.stdout.on('data', handleData);
        buildProcess.stderr.on('data', handleData);

        buildProcess.on('close', (code) => {
            if (code === 0) {
                sendEvent({ type: 'success', imageId: imageTag });
            } else {
                sendEvent({ type: 'error', content: `Build process exited with code ${code}` });
            }
            res.end();
            fs.rm(buildDir, { recursive: true, force: true });
        });

        buildProcess.on('error', (err) => {
           sendEvent({ type: 'error', content: `Failed to start build process: ${err.message}` });
           res.end();
           fs.rm(buildDir, { recursive: true, force: true });
        });

    } catch (error) {
        sendEvent({ type: 'error', content: `Server error: ${error.message}` });
        res.end();
        if (buildDir) {
           fs.rm(buildDir, { recursive: true, force: true });
        }
    }
});

const server = http.createServer(app);

// --- WEBSOCKET SERVER FOR RUNTIME ---
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
    let ptyProcess = null;

    ws.on('message', (message) => {
        try {
            const msgStr = message.toString();
            const data = JSON.parse(msgStr);

            if (data.type === 'run' && data.imageId) {
                if (ptyProcess) {
                    ptyProcess.kill();
                }

                const shell = 'sh';
                ptyProcess = pty.spawn('docker', ['run', '--rm', '-it', data.imageId, shell], {
                    name: 'xterm-color',
                    cols: 80,
                    rows: 30,
                    cwd: process.env.HOME,
                    env: process.env,
                });

                ptyProcess.onData((data) => {
                    ws.send(JSON.stringify({ type: 'log', content: data }));
                });
                
                ptyProcess.onExit(({ exitCode }) => {
                     ws.send(JSON.stringify({ type: 'exit', content: `Container exited with code ${exitCode}.` }));
                     ptyProcess = null;
                });

            } else if (data.type === 'command' && ptyProcess) {
                ptyProcess.write(data.command);
            }
        } catch(e) {
            ws.send(JSON.stringify({type: 'error', content: 'Invalid command from client.'}))
        }
    });

    ws.on('close', () => {
        if (ptyProcess) {
            ptyProcess.kill();
        }
    });
});

server.listen(port, () => {
    console.log(`Docker execution server listening on http://localhost:${port}`);
    console.log('Ensure Docker Desktop or Docker Engine is running.');
});
