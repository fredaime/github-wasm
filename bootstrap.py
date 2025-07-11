#!/usr/bin/env python3
"""
Docker Terminal Application - One-Shot Configuration Script
This script will install, configure, and set up the complete environment
"""

import os
import sys
import subprocess
import json
import shutil
import platform
import argparse
import secrets
import pwd
import grp
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class DockerTerminalSetup:
    def __init__(self, install_dir: str = "/opt/docker-terminal",
                 port: int = 3000, backend_port: int = 3001):
        self.install_dir = Path(install_dir)
        self.port = port
        self.backend_port = backend_port
        self.app_user = "dockerterm"
        self.app_group = "dockerterm"
        self.node_version = "20"
        self.config = {
            "jwt_secret": secrets.token_hex(32),
            "session_secret": secrets.token_hex(32),
            "allowed_images": ["alpine", "ubuntu", "node", "python", "nginx"],
            "max_containers_per_user": 5,
            "container_timeout_minutes": 30
        }

    def log(self, message: str, level: str = "info"):
        """Colored logging output"""
        colors = {
            "info": Colors.OKBLUE,
            "success": Colors.OKGREEN,
            "warning": Colors.WARNING,
            "error": Colors.FAIL,
            "header": Colors.HEADER
        }
        color = colors.get(level, Colors.ENDC)
        print(f"{color}[{level.upper()}] {message}{Colors.ENDC}")

    def run_command(self, cmd: List[str], check: bool = True,
                    capture_output: bool = False) -> subprocess.CompletedProcess:
        """Execute shell command with error handling"""
        try:
            result = subprocess.run(cmd, check=check, capture_output=capture_output,
                                    text=True)
            return result
        except subprocess.CalledProcessError as e:
            self.log(f"Command failed: {' '.join(cmd)}", "error")
            self.log(f"Error: {e}", "error")
            if capture_output and e.stderr:
                self.log(f"stderr: {e.stderr}", "error")
            sys.exit(1)

    def check_system_requirements(self):
        """Check if system meets requirements"""
        self.log("Checking system requirements...", "header")

        # Check OS
        if platform.system() != "Linux":
            self.log("This script is designed for Linux systems only", "error")
            sys.exit(1)

        # Check if running as root
        if os.geteuid() != 0:
            self.log("This script must be run as root", "error")
            sys.exit(1)

        # Check distribution
        if os.path.exists("/etc/debian_version"):
            self.distro = "debian"
        elif os.path.exists("/etc/redhat-release"):
            self.distro = "redhat"
        else:
            self.log("Unsupported distribution. Supports Debian/Ubuntu and RHEL/CentOS", "error")
            sys.exit(1)

        self.log(f"Detected {self.distro}-based system", "success")

    def install_docker(self):
        """Install Docker if not present"""
        self.log("Checking Docker installation...", "header")

        if shutil.which("docker"):
            self.log("Docker is already installed", "success")
            return

        self.log("Installing Docker...", "info")

        if self.distro == "debian":
            # Update package index
            self.run_command(["apt-get", "update"])

            # Install prerequisites
            self.run_command([
                "apt-get", "install", "-y",
                "apt-transport-https", "ca-certificates",
                "curl", "gnupg", "lsb-release"
            ])

            # Add Docker's official GPG key
            self.run_command([
                "sh", "-c",
                "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg"
            ])

            # Set up repository
            self.run_command([
                "sh", "-c",
                'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null'
            ])

            # Install Docker
            self.run_command(["apt-get", "update"])
            self.run_command(["apt-get", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io"])

        else:  # redhat
            self.run_command(["yum", "install", "-y", "yum-utils"])
            self.run_command([
                "yum-config-manager", "--add-repo",
                "https://download.docker.com/linux/centos/docker-ce.repo"
            ])
            self.run_command(["yum", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io"])

        # Start Docker
        self.run_command(["systemctl", "start", "docker"])
        self.run_command(["systemctl", "enable", "docker"])

        self.log("Docker installed successfully", "success")

    def install_nodejs(self):
        """Install Node.js if not present"""
        self.log("Checking Node.js installation...", "header")

        # Check if correct version is installed
        if shutil.which("node"):
            result = self.run_command(["node", "--version"], capture_output=True)
            version = result.stdout.strip()
            if version.startswith(f"v{self.node_version}"):
                self.log(f"Node.js {version} is already installed", "success")
                return

        self.log(f"Installing Node.js {self.node_version}...", "info")

        # Install NodeSource repository
        if self.distro == "debian":
            self.run_command([
                "curl", "-fsSL",
                f"https://deb.nodesource.com/setup_{self.node_version}.x",
                "-o", "/tmp/nodesource_setup.sh"
            ])
            self.run_command(["bash", "/tmp/nodesource_setup.sh"])
            self.run_command(["apt-get", "install", "-y", "nodejs"])
        else:  # redhat
            self.run_command([
                "curl", "-fsSL",
                f"https://rpm.nodesource.com/setup_{self.node_version}.x",
                "-o", "/tmp/nodesource_setup.sh"
            ])
            self.run_command(["bash", "/tmp/nodesource_setup.sh"])
            self.run_command(["yum", "install", "-y", "nodejs"])

        # Install build tools for native modules
        if self.distro == "debian":
            self.run_command(["apt-get", "install", "-y", "build-essential", "python3"])
        else:
            self.run_command(["yum", "groupinstall", "-y", "Development Tools"])
            self.run_command(["yum", "install", "-y", "python3"])

        self.log("Node.js installed successfully", "success")

    def create_app_user(self):
        """Create dedicated user for the application"""
        self.log("Creating application user...", "header")

        try:
            pwd.getpwnam(self.app_user)
            self.log(f"User {self.app_user} already exists", "success")
        except KeyError:
            self.run_command(["groupadd", "-r", self.app_group])
            self.run_command([
                "useradd", "-r", "-g", self.app_group,
                "-s", "/bin/false", "-d", str(self.install_dir),
                "-c", "Docker Terminal Application", self.app_user
            ])
            # Add user to docker group
            self.run_command(["usermod", "-aG", "docker", self.app_user])
            self.log(f"Created user {self.app_user}", "success")

    def setup_application_files(self):
        """Create enhanced application files"""
        self.log("Setting up application files...", "header")

        # Create directory structure
        dirs = [
            self.install_dir,
            self.install_dir / "frontend",
            self.install_dir / "frontend/components",
            self.install_dir / "frontend/services",
            self.install_dir / "backend",
            self.install_dir / "backend/src",
            self.install_dir / "backend/src/middleware",
            self.install_dir / "backend/src/utils",
            self.install_dir / "logs",
            self.install_dir / "config"
        ]

        for dir_path in dirs:
            dir_path.mkdir(parents=True, exist_ok=True)

        # Create enhanced backend files
        self._create_enhanced_backend()
        self._create_enhanced_frontend()
        self._create_config_files()

        # Set permissions
        self.run_command(["chown", "-R", f"{self.app_user}:{self.app_group}",
                          str(self.install_dir)])
        self.run_command(["chmod", "-R", "750", str(self.install_dir)])
        self.run_command(["chmod", "-R", "770", str(self.install_dir / "logs")])

        self.log("Application files created", "success")

    def _create_enhanced_backend(self):
        """Create enhanced backend with security and monitoring"""

        # Main server file with security enhancements
        server_content = '''import http from 'http';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import winston from 'winston';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { promises as fs } from 'fs';
import os from 'os';
import { WebSocketServer } from 'ws';
import pty from 'node-pty';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load configuration
const config = JSON.parse(await fs.readFile('/opt/docker-terminal/config/app.json', 'utf8'));

// Setup logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: '/opt/docker-terminal/logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: '/opt/docker-terminal/logs/combined.log' }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

const app = express();
const port = config.backend_port || 3001;

// Security middleware
app.use(helmet());
app.use(cors({
    origin: [`http://localhost:${config.frontend_port}`, `http://${config.hostname}:${config.frontend_port}`],
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Build rate limiter (more restrictive)
const buildLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10 // limit each IP to 10 builds per hour
});

app.use(express.json({ limit: '1mb' }));

// Container tracking
const activeContainers = new Map();
const userContainers = new Map();

// Cleanup old containers periodically
setInterval(() => {
    const now = Date.now();
    for (const [containerId, data] of activeContainers.entries()) {
        if (now - data.startTime > config.container_timeout_minutes * 60 * 1000) {
            logger.info(`Stopping expired container: ${containerId}`);
            spawn('docker', ['stop', containerId]);
            activeContainers.delete(containerId);
        }
    }
}, 60000); // Check every minute

// Authentication middleware
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, config.jwt_secret);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        uptime: process.uptime(),
        activeContainers: activeContainers.size
    });
});

// Login endpoint (simplified - in production, use proper user management)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // Demo authentication - replace with real user management
    if (username === 'demo' && password === 'demo123') {
        const token = jwt.sign(
            { userId: 'demo-user', username },
            config.jwt_secret,
            { expiresIn: '24h' }
        );
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Build endpoint with security checks
app.post('/api/build', authenticate, buildLimiter, async (req, res) => {
    const { dockerfile } = req.body;
    const userId = req.user.userId;

    if (!dockerfile || dockerfile.length > 10000) {
        return res.status(400).json({ error: 'Invalid Dockerfile' });
    }

    // Security: Validate Dockerfile content
    const dangerousPatterns = [
        /rm\s+-rf\s+\//,
        /curl.*\|.*sh/,
        /wget.*\|.*sh/,
        /--privileged/
    ];

    for (const pattern of dangerousPatterns) {
        if (pattern.test(dockerfile)) {
            logger.warn(`Dangerous pattern detected in Dockerfile from user ${userId}`);
            return res.status(400).json({ error: 'Dockerfile contains potentially dangerous commands' });
        }
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const sendEvent = (data) => res.write(`data: ${JSON.stringify(data)}\\n\\n`);

    let buildDir;
    try {
        buildDir = await fs.mkdtemp(join(os.tmpdir(), 'docker-build-'));
        await fs.writeFile(join(buildDir, 'Dockerfile'), dockerfile);

        const imageTag = `dockerterm-${userId}-${Date.now()}`;
        const buildProcess = spawn('docker', [
            'build',
            '--memory', '512m',
            '--cpu-shares', '512',
            '-t', imageTag,
            '.'
        ], { cwd: buildDir });

        buildProcess.stdout.on('data', (data) => {
            sendEvent({ type: 'log', content: data.toString() });
        });

        buildProcess.stderr.on('data', (data) => {
            sendEvent({ type: 'log', content: data.toString() });
        });

        buildProcess.on('close', async (code) => {
            if (code === 0) {
                sendEvent({ type: 'success', imageId: imageTag });
                logger.info(`Build successful: ${imageTag} for user ${userId}`);
            } else {
                sendEvent({ type: 'error', content: `Build failed with code ${code}` });
                logger.error(`Build failed: ${imageTag} for user ${userId}`);
            }
            res.end();
            await fs.rm(buildDir, { recursive: true, force: true });
        });

    } catch (error) {
        logger.error(`Build error: ${error.message}`);
        sendEvent({ type: 'error', content: `Server error: ${error.message}` });
        res.end();
        if (buildDir) {
            await fs.rm(buildDir, { recursive: true, force: true });
        }
    }
});

const server = http.createServer(app);

// WebSocket server with authentication
const wss = new WebSocketServer({ 
    server,
    verifyClient: (info, cb) => {
        const token = info.req.url.split('token=')[1];
        if (!token) {
            cb(false, 401, 'Unauthorized');
            return;
        }

        try {
            const decoded = jwt.verify(token, config.jwt_secret);
            info.req.user = decoded;
            cb(true);
        } catch (error) {
            cb(false, 403, 'Forbidden');
        }
    }
});

wss.on('connection', (ws, req) => {
    const userId = req.user.userId;
    let ptyProcess = null;
    let containerId = null;

    // Check container limit
    const userContainerCount = userContainers.get(userId) || 0;
    if (userContainerCount >= config.max_containers_per_user) {
        ws.send(JSON.stringify({ 
            type: 'error', 
            content: `Container limit (${config.max_containers_per_user}) reached` 
        }));
        ws.close();
        return;
    }

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message.toString());

            if (data.type === 'run' && data.imageId) {
                // Verify image ownership
                if (!data.imageId.startsWith(`dockerterm-${userId}-`)) {
                    ws.send(JSON.stringify({ 
                        type: 'error', 
                        content: 'Unauthorized image access' 
                    }));
                    return;
                }

                containerId = `dockerterm-${uuidv4()}`;

                const dockerArgs = [
                    'run',
                    '--rm',
                    '-it',
                    '--name', containerId,
                    '--memory', '256m',
                    '--cpus', '0.5',
                    '--network', 'none',
                    '--read-only',
                    '--tmpfs', '/tmp:size=10M',
                    data.imageId,
                    'sh'
                ];

                ptyProcess = pty.spawn('docker', dockerArgs, {
                    name: 'xterm-color',
                    cols: 80,
                    rows: 30,
                    cwd: process.env.HOME,
                    env: process.env,
                });

                activeContainers.set(containerId, {
                    userId,
                    startTime: Date.now(),
                    imageId: data.imageId
                });

                userContainers.set(userId, (userContainers.get(userId) || 0) + 1);

                ptyProcess.onData((data) => {
                    ws.send(JSON.stringify({ type: 'log', content: data }));
                });

                ptyProcess.onExit(({ exitCode }) => {
                    ws.send(JSON.stringify({ 
                        type: 'exit', 
                        content: `Container exited with code ${exitCode}.` 
                    }));

                    activeContainers.delete(containerId);
                    userContainers.set(userId, Math.max(0, (userContainers.get(userId) || 1) - 1));

                    ptyProcess = null;
                    containerId = null;
                });

                logger.info(`Container started: ${containerId} for user ${userId}`);

            } else if (data.type === 'command' && ptyProcess) {
                ptyProcess.write(data.command);
            }
        } catch (error) {
            logger.error(`WebSocket error: ${error.message}`);
            ws.send(JSON.stringify({
                type: 'error',
                content: 'Invalid command'
            }));
        }
    });

    ws.on('close', () => {
        if (containerId) {
            spawn('docker', ['stop', containerId]);
            activeContainers.delete(containerId);
            userContainers.set(userId, Math.max(0, (userContainers.get(userId) || 1) - 1));
            logger.info(`Container stopped: ${containerId} for user ${userId}`);
        }
        if (ptyProcess) {
            ptyProcess.kill();
        }
    });
});

server.listen(port, () => {
    logger.info(`Docker Terminal Backend listening on port ${port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');

    // Stop all containers
    for (const [containerId] of activeContainers.entries()) {
        spawn('docker', ['stop', containerId]);
    }

    server.close(() => {
        logger.info('Server closed');
        process.exit(0);
    });
});
'''

        (self.install_dir / "backend/src/index.js").write_text(server_content)

        # Package.json for backend
        backend_package = {
            "name": "docker-terminal-backend",
            "version": "2.0.0",
            "description": "Secure Docker Terminal Backend",
            "main": "src/index.js",
            "type": "module",
            "scripts": {
                "start": "node src/index.js",
                "dev": "nodemon src/index.js"
            },
            "dependencies": {
                "express": "^4.19.2",
                "cors": "^2.8.5",
                "helmet": "^7.1.0",
                "express-rate-limit": "^7.1.5",
                "winston": "^3.11.0",
                "ws": "^8.16.0",
                "node-pty": "^1.0.0",
                "jsonwebtoken": "^9.0.2",
                "bcrypt": "^5.1.1",
                "uuid": "^9.0.1"
            },
            "devDependencies": {
                "nodemon": "^3.0.2"
            }
        }

        (self.install_dir / "backend/package.json").write_text(
            json.dumps(backend_package, indent=2)
        )

    def _create_enhanced_frontend(self):
        """Create enhanced frontend with authentication"""

        # index.html
        index_html = '''<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Secure Docker Terminal</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
'''

        (self.install_dir / "frontend/index.html").write_text(index_html)

        # Create src directory
        src_dir = self.install_dir / "frontend/src"
        src_dir.mkdir(exist_ok=True)

        # main.tsx
        main_content = '''import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
'''

        (src_dir / "main.tsx").write_text(main_content)

        # index.css
        index_css = '''@tailwind base;
@tailwind components;
@tailwind utilities;

body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
'''

        (src_dir / "index.css").write_text(index_css)

        # Enhanced App.tsx with login
        app_content = '''import React, { useState } from 'react';
import DockerTerminal from './components/DockerTerminal';
import Login from './components/Login';

function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('dockerterm_token'));

  const handleLogin = (newToken: string) => {
    setToken(newToken);
    localStorage.setItem('dockerterm_token', newToken);
  };

  const handleLogout = () => {
    setToken(null);
    localStorage.removeItem('dockerterm_token');
  };

  if (!token) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col items-center justify-start p-4 font-sans">
      <header className="w-full max-w-7xl mx-auto text-center my-6">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-4xl font-bold text-cyan-400 flex items-center gap-3">
              <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-cyan-500">
                <path d="M22 18V6H2l10 12L22 6V4H2v2l10 12L22 4h-2.31"/>
                <path d="M14 12.37V6.03h-2.11v1.16l2.11 2.37zM2 18v-2h20v2Z"/>
                <path d="M4.69 16l-2.31-2.63"/>
                <path d="M19.31 16l2.31-2.63"/>
              </svg>
              Secure Docker Terminal
            </h1>
            <p className="text-gray-400 mt-2">
              Build and run Docker containers securely
            </p>
          </div>
          <button
            onClick={handleLogout}
            className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700"
          >
            Logout
          </button>
        </div>
      </header>
      <main className="w-full flex-grow">
        <DockerTerminal token={token} />
      </main>
    </div>
  );
}

export default App;
'''

        (src_dir / "App.tsx").write_text(app_content)

        # Create components directory
        components_dir = src_dir / "components"
        components_dir.mkdir(exist_ok=True)

        # Login component
        login_content = '''import React, { useState } from 'react';

interface LoginProps {
  onLogin: (token: string) => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('http://localhost:3001/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();

      if (response.ok) {
        onLogin(data.token);
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (error) {
      setError('Connection failed. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-96">
        <h2 className="text-2xl font-bold text-white mb-6 text-center">
          Docker Terminal Login
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-cyan-500"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-cyan-500"
              required
            />
          </div>

          {error && (
            <div className="text-red-400 text-sm">{error}</div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 bg-cyan-600 text-white rounded-md hover:bg-cyan-700 disabled:bg-gray-600"
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>

          <p className="text-gray-400 text-sm text-center mt-4">
            Demo credentials: demo / demo123
          </p>
        </form>
      </div>
    </div>
  );
}
'''

        (components_dir / "Login.tsx").write_text(login_content)

        # Enhanced DockerTerminal component
        docker_terminal_content = '''import React, { useState, useRef, useEffect, useCallback } from 'react';

interface DockerTerminalProps {
  token: string;
}

enum ContainerStatus {
  IDLE = 'IDLE',
  BUILDING = 'BUILDING',
  BUILD_SUCCESS = 'BUILD_SUCCESS',
  RUNNING = 'RUNNING',
  ERROR = 'ERROR',
}

enum LogType {
  SYSTEM = 'SYSTEM',
  INPUT = 'INPUT',
  OUTPUT = 'OUTPUT',
  ERROR = 'ERROR',
  SUCCESS = 'SUCCESS',
}

interface LogEntry {
  type: LogType;
  content: string;
  timestamp: string;
}

const BACKEND_URL = 'http://localhost:3001';

const initialDockerfile = `# Simple Alpine container
FROM alpine:latest

# Install basic tools
RUN apk add --no-cache bash curl

WORKDIR /app

# Default command
CMD ["sh"]
`.trim();

export default function DockerTerminal({ token }: DockerTerminalProps) {
  const [dockerfile, setDockerfile] = useState<string>(initialDockerfile);
  const [status, setStatus] = useState<ContainerStatus>(ContainerStatus.IDLE);
  const [imageId, setImageId] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [command, setCommand] = useState<string>('');

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const ws = useRef<WebSocket | null>(null);

  const addLog = useCallback((content: string, type: LogType) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { content, type, timestamp }]);
  }, []);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    return () => {
      ws.current?.close();
    };
  }, []);

  const handleBuild = useCallback(async () => {
    setStatus(ContainerStatus.BUILDING);
    setImageId(null);
    setLogs([]);
    addLog("Starting Docker build...", LogType.SYSTEM);

    try {
      const response = await fetch(`${BACKEND_URL}/api/build`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ dockerfile }),
      });

      if (!response.body) throw new Error("No response body");

      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        const lines = value.split('\\n\\n');
        for (const line of lines) {
          if (line.startsWith('data:')) {
            try {
              const data = JSON.parse(line.substring(5));
              if (data.type === 'log') {
                addLog(data.content, LogType.OUTPUT);
              } else if (data.type === 'success') {
                addLog(`Build successful! Image ID: ${data.imageId}`, LogType.SUCCESS);
                setImageId(data.imageId);
                setStatus(ContainerStatus.BUILD_SUCCESS);
              } else if (data.type === 'error') {
                addLog(data.content, LogType.ERROR);
                setStatus(ContainerStatus.ERROR);
              }
            } catch(e) {
              // Ignore parsing errors
            }
          }
        }
      }
    } catch (error) {
      addLog(`Build failed: ${error instanceof Error ? error.message : 'Unknown error'}`, LogType.ERROR);
      setStatus(ContainerStatus.ERROR);
    }
  }, [dockerfile, token, addLog]);

  const handleRun = useCallback(() => {
    if (!imageId) return;

    setStatus(ContainerStatus.RUNNING);
    setLogs([]);
    addLog(`Starting container...`, LogType.SYSTEM);

    ws.current = new WebSocket(`ws://localhost:3001?token=${token}`);

    ws.current.onopen = () => {
      addLog("Connected to container", LogType.SUCCESS);
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
        } else if(data.type === 'error') {
          addLog(data.content, LogType.ERROR);
        }
      } catch(e) {
        addLog('Received invalid data', LogType.ERROR);
      }
    };

    ws.current.onerror = () => {
      addLog('WebSocket error occurred', LogType.ERROR);
      setStatus(ContainerStatus.ERROR);
    };

    ws.current.onclose = () => {
      if (status === ContainerStatus.RUNNING) {
        addLog("Disconnected from container", LogType.SYSTEM);
        setStatus(ContainerStatus.BUILD_SUCCESS);
      }
    };
  }, [imageId, token, addLog, status]);

  const handleStop = useCallback(() => {
    ws.current?.close();
    ws.current = null;
    addLog("Container stopped", LogType.SYSTEM);
    setStatus(ContainerStatus.BUILD_SUCCESS);
  }, [addLog]);

  const handleCommandSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!command.trim() || !ws.current || ws.current.readyState !== WebSocket.OPEN) return;

    ws.current.send(JSON.stringify({ type: 'command', command: command + '\\n' }));
    setCommand('');
  };

  const isBuilding = status === ContainerStatus.BUILDING;
  const isRunning = status === ContainerStatus.RUNNING;
  const canRun = status === ContainerStatus.BUILD_SUCCESS;

  return (
    <div className="w-full max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6 h-[720px]">
      <div className="bg-gray-800 rounded-lg shadow-lg p-5 flex flex-col gap-4">
        <h2 className="text-xl font-semibold text-gray-200 border-b border-gray-700 pb-2">Control Panel</h2>

        <div className="flex flex-col gap-2">
          <button 
            onClick={handleBuild} 
            disabled={isBuilding || isRunning} 
            className="px-4 py-2 bg-blue-600 text-white rounded-md font-semibold hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
          >
            {isBuilding ? 'Building...' : 'Build Image'}
          </button>

          <button 
            onClick={handleRun} 
            disabled={!canRun} 
            className="px-4 py-2 bg-green-600 text-white rounded-md font-semibold hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
          >
            Run Container
          </button>

          <button 
            onClick={handleStop} 
            disabled={!isRunning} 
            className="px-4 py-2 bg-red-600 text-white rounded-md font-semibold hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
          >
            Stop Container
          </button>
        </div>

        <div className="flex flex-col flex-grow min-h-0">
          <label htmlFor="dockerfile" className="block text-sm font-medium text-gray-300 mb-1">
            Dockerfile
          </label>
          <textarea 
            id="dockerfile"
            value={dockerfile}
            onChange={(e) => setDockerfile(e.target.value)}
            disabled={isBuilding || isRunning}
            className="w-full flex-grow p-3 font-mono text-sm bg-gray-900 text-gray-300 border border-gray-700 rounded-md focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 transition-colors disabled:bg-gray-700"
            spellCheck={false}
          />
        </div>
      </div>

      <div className="lg:col-span-2 bg-black rounded-lg shadow-lg flex flex-col h-full">
        <div className="bg-gray-800 p-3 border-b border-gray-700 rounded-t-lg">
          <h2 className="text-xl font-semibold text-gray-200">Terminal Output</h2>
        </div>

        <div className="flex-grow p-4 overflow-y-auto font-mono text-sm leading-6">
          {logs.map((log, index) => {
            let colorClass = 'text-gray-300';
            if (log.type === LogType.SYSTEM) colorClass = 'text-yellow-400';
            if (log.type === LogType.ERROR) colorClass = 'text-red-400';
            if (log.type === LogType.SUCCESS) colorClass = 'text-cyan-400';

            return (
              <div key={index}>
                {log.timestamp && <span className="text-gray-500 mr-2">{log.timestamp}</span>}
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
              disabled={!isRunning}
              className="flex-1 bg-transparent text-gray-200 font-mono focus:outline-none"
              placeholder={isRunning ? "Enter command..." : "Container not running"}
            />
          </form>
        </div>
      </div>
    </div>
  );
}
'''

        (components_dir / "DockerTerminal.tsx").write_text(docker_terminal_content)

        # types.ts
        types_content = '''export enum ContainerStatus {
  IDLE = 'IDLE',
  BUILDING = 'BUILDING',
  BUILD_SUCCESS = 'BUILD_SUCCESS',
  RUNNING = 'RUNNING',
  ERROR = 'ERROR',
}

export enum LogType {
  SYSTEM = 'SYSTEM',
  INPUT = 'INPUT',
  OUTPUT = 'OUTPUT',
  ERROR = 'ERROR',
  SUCCESS = 'SUCCESS',
}

export interface LogEntry {
  type: LogType;
  content: string;
  timestamp: string;
}
'''

        (src_dir / "types.ts").write_text(types_content)

        # vite.config.ts
        vite_config = '''import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true
  }
});
'''

        (self.install_dir / "frontend/vite.config.ts").write_text(vite_config)

        # tsconfig.json
        tsconfig = {
            "compilerOptions": {
                "target": "ES2020",
                "useDefineForClassFields": True,
                "lib": ["ES2020", "DOM", "DOM.Iterable"],
                "module": "ESNext",
                "skipLibCheck": True,
                "moduleResolution": "bundler",
                "allowImportingTsExtensions": True,
                "resolveJsonModule": True,
                "isolatedModules": True,
                "noEmit": True,
                "jsx": "react-jsx",
                "strict": True,
                "noUnusedLocals": True,
                "noUnusedParameters": True,
                "noFallthroughCasesInSwitch": True
            },
            "include": ["src"],
            "references": [{"path": "./tsconfig.node.json"}]
        }

        (self.install_dir / "frontend/tsconfig.json").write_text(
            json.dumps(tsconfig, indent=2)
        )

        # tsconfig.node.json
        tsconfig_node = {
            "compilerOptions": {
                "composite": True,
                "skipLibCheck": True,
                "module": "ESNext",
                "moduleResolution": "bundler",
                "allowSyntheticDefaultImports": True
            },
            "include": ["vite.config.ts"]
        }

        (self.install_dir / "frontend/tsconfig.node.json").write_text(
            json.dumps(tsconfig_node, indent=2)
        )

        # Frontend package.json
        frontend_package = {
            "name": "docker-terminal-frontend",
            "version": "2.0.0",
            "type": "module",
            "scripts": {
                "dev": "vite",
                "build": "tsc && vite build",
                "preview": "vite preview"
            },
            "dependencies": {
                "react": "^18.2.0",
                "react-dom": "^18.2.0"
            },
            "devDependencies": {
                "@types/react": "^18.2.43",
                "@types/react-dom": "^18.2.17",
                "@vitejs/plugin-react": "^4.2.1",
                "typescript": "^5.2.2",
                "vite": "^5.0.8"
            }
        }

        (self.install_dir / "frontend/package.json").write_text(
            json.dumps(frontend_package, indent=2)
        )

    def _create_config_files(self):
        """Create configuration files"""

        # Main app configuration
        app_config = {
            "frontend_port": self.port,
            "backend_port": self.backend_port,
            "hostname": "localhost",
            "jwt_secret": self.config["jwt_secret"],
            "session_secret": self.config["session_secret"],
            "allowed_images": self.config["allowed_images"],
            "max_containers_per_user": self.config["max_containers_per_user"],
            "container_timeout_minutes": self.config["container_timeout_minutes"]
        }

        (self.install_dir / "config/app.json").write_text(
            json.dumps(app_config, indent=2)
        )

        # Nginx configuration
        nginx_config = f'''server {{
    listen 80;
    server_name _;

    # Frontend
    location / {{
        proxy_pass http://localhost:{self.port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }}

    # Backend API
    location /api {{
        proxy_pass http://localhost:{self.backend_port};
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }}

    # WebSocket
    location /ws {{
        proxy_pass http://localhost:{self.backend_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }}
}}
'''

        (self.install_dir / "config/nginx.conf").write_text(nginx_config)

    def install_dependencies(self):
        """Install Node.js dependencies"""
        self.log("Installing Node.js dependencies...", "header")

        # Backend dependencies
        os.chdir(self.install_dir / "backend")
        self.run_command(["npm", "install"], check=False)

        # Frontend dependencies
        os.chdir(self.install_dir / "frontend")
        self.run_command(["npm", "install"], check=False)

        self.log("Dependencies installed", "success")

    def setup_systemd_services(self):
        """Create systemd services for auto-start"""
        self.log("Setting up systemd services...", "header")

        # Backend service
        backend_service = f'''[Unit]
Description=Docker Terminal Backend
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User={self.app_user}
Group={self.app_group}
WorkingDirectory={self.install_dir}/backend
ExecStart=/usr/bin/node {self.install_dir}/backend/src/index.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=docker-terminal-backend
Environment="NODE_ENV=production"

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={self.install_dir}/logs

[Install]
WantedBy=multi-user.target
'''

        Path("/etc/systemd/system/docker-terminal-backend.service").write_text(backend_service)

        # Frontend service
        frontend_service = f'''[Unit]
Description=Docker Terminal Frontend
After=network.target

[Service]
Type=simple
User={self.app_user}
Group={self.app_group}
WorkingDirectory={self.install_dir}/frontend
ExecStart=/usr/bin/npm run preview -- --port {self.port} --host
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=docker-terminal-frontend
Environment="NODE_ENV=production"

[Install]
WantedBy=multi-user.target
'''

        Path("/etc/systemd/system/docker-terminal-frontend.service").write_text(frontend_service)

        # Reload systemd and enable services
        self.run_command(["systemctl", "daemon-reload"])
        self.run_command(["systemctl", "enable", "docker-terminal-backend"])
        self.run_command(["systemctl", "enable", "docker-terminal-frontend"])

        self.log("Systemd services created", "success")

    def setup_firewall(self):
        """Configure firewall rules"""
        self.log("Configuring firewall...", "header")

        if shutil.which("ufw"):
            # Ubuntu/Debian with UFW
            self.run_command(["ufw", "allow", str(self.port)], check=False)
            self.run_command(["ufw", "allow", str(self.backend_port)], check=False)
            self.log("UFW rules added", "success")
        elif shutil.which("firewall-cmd"):
            # RHEL/CentOS with firewalld
            self.run_command([
                "firewall-cmd", f"--add-port={self.port}/tcp", "--permanent"
            ], check=False)
            self.run_command([
                "firewall-cmd", f"--add-port={self.backend_port}/tcp", "--permanent"
            ], check=False)
            self.run_command(["firewall-cmd", "--reload"], check=False)
            self.log("Firewalld rules added", "success")
        else:
            self.log("No firewall detected, skipping firewall configuration", "warning")

    def build_frontend(self):
        """Build frontend for production"""
        self.log("Building frontend...", "header")

        os.chdir(self.install_dir / "frontend")
        self.run_command(["npm", "run", "build"])

        self.log("Frontend built successfully", "success")

    def start_services(self):
        """Start the application services"""
        self.log("Starting services...", "header")

        self.run_command(["systemctl", "start", "docker-terminal-backend"])
        self.run_command(["systemctl", "start", "docker-terminal-frontend"])

        # Wait a moment for services to start
        import time
        time.sleep(3)

        # Check if services are running
        backend_status = self.run_command(
            ["systemctl", "is-active", "docker-terminal-backend"],
            capture_output=True
        )
        frontend_status = self.run_command(
            ["systemctl", "is-active", "docker-terminal-frontend"],
            capture_output=True
        )

        if backend_status.stdout.strip() == "active":
            self.log("Backend service is running", "success")
        else:
            self.log("Backend service failed to start", "error")
            self.run_command(["journalctl", "-u", "docker-terminal-backend", "-n", "20"])

        if frontend_status.stdout.strip() == "active":
            self.log("Frontend service is running", "success")
        else:
            self.log("Frontend service failed to start", "error")
            self.run_command(["journalctl", "-u", "docker-terminal-frontend", "-n", "20"])

    def create_documentation(self):
        """Create README and documentation"""
        self.log("Creating documentation...", "header")

        readme_content = f'''# Docker Terminal Application

## Overview
A secure web-based Docker terminal that allows users to build and run containers through a browser interface.

## Access
- URL: http://localhost:{self.port}
- Default credentials: demo / demo123

## Security Features
- JWT-based authentication
- Rate limiting on API endpoints
- Container resource limits (CPU: 0.5 cores, Memory: 256MB)
- Network isolation for containers
- Read-only root filesystem
- Automatic container timeout after {self.config["container_timeout_minutes"]} minutes
- Per-user container limits ({self.config["max_containers_per_user"]} containers)

## Configuration
Configuration file: {self.install_dir}/config/app.json

## Logs
- Application logs: {self.install_dir}/logs/
- Service logs: journalctl -u docker-terminal-backend
                journalctl -u docker-terminal-frontend

## Management Commands

### Start services:
sudo systemctl start docker-terminal-backend
sudo systemctl start docker-terminal-frontend

### Stop services:
sudo systemctl stop docker-terminal-backend
sudo systemctl stop docker-terminal-frontend

### View logs:
sudo journalctl -u docker-terminal-backend -f
sudo journalctl -u docker-terminal-frontend -f

### Clean up old images:
docker image prune -f --filter "label=dockerterm"

## Troubleshooting

### Backend not starting:
1. Check Docker is running: sudo systemctl status docker
2. Check logs: sudo journalctl -u docker-terminal-backend -n 50
3. Verify port {self.backend_port} is not in use: sudo netstat -tlnp | grep {self.backend_port}

### Frontend not accessible:
1. Check service status: sudo systemctl status docker-terminal-frontend
2. Verify port {self.port} is not in use: sudo netstat -tlnp | grep {self.port}
3. Check firewall rules

### Container issues:
1. List running containers: docker ps --filter "name=dockerterm"
2. Stop all app containers: docker stop $(docker ps -q --filter "name=dockerterm")
3. Check container logs: docker logs <container-id>

## Security Considerations
- Change default credentials immediately
- Use HTTPS in production (configure nginx with SSL)
- Regularly update dependencies
- Monitor logs for suspicious activity
- Consider implementing proper user management

## Backup
Important files to backup:
- {self.install_dir}/config/app.json
- {self.install_dir}/logs/

Created by Docker Terminal Setup Script
'''

        (self.install_dir / "README.md").write_text(readme_content)

        self.log("Documentation created", "success")

    def display_summary(self):
        """Display installation summary"""
        print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        print(f"{Colors.HEADER}Installation Complete!{Colors.ENDC}")
        print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}\n")

        print(f"{Colors.OKGREEN}✓ Docker Terminal has been successfully installed{Colors.ENDC}")
        print(f"\n{Colors.OKCYAN}Access Information:{Colors.ENDC}")
        print(f"  URL: http://localhost:{self.port}")
        print(f"  Username: demo")
        print(f"  Password: demo123")

        print(f"\n{Colors.OKCYAN}Service Management:{Colors.ENDC}")
        print(f"  Start:   sudo systemctl start docker-terminal-backend docker-terminal-frontend")
        print(f"  Stop:    sudo systemctl stop docker-terminal-backend docker-terminal-frontend")
        print(f"  Status:  sudo systemctl status docker-terminal-backend docker-terminal-frontend")
        print(f"  Logs:    sudo journalctl -u docker-terminal-backend -f")

        print(f"\n{Colors.WARNING}⚠ Security Notes:{Colors.ENDC}")
        print(f"  - Change the default credentials immediately")
        print(f"  - Configure HTTPS for production use")
        print(f"  - Review firewall rules")
        print(f"  - Monitor {self.install_dir}/logs/ for activity")

        print(f"\n{Colors.OKBLUE}Documentation: {self.install_dir}/README.md{Colors.ENDC}")
        print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}\n")

    def run(self):
        """Execute the complete setup process"""
        try:
            self.log("Starting Docker Terminal Setup", "header")

            self.check_system_requirements()
            self.install_docker()
            self.install_nodejs()
            self.create_app_user()
            self.setup_application_files()
            self.install_dependencies()
            self.build_frontend()
            self.setup_systemd_services()
            self.setup_firewall()
            self.start_services()
            self.create_documentation()
            self.display_summary()

        except Exception as e:
            self.log(f"Setup failed: {str(e)}", "error")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Docker Terminal Application - One-Shot Setup Script"
    )
    parser.add_argument(
        "--install-dir",
        default="/opt/docker-terminal",
        help="Installation directory (default: /opt/docker-terminal)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=3000,
        help="Frontend port (default: 3000)"
    )
    parser.add_argument(
        "--backend-port",
        type=int,
        default=3001,
        help="Backend port (default: 3001)"
    )

    args = parser.parse_args()

    # ASCII Art Banner
    banner = f'''
{Colors.OKCYAN}
    ____             __                  ______                    _             __
   / __ \\____  _____/ /_____  _____    /_  __/__  _________ ___  (_)___  ____ _/ /
  / / / / __ \\/ ___/ //_/ _ \\/ ___/     / / / _ \\/ ___/ __ `__ \\/ / __ \\/ __ `/ / 
 / /_/ / /_/ / /__/ ,< /  __/ /        / / /  __/ /  / / / / / / / / / / /_/ / /  
/_____/\\____/\\___/_/|_|\\___/_/        /_/  \\___/_/  /_/ /_/ /_/_/_/ /_/\\__,_/_/   

{Colors.ENDC}
{Colors.OKGREEN}Secure Web-Based Docker Terminal - One-Shot Setup{Colors.ENDC}
'''
    print(banner)

    setup = DockerTerminalSetup(
        install_dir=args.install_dir,
        port=args.port,
        backend_port=args.backend_port
    )
    setup.run()


if __name__ == "__main__":
    main()