const { app, BrowserWindow, Menu, shell, protocol, net } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const url = require('url');

// Register app protocol as privileged
protocol.registerSchemesAsPrivileged([
    { scheme: 'app', privileges: { secure: true, standard: true, supportFetchAPI: true, corsEnabled: true } }
]);

// Single instance lock
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
    app.quit();
}

let mainWindow;
let backendProcess;
let frontendProcess;

function checkPort(port) {
    return new Promise((resolve) => {
        const client = new net.Socket();
        client.connect({ port }, () => {
            client.end();
            resolve(true);
        });
        client.on('error', () => {
            resolve(false);
        });
    });
}

// ... (rest of checkPort/waitForServer is mostly fine, just ensuring correct module)

async function waitForServer(port, name, maxRetries = 60) {
    console.log(`Waiting for ${name} on port ${port}...`);
    for (let i = 0; i < maxRetries; i++) {
        const isReady = await checkPort(port);
        if (isReady) {
            console.log(`✓ ${name} is ready on port ${port}`);
            return true;
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    console.error(`✗ Failed to connect to ${name} on port ${port}`);
    return false;
}

function startBackend() {
    console.log('Starting backend...');

    let backendPath;
    if (app.isPackaged) {
        // In bundled app, backend is in Resources/backend/gcp-scanner-backend
        // Note: PyInstaller creates a directory if we used --onedir, or file if --onefile.
        // The spec file uses COLLECT, which implies --onedir (directory).
        // So the executable is inside the folder.
        const executableName = process.platform === 'win32' ? 'gcp-scanner-backend.exe' : 'gcp-scanner-backend';
        backendPath = path.join(process.resourcesPath, 'backend', 'gcp-scanner-backend', executableName);
    } else {
        // Dev mode: use local dist if available, or python source
        const distPath = path.join(__dirname, 'backend', 'dist', 'gcp-scanner-backend', 'gcp-scanner-backend');
        if (fs.existsSync(distPath)) {
            backendPath = distPath;
        } else {
            // Fallback to python source for dev
            const backendDir = path.join(__dirname, 'backend');
            const pythonPath = path.join(backendDir, 'venv', 'bin', 'python3');
            backendProcess = spawn(pythonPath, [
                '-m', 'uvicorn',
                'app.main:app',
                '--host', '127.0.0.1',
                '--port', '8000'
            ], {
                cwd: backendDir,
                env: { ...process.env, PYTHONUNBUFFERED: '1' }
            });
            setupProcessListeners(backendProcess, 'Backend');
            return;
        }
    }

    console.log(`Backend executable: ${backendPath}`);

    // Spawn the backend executable
    // Note: When using PyInstaller one-dir, we execute the binary.
    // Env vars are passed, which is important for CREDENTIALS if needed.

    // Find a free port first? 
    // Ideally yes, but the current code hardcodes 8000 or expects startBackend to handle it.
    // The previous code hardcoded 8000. Let's stick to 8000 for "same as before" stability,
    // unless we want to use the 'checkPort' logic to find a free one.
    // The previous code waited for 8000. Let's try to stick to 8000.

    // We pass port 8000 via args if the backend supports it, or env var.
    // Uvicorn in main.py usually reads args or env? 
    // The pyinstaller spec entry point is `app/main.py`.
    // If it uses `if __name__ == "__main__": uvicorn.run(...)` it might respect args.

    // Let's assume standard uvicorn behavior requires us to pass arguments IF we invoke uvicorn.
    // But this is a compiled app. How does `main.py` start?
    // We need to check `app/main.py`.

    // If we can't check `app/main.py`, we assume standard uvicorn launch.
    // Wait, PyInstaller executes the script.

    backendProcess = spawn(backendPath, [], {
        env: {
            ...process.env,
            PORT: '8000',
            PYTHONUNBUFFERED: '1'
        }
    });

    setupProcessListeners(backendProcess, 'Backend');
}

function setupProcessListeners(proc, name) {
    proc.stdout.on('data', (data) => console.log(`[${name}] ${data}`));
    proc.stderr.on('data', (data) => console.error(`[${name} Error] ${data}`));
    proc.on('close', (code) => console.log(`[${name}] Exited with code ${code}`));
}

function startFrontend() {
    console.log('Starting frontend...');

    let frontendDir;
    let nodePath;

    if (app.isPackaged) {
        // In packaged mode, we use static export. No server needed.
        console.log('Frontend is static (packaged), skipping server start.');
        return;
    } else {
        frontendDir = path.join(__dirname, 'frontend');
        nodePath = 'node';
    }

    console.log(`Frontend dir: ${frontendDir}`);
    console.log(`Node path: ${nodePath}`);
    console.log(`Frontend dir exists: ${fs.existsSync(frontendDir)}`);

    // Start Next.js server using the standalone server if available
    const standaloneServer = path.join(frontendDir, '.next', 'standalone', 'server.js');
    const nextBin = path.join(frontendDir, 'node_modules', 'next', 'dist', 'bin', 'next');

    let serverPath;
    let args;

    if (fs.existsSync(standaloneServer)) {
        console.log('Using standalone server');
        serverPath = standaloneServer;
        args = [];
    } else if (fs.existsSync(nextBin)) {
        console.log('Using next binary');
        serverPath = nextBin;
        args = ['start', '-p', '3001'];
    } else {
        console.error('No Next.js server found!');
        console.error(`Checked standalone: ${standaloneServer}`);
        console.error(`Checked next bin: ${nextBin}`);
        return;
    }

    console.log(`Starting: ${nodePath} ${serverPath} ${args.join(' ')}`);

    frontendProcess = spawn(nodePath, [serverPath, ...args], {
        cwd: frontendDir,
        env: {
            ...process.env,
            PORT: '3001',
            NODE_ENV: 'production',
            HOSTNAME: '127.0.0.1',
            ELECTRON_RUN_AS_NODE: '1' // CRITICAL: Stop recursive spawning
        }
    });

    frontendProcess.stdout.on('data', (data) => {
        console.log(`[Frontend] ${data.toString().trim()}`);
    });

    frontendProcess.stderr.on('data', (data) => {
        console.error(`[Frontend Error] ${data.toString().trim()}`);
    });

    frontendProcess.on('error', (error) => {
        console.error('[Frontend] Failed to start:', error);
    });

    frontendProcess.on('close', (code) => {
        console.log(`[Frontend] Process exited with code ${code}`);
    });
}

function openReadmeWindow(filename, title) {
    let filePath;
    if (app.isPackaged) {
        filePath = path.join(process.resourcesPath, filename);
    } else {
        filePath = path.join(__dirname, filename);
    }

    const helpWindow = new BrowserWindow({
        width: 800,
        height: 600,
        title: title,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true
        },
        autoHideMenuBar: true
    });

    // Read file and wrap in basic HTML for readability
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            helpWindow.loadURL(`data:text/html;charset=utf-8,<h1>Error reading file</h1><p>${err.message}</p>`);
            return;
        }

        // Simple Markdown-ish to HTML conversion (paragraphs and headers)
        // Or just display as preformatted text which is honest and readable
        const htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>${title}</title>
                <style>
                    body { font-family: system-ui, -apple-system, sans-serif; padding: 40px; line-height: 1.6; max-width: 800px; mx-auto; color: #333; }
                    pre { white-space: pre-wrap; font-family: monospace; background: #f5f5f5; padding: 15px; border-radius: 5px; }
                    h1 { border-bottom: 1px solid #eee; padding-bottom: 10px; }
                </style>
            </head>
            <body>
                <h1>${title}</h1>
                <pre>${data}</pre>
            </body>
            </html>
        `;

        helpWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(htmlContent)}`);
    });
}

function createMenu() {
    const isMac = process.platform === 'darwin';

    const template = [
        // App Menu (Mac only)
        ...(isMac ? [{
            label: app.name,
            submenu: [
                { role: 'about' },
                { type: 'separator' },
                { role: 'services' },
                { type: 'separator' },
                { role: 'hide' },
                { role: 'hideOthers' },
                { role: 'unhide' },
                { type: 'separator' },
                { role: 'quit' }
            ]
        }] : []),
        // File
        {
            label: 'File',
            submenu: [
                isMac ? { role: 'close' } : { role: 'quit' }
            ]
        },
        // Edit
        {
            label: 'Edit',
            submenu: [
                { role: 'undo' },
                { role: 'redo' },
                { type: 'separator' },
                { role: 'cut' },
                { role: 'copy' },
                { role: 'paste' },
                ...(isMac ? [
                    { role: 'pasteAndMatchStyle' },
                    { role: 'delete' },
                    { role: 'selectAll' },
                    { type: 'separator' },
                    {
                        label: 'Speech',
                        submenu: [
                            { role: 'startSpeaking' },
                            { role: 'stopSpeaking' }
                        ]
                    }
                ] : [
                    { role: 'delete' },
                    { type: 'separator' },
                    { role: 'selectAll' }
                ])
            ]
        },
        // View
        {
            label: 'View',
            submenu: [
                { role: 'reload' },
                { role: 'forceReload' },
                { role: 'toggleDevTools' },
                { type: 'separator' },
                { role: 'resetZoom' },
                { role: 'zoomIn' },
                { role: 'zoomOut' },
                { type: 'separator' },
                { role: 'togglefullscreen' }
            ]
        },
        // Window
        {
            label: 'Window',
            submenu: [
                { role: 'minimize' },
                { role: 'zoom' },
                ...(isMac ? [
                    { type: 'separator' },
                    { role: 'front' },
                    { type: 'separator' },
                    { role: 'window' }
                ] : [
                    { role: 'close' }
                ])
            ]
        },
        // Help
        {
            role: 'help',
            submenu: [
                {
                    label: 'GCP Security Hardening Guide',
                    click: () => {
                        openReadmeWindow('GCP_SECURITY_HARDENING_README.md', 'Security Hardening Guide');
                    }
                },
                {
                    label: 'Technical Scanner Guide',
                    click: () => {
                        openReadmeWindow('GCP_SECURITY_SCANNER_TECHNICAL_README.md', 'Technical Scanner Guide');
                    }
                },
                { type: 'separator' },
                {
                    label: 'Learn More',
                    click: async () => {
                        await shell.openExternal('https://cloud.google.com/security');
                    }
                }
            ]
        }
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        title: 'GCP Security Hardener',
        webPreferences: {
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true
        },
        icon: path.join(__dirname, 'assets', 'icon.png'),
        show: false, // Don't show until loaded
        backgroundColor: '#f3f4f6' // Match your bg-gray-50
    });

    const frontendURL = 'http://localhost:3001';

    // Create Application Menu
    createMenu();

    // LOAD IMMEDIATELY - Don't wait for backend
    // Determine start URL
    if (app.isPackaged) {
        // Load using custom protocol to handle absolute paths in Next.js export
        // "frontend/out" is mapped by the protocol handler
        console.log('Loading packaged app via app:// protocol');
        mainWindow.loadURL('app://start/index.html?port=8000');
    } else {
        // Dev mode
        mainWindow.loadURL(frontendURL);
    }

    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    // Optional: Still log when services are ready for debugging
    waitForServer(8000, 'Backend').then(() => {
        console.log('Backend confirmed ready.');
    }).catch(err => {
        console.error('Service check failed (non-fatal):', err);
    });

    // Always open DevTools so we can see errors
    mainWindow.webContents.openDevTools();

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

app.on('ready', () => {
    console.log('='.repeat(60));
    console.log('Electron app is ready');
    console.log('Is packaged:', app.isPackaged);
    console.log('Resources path:', process.resourcesPath);
    console.log('App path:', app.getAppPath());
    console.log('='.repeat(60));

    // Register custom protocol to serve static files
    // This allows absolute paths like '/_next/...' to work correctly
    protocol.handle('app', (request) => {
        const { host, pathname } = new URL(request.url);

        // Remove leading slash from pathname if present (windows compat)
        let normalizedPath = pathname === '/' ? 'index.html' : pathname;
        if (normalizedPath.startsWith('/')) normalizedPath = normalizedPath.slice(1);

        // Define root where static files are located
        let rootPath;
        if (app.isPackaged) {
            rootPath = path.join(process.resourcesPath, 'app.asar.unpacked', 'frontend', 'out');
            // Fallback for when asarUnpack isn't used for frontend (which is our case now)
            if (!fs.existsSync(rootPath)) {
                rootPath = path.join(__dirname, 'frontend', 'out');
            }
        } else {
            rootPath = path.join(__dirname, 'frontend', 'out');
        }

        const filePath = path.join(rootPath, normalizedPath);

        // Security check: ensure valid path traversal is handled by path.join but good to be careful
        // console.log(`Serving ${request.url} -> ${filePath}`); 

        return net.fetch(url.pathToFileURL(filePath).toString());
    });

    startBackend();
    // Frontend server not needed in prod (handled by app://), strictly dev only valid in startFrontend
    startFrontend();
    createWindow(); // Start immediately
});

app.on('window-all-closed', () => {
    console.log('All windows closed, cleaning up...');

    if (backendProcess) {
        backendProcess.kill('SIGTERM');
    }

    if (frontendProcess) {
        frontendProcess.kill('SIGTERM');
    }

    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (mainWindow === null) {
        createWindow();
    }
});

app.on('before-quit', () => {
    if (backendProcess) {
        backendProcess.kill('SIGTERM');
    }
    if (frontendProcess) {
        frontendProcess.kill('SIGTERM');
    }
});
