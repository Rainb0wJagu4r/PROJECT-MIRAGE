import { app, BrowserWindow } from 'electron';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { startServer, stopServer, API_TOKEN } from './server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow;

async function createWindow() {
  // Start the background HTTPS API server
  await startServer(3001);

  mainWindow = new BrowserWindow({
    width: 1080,
    height: 780,
    minWidth: 900,
    minHeight: 650,
    title: 'Project Mirage',
    autoHideMenuBar: true,
    backgroundColor: '#050408',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  // Load the web UI
  if (process.env.NODE_ENV === 'development') {
    mainWindow.loadURL(`http://localhost:5173?token=${API_TOKEN}`);
    // Open DevTools in development if needed
    // mainWindow.webContents.openDevTools();
  } else {
    // In production, we load from our local Express server over HTTPS (or HTTP if fallback)
    const certPath = path.join(__dirname, 'certs', 'localhost.pem');
    const keyPath = path.join(__dirname, 'certs', 'localhost-key.pem');
    const hasSSL = fs.existsSync(certPath) && fs.existsSync(keyPath);
    const protocol = hasSSL ? 'https' : 'http';
    mainWindow.loadURL(`${protocol}://localhost:3001?token=${API_TOKEN}`);
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Ignore certificate errors for local self-signed SSL certificates from mkcert
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  if (url.startsWith('https://localhost:3001') || url.startsWith('https://127.0.0.1:3001')) {
    event.preventDefault();
    callback(true);
  } else {
    callback(false);
  }
});

app.on('ready', createWindow);

app.on('window-all-closed', () => {
  stopServer();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});
