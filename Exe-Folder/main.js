// main.js
// const { app, BrowserWindow, ipcMain } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const { app, BrowserWindow, ipcMain, dialog } = require('electron');


function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      nodeIntegration: true, // Enable Node.js integration
    },autoHideMenuBar: true, // Hides the menu bar
    // frame: false, // Removes the native title bar for a clean UI
    
  });


  win.loadFile('index.html');
  
}

app.whenReady().then(createWindow);

// IPC handlers for Python script interactions
ipcMain.handle('run-pcap-capture', (event, args) => {
  return new Promise((resolve, reject) => {
    const process = spawn('python', [path.join(__dirname, 'python_scripts', 'pcap_capture.py'), ...args]);
    
    let output = '';
    let errorOutput = '';

    process.stdout.on('data', (data) => {
      output += data.toString();
    });

    process.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    process.on('close', (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(errorOutput);
      }
    });
  });
});

ipcMain.handle('run-pcap-to-audio', (event, pcapFile) => {
  return new Promise((resolve, reject) => {
    const process = spawn('python', [path.join(__dirname, 'python_scripts', 'pcap_to_audio.py'), pcapFile]);
    
    let output = '';
    let errorOutput = '';

    process.stdout.on('data', (data) => {
      output += data.toString();
    });

    process.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    process.on('close', (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(errorOutput);
      }
    });
  });
});

ipcMain.handle('run-pcap-to-caller-info', (event, pcapFile) => {
  return new Promise((resolve, reject) => {
    const process = spawn('python', [path.join(__dirname, 'python_scripts', 'pcap_to_caller_info.py'), pcapFile]);
    
    let output = '';
    let errorOutput = '';

    process.stdout.on('data', (data) => {
      output += data.toString();
    });

    process.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    process.on('close', (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(errorOutput);
      }
    });
  });
});

ipcMain.handle('run-audio-to-text', (event, audioFile) => {
  return new Promise((resolve, reject) => {
    const process = spawn('python', [path.join(__dirname, 'python_scripts', 'audio_to_text.py'), audioFile]);
    
    let output = '';
    let errorOutput = '';

    process.stdout.on('data', (data) => {
      output += data.toString();
    });

    process.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    process.on('close', (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(errorOutput);
      }
    });
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handler for opening the file dialog
ipcMain.handle('open-file-dialog', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({
      properties: ['openFile'], // Allow opening files only
      filters: [
          { name: 'Packet Capture Files', extensions: ['pcap', 'pcapng'] }, // Limit to PCAP/PCAPNG files
      ],
  });

  if (canceled || filePaths.length === 0) {
      return null; // No file selected
  }

  return filePaths[0]; // Return the selected file path
});