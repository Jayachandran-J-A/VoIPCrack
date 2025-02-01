// const { dialog } = require('electron').remote;
const { spawn } = require('child_process');
const { ipcRenderer } = require('electron'); // Import ipcRenderer for communication

function browseFile() {
    ipcRenderer.invoke('open-file-dialog').then((filePath) => {
        if (filePath) {
            const packetInput = document.getElementById('packetInput');
            packetInput.value = filePath; // Update input field with the selected file path
        }
    }).catch((error) => {
        console.error('Error selecting file:', error); // Log any errors
    });
}

function startVoIPServer() {
    const ipInput = document.getElementById('ipInput').value;
    const outputArea = document.getElementById('outputText');
    
    if (!ipInput) {
        outputArea.textContent = 'Please enter a valid SIP address or IP.';
        return;
    }

    outputArea.textContent = 'Starting VoIP server...';
    const pythonProcess = spawn('python', ['path/to/start_voip_server.py', ipInput]);

    pythonProcess.stdout.on('data', (data) => {
        outputArea.textContent = `Server Output: ${data.toString()}`;
    });

    pythonProcess.stderr.on('data', (data) => {
        outputArea.textContent = `Error: ${data.toString()}`;
    });

    pythonProcess.on('close', (code) => {
        outputArea.textContent += `\nProcess exited with code: ${code}`;
    });
}

function showCallerInfo() {
    // Show the Caller Information tab
    document.getElementById('callerInfoTab').style.display = 'block';
}

function showLogsAndAudio() {
    // Show the Logs and Audio tab
    document.getElementById('logsAudioTab').style.display = 'block';
}

function analyze() {
    const packetInput = document.getElementById('packetInput').value;
    const outputArea = document.getElementById('callerInfoOutput');  // Existing Caller Info output box
    const logArea = document.getElementById('logOutput');  // New dedicated area for logs
    const audioPlayer = document.getElementById('audioPlayer'); // Audio player element
    const audioSource = document.getElementById('audioSource'); // Audio source element

    if (!packetInput) {
        outputArea.textContent = 'Please select a valid PCAP file.';
        return;
    }

    outputArea.textContent = 'Analyzing PCAP file...';
    logArea.textContent = ''; // Clear log output before analysis

    // Run the first script: Caller Info extraction
    const callerInfoProcess = spawn('python', ['python_scripts/pcap_to_caller_info.py', packetInput]);

    callerInfoProcess.stdout.on('data', (data) => {
        try {
            const result = JSON.parse(data.toString());

            if (result.error) {
                outputArea.textContent = `Error: ${result.error}`;
                return;
            }

            let resultText = '';

            resultText += `Date: ${result.ip_summary.date}\n`;
            resultText += `Start Time: ${result.ip_summary.start_time}\n`;
            resultText += `End Time: ${result.ip_summary.end_time}\n`;

            resultText += "\nCall Details:\n";
            for (let call_id in result.calls) {
                const callDetails = result.calls[call_id];
                resultText += `\nCall ID: ${call_id}\n`;
                resultText += `From User: ${callDetails.from.user}\n`;
                resultText += `From Address: ${callDetails.from.addr}\n`;
                resultText += `To User: ${callDetails.to.user}\n`;
                resultText += `To Address: ${callDetails.to.addr}\n`;
            }

            outputArea.textContent = resultText;
            showCallerInfo(); // Show Caller Info tab
        } catch (error) {
            console.error('Error parsing Caller Info output:', error);
            outputArea.textContent = 'Error analyzing Caller Info.';
        }
    });

    callerInfoProcess.stderr.on('data', (data) => {
        outputArea.textContent += `\nError: ${data.toString()}`;
    });

    callerInfoProcess.on('close', () => {
        // After Caller Info, proceed to process audio
        const audioProcess = spawn('python', ['python_scripts/pcap_to_audio.py', packetInput]);

        audioProcess.stdout.on('data', (data) => {
            const message = data.toString();
            logArea.textContent += message; // Append log messages to log area
        });

        audioProcess.stderr.on('data', (data) => {
            logArea.textContent += `\nError: ${data.toString()}`;
        });

        audioProcess.on('close', (code) => {
            logArea.textContent += `\nAudio extraction completed with exit code: ${code}`;

            // Update audio player with the extracted audio file
            const audioFilePath = 'output_audio_files/extracted_audio.wav'; // Ensure this matches your script output
            audioSource.src = audioFilePath; // Set audio source
            audioPlayer.load(); // Load the audio file in the player

            // Automatically show Logs and Audio tab
            showLogsAndAudio();
        });
    });
}
