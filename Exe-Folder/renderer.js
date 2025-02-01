const captureBtn = document.getElementById('capture-btn');
const ipInput = document.getElementById('ip-input');
const captureStatus = document.getElementById('capture-status');
const callerInfoDisplay = document.getElementById('caller-info-display');
const convertAudioBtn = document.getElementById('convert-audio-btn');
const audioTextDisplay = document.getElementById('audio-text-display');
const analyzeBtn = document.getElementById('analyze-btn'); // Add this to select the "Analyze" button
const audioPlayer = document.getElementById('audioPlayer'); // Add this for the audio player
const audioSource = document.getElementById('audioSource'); // Add this to manage audio source

let currentPcapFile = null;

captureBtn.addEventListener('click', async () => {
    const ip = ipInput.value;
    if (!ip) {
        captureStatus.textContent = 'Please enter an IP address';
        return;
    }

    try {
        captureStatus.textContent = 'Capturing packets...';
        const result = await window.require('electron').ipcRenderer.invoke('run-pcap-capture', [ip]);
        
        currentPcapFile = result.trim(); // Assuming script returns pcap file path
        captureStatus.textContent = `Packet capture complete: ${currentPcapFile}`;

        // Automatically attempt to get caller info
        const callerInfo = await window.require('electron').ipcRenderer.invoke('run-pcap-to-caller-info', [currentPcapFile]);
        callerInfoDisplay.textContent = callerInfo;
    } catch (error) {
        captureStatus.textContent = `Error: ${error}`;
    }
});

analyzeBtn.addEventListener('click', async () => {
    if (!currentPcapFile) {
        captureStatus.textContent = 'Please capture packets first';
        return;
    }

    try {
        captureStatus.textContent = 'Analyzing...';

        // Run both Python scripts in parallel
        const audioResultPromise = window.require('electron').ipcRenderer.invoke('run-pcap-to-audio', [currentPcapFile]);
        const callerInfoPromise = window.require('electron').ipcRenderer.invoke('run-pcap-to-caller-info', [currentPcapFile]);

        // Wait for both scripts to complete
        const [audioResult, callerInfo] = await Promise.all([audioResultPromise, callerInfoPromise]);
        console.log('Audio conversion result:', audioResult);
        console.log('Caller info result:', callerInfo);

        // Once the audio is extracted, load and play the file in the UI
        const audioFilePath = 'output_audio_files/extracted_audio.wav'; // This should match your output path
        audioSource.src = audioFilePath; // Set the audio source
        audioPlayer.load(); // Reload the audio player
        audioPlayer.play(); // Automatically play the audio

        // Update caller info display
        callerInfoDisplay.textContent = callerInfo;
    } catch (error) {
        captureStatus.textContent = `Error during analysis: ${error}`;
    }
});

convertAudioBtn.addEventListener('click', async () => {
    if (!currentPcapFile) {
        audioTextDisplay.textContent = 'Please capture packets first';
        return;
    }

    try {
        // Assumes previous step created an audio file
        const audioTextResult = await window.require('electron').ipcRenderer.invoke('run-audio-to-text', [currentPcapFile.replace('.pcap', '.wav')]);
        audioTextDisplay.textContent = audioTextResult;
    } catch (error) {
        audioTextDisplay.textContent = `Error converting audio: ${error}`;
    }
});
