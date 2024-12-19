import librosa
import soundfile as sf
import whisper
import numpy as np
import os

def separate_audio_channels(audio_path):
    # Load the audio file
    audio, sample_rate = librosa.load(audio_path, mono=False)
    
    # If the audio is not stereo, raise an error
    if audio.ndim != 2:
        raise ValueError("Input audio must be a stereo file with two channels")
    
    # Extract left and right channels
    left_channel = audio[0]
    right_channel = audio[1]
    
    return left_channel, right_channel, sample_rate

def save_channel_audio(channel_audio, sample_rate, output_path):
    sf.write(output_path, channel_audio, sample_rate)

def transcribe_audio(audio_path, model='base'):
    # Load the Whisper model
    whisper_model = whisper.load_model(model)
    
    # Transcribe the audio
    result = whisper_model.transcribe(audio_path, 
                                      verbose=False, 
                                      word_timestamps=True)
    
    return result

def generate_conversation_transcript(left_transcription, right_transcription):
    # Combine and sort all words from both transcriptions
    all_words = []
    
    for segments in [left_transcription['segments'], right_transcription['segments']]:
        for segment in segments:
            for word in segment['words']:
                all_words.append({
                    'timestamp': word['start'],
                    'text': word['word'].strip(),
                    'speaker': 'person1' if segments == left_transcription['segments'] else 'person2'
                })
    
    # Sort words by timestamp
    all_words.sort(key=lambda x: x['timestamp'])
    
    # Format the conversation transcript
    conversation_transcript = [
        f"{word['timestamp']:.3f} - {word['speaker']}: {word['text']}"
        for word in all_words
    ]
    
    return conversation_transcript

def main(input_audio_path):
    # Create output directory if it doesn't exist
    os.makedirs('output', exist_ok=True)
    
    # Separate audio channels
    left_channel, right_channel, sample_rate = separate_audio_channels(input_audio_path)
    
    # Save individual channel audio files
    left_audio_path = 'output/left_channel.wav'
    right_audio_path = 'output/right_channel.wav'
    
    save_channel_audio(left_channel, sample_rate, left_audio_path)
    save_channel_audio(right_channel, sample_rate, right_audio_path)
    
    # Transcribe each channel
    left_transcription = transcribe_audio(left_audio_path)
    right_transcription = transcribe_audio(right_audio_path)
    
    # Generate conversation transcript
    conversation_transcript = generate_conversation_transcript(
        left_transcription, 
        right_transcription
    )
    
    # Print and save the transcript
    print("Conversation Transcript:")
    for line in conversation_transcript:
        print(line)
    
    # Optional: Save transcript to a file
    with open('conversation_transcript.txt', 'w') as f:
        f.write('\n'.join(conversation_transcript))

# Example usage
if __name__ == "__main__":
    input_audio_file = "Conversation.wav"
    main(input_audio_file)
