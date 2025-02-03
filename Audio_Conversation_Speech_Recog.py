import argparse
import tkinter as tk
from tkinter import filedialog
import speech_recognition as sr
from pydub import AudioSegment
from pydub.silence import split_on_silence
from deep_translator import GoogleTranslator
import os
import json

class SimpleTranscriber:
    def __init__(self):
        self.recognizer = sr.Recognizer()
        self.translator = GoogleTranslator(source='ta', target='en')

    def detect_speakers(self, audio_segments):
        """Simple speaker detection based on energy levels"""
        speakers = []
        last_speaker = 0
        for i, segment in enumerate(audio_segments):
            energy = segment.dBFS
            if i > 0 and abs(energy - audio_segments[i-1].dBFS) > 5:
                last_speaker = 1 - last_speaker
            speakers.append(f"Speaker_{last_speaker + 1}")
        return speakers

    def translate_text(self, text):
        """Translate text from Tamil to English"""
        try:
            return self.translator.translate(text) if text.strip() else ""
        except Exception as e:
            print(f"Translation error: {e}")
            return text

    def process_audio(self, audio_path):
        """Process audio file and return conversation transcript"""
        try:
            print("\n🔄 **Starting audio processing...**")
            print("🔹 Loading audio file...")
            audio = AudioSegment.from_file(audio_path)

            print("🔹 Splitting audio into segments...")
            segments = split_on_silence(
                audio,
                min_silence_len=500,  # Reduce to capture more speech
                silence_thresh=audio.dBFS - 14,  # Increase threshold to detect more speech
                keep_silence=300
            )

            print("🔹 Detecting speakers...")
            speakers = self.detect_speakers(segments)

            print("🔹 Transcribing segments...")
            conversation = []
            for i, segment in enumerate(segments):
                temp_path = f"temp_segment_{i}.wav"
                segment.export(temp_path, format="wav")

                with sr.AudioFile(temp_path) as source:
                    audio_data = self.recognizer.record(source)
                    try:
                        text = self.recognizer.recognize_google(audio_data, language='ta')
                        translation = self.translate_text(text)

                        transcript_entry = {
                            'speaker': speakers[i],
                            'original': text,
                            'translation': translation,
                            'time': i * len(segment) / 1000.0
                        }
                        conversation.append(transcript_entry)

                        # ✅ Always show output in terminal
                        print("\n🔹 **New Segment**")
                        print(f"👤 Speaker: {transcript_entry['speaker']}")
                        print(f"🕒 Time: {transcript_entry['time']:.2f}s")
                        print(f"🎙 Tamil: {transcript_entry['original']}")
                        print(f"🌍 English: {transcript_entry['translation']}")
                        print("-" * 50)

                    except sr.UnknownValueError:
                        print(f"⚠️ **Could not understand segment {i}** (Possible noise/silence)")
                    except sr.RequestError as e:
                        print(f"❌ Error with speech recognition: {e}")

                os.remove(temp_path)

            return conversation
        except Exception as e:
            print(f"❌ Error processing audio: {e}")
            return []

    def save_transcript(self, conversation, output_path):
        """Save transcript to text and JSON files"""
        try:
            text_output = os.path.join(os.path.dirname(output_path), 'conversation_transcript.txt')
            json_output = os.path.join(os.path.dirname(output_path), 'conversation_transcript.json')

            with open(text_output, 'w', encoding='utf-8') as f:
                f.write("Conversation Transcript\n")
                f.write("=" * 50 + "\n\n")
                for turn in conversation:
                    f.write(f"\n[{turn['speaker']}]\n")
                    f.write(f"🕒 Time: {turn['time']:.2f}s\n")
                    f.write(f"🎙 Tamil: {turn['original']}\n")
                    f.write(f"🌍 English: {turn['translation']}\n")
                    f.write("-" * 50 + "\n")

            with open(json_output, 'w', encoding='utf-8') as f:
                json.dump(conversation, f, ensure_ascii=False, indent=2)

            print(f"\n✅ **Transcript saved to:**")
            print(f"📄 {text_output}")
            print(f"📄 {json_output}")
        except Exception as e:
            print(f"❌ Error saving transcript: {e}")

def browse_file():
    """Open file dialog to select a WAV file"""
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(filetypes=[("WAV files", "*.wav")])
    return file_path

def main():
    parser = argparse.ArgumentParser(description="Transcribe and translate Tamil audio files.")
    parser.add_argument("--audio_path", type=str, help="Path to the audio file (WAV format)")
    args = parser.parse_args()

    audio_path = args.audio_path if args.audio_path else browse_file()
    
    if not audio_path:
        print("❌ No file selected. Exiting...")
        return
    
    transcriber = SimpleTranscriber()
    conversation = transcriber.process_audio(audio_path)

    if conversation:
        transcriber.save_transcript(conversation, audio_path)
    else:
        print("⚠️ No conversation data was processed.")

if __name__ == "__main__":
    main()
