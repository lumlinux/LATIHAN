import os
from faster_whisper import WhisperModel

script_dir = os.path.dirname(os.path.abspath(__file__))
video_file = os.path.join(script_dir, "meeting.mp4")

if not os.path.exists(video_file):
    print("File video tidak ditemukan:")
    print(video_file)
    print("\nPastikan file meeting.mp4 ada di folder yang sama dengan script ini.")
    print("Kalau nama file berbeda, ubah variabel video_file di file ini.")
    available = [f for f in os.listdir(script_dir) if f.lower().endswith((".mp4", ".mp3", ".m4a", ".wav", ".mov"))]
    if available:
        print("File media yang ditemukan:", available)
    raise SystemExit(1)

# Pilih model
model_size = "medium"

print("Memuat model Whisper...")
model = WhisperModel(model_size, compute_type="int8")

print("Memulai transkripsi...")
segments, info = model.transcribe(
    video_file,
    language="id",
    beam_size=5,
)

# Simpan ke TXT
base_name = os.path.splitext(video_file)[0]
txt_output = base_name + ".txt"

with open(txt_output, "w", encoding="utf-8") as f:
    for segment in segments:
        f.write(segment.text.strip() + "\n")

print(f"Selesai! Hasil tersimpan di: {txt_output}")