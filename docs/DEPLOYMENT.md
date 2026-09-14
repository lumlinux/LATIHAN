# Deployment

Mode pengembangan:

```powershell
.\.venv-1\Scripts\python.exe app.py
```

Untuk production nanti:

- gunakan WSGI server
- pindahkan secret ke environment variable
- gunakan reverse proxy
- aktifkan backup terjadwal
- pindahkan SQLite ke DB server jika concurrency meningkat
