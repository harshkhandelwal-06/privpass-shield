FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
# git is needed for history scans of uploaded repositories (.git inside the ZIP)
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p runtime
EXPOSE 8000
# Render/Railway/Fly inject $PORT; locally it defaults to 8000.
# The app runs its own migrations and account setup on start (see app/main.py lifespan).
# --proxy-headers makes the HTTPS scheme visible behind Render's proxy, which passkeys (WebAuthn) require.
CMD ["sh","-c","uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --proxy-headers --forwarded-allow-ips=*"]
