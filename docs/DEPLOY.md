# Put PrivPass Shield online (free, about 15 minutes)

Judges are far more likely to open a link than run a zip, and a real HTTPS domain also makes **passkeys** work
on every phone and laptop. The project ships a Render blueprint (`render.yaml`) that deploys a **public demo**:

- production security (Secure cookies, no reset tokens in responses, no generated passwords on the server);
- the shared **demo workspace** with the three demo accounts, demo downloads and simulations;
- **sample data loaded automatically** on a fresh start, so the first screen a judge sees is alive;
- your **private real admin** from two environment variables. It lives in the separate live workspace and never sees demo data.

## Step 1: put the project on GitHub

**Easiest (GitHub Desktop):** install GitHub Desktop → *File → Add local repository* → pick the project folder →
it offers to create a repository → *Publish repository* (you can keep it private).

**Or with git:**
```bash
cd "C:\Users\Harsh Khandelwal\Downloads\priv pass claude"
git init && git add . && git commit -m "PrivPass Shield"
# create an empty repo on github.com first, then:
git remote add origin https://github.com/<you>/privpass-shield.git
git push -u origin main
```
`.env` and `runtime/` are git-ignored, so your API keys, local database and admin password are never uploaded.

> **If GitHub says "push declined: secrets detected"**: the project contains *fake* keys on purpose
> (the scanner's demo and test files). Open the link GitHub prints, choose **"It's used in tests"**, and push again.

## Step 2: deploy on Render
1. Sign in at **render.com** with your GitHub account.
2. **New → Blueprint** → select the repository → **Apply**. Render reads `render.yaml`.
3. When it asks for the secret values:
   - `PRIVPASS_ADMIN_EMAIL`: the email for *your* admin (for example your own email).
   - `PRIVPASS_ADMIN_PASSWORD`: a long passphrase (15+ characters). **This is your real admin login.**
   - `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `ALERT_WEBHOOK_URL`: optional, leave empty if you don't have them.
4. Wait for the first build (5–8 minutes), then open `https://privpass-shield-<something>.onrender.com`.

Check it worked: `https://…onrender.com/api/health` shows `"env":"production","demo":true`.

## Step 3: before you present
- **Wake it up 2 minutes early.** Free Render instances sleep after ~15 idle minutes; the first request takes ~30–60 s.
- Open the site → **▶ Guided tour**. It signs in as the demo admin and walks through all 15 steps with sample data.
- Command Center → **Load demo data** restores the sample story any time; **Remove simulation data** clears it.
- Sign in with your real admin in a private window to show that it sees *none* of the demo data.

## What to know about the free plan
- **Data is temporary.** SQLite lives on the instance disk, which resets when the instance restarts or redeploys.
  The demo reseeds itself automatically; accounts people create are lost on a restart. For permanent data create a
  Render **PostgreSQL** database and set `DATABASE_URL` to its connection string (the `psycopg` driver is already installed).
- **Passkeys are tied to the domain.** Passkeys created on `localhost` don't work on the Render URL and the other way round.
- **Password reset** for real accounts sends no email in this build, so on the public site it only confirms the request.
  (Locally, development mode shows the reset link on screen.)

## Breach watch on a server
The server now contacts `api.pwnedpasswords.com` itself (HTTPS, only 5-character prefixes), so the host needs outbound
internet. Render, Railway and Fly all allow it. `PRIVPASS_BREACH_WATCH_MINUTES` (default `360`) sets how often every account
is re-checked in the background; `0` turns the schedule off (sign-in checks and the admin button still work).

## Settings reference
| Variable | Public demo (render.yaml) | Meaning |
|---|---|---|
| `APP_ENV` | `production` | Production security. `development` is only for your laptop. |
| `PRIVPASS_PUBLIC_DEMO` | `true` | Keep the demo workspace, demo downloads and simulations in production. Set `false` for a real deployment. |
| `PRIVPASS_DEMO_AUTOSEED` | `true` | Load the sample story when the demo workspace is empty at start-up. |
| `PRIVPASS_ADMIN_EMAIL` / `PRIVPASS_ADMIN_PASSWORD` | you choose | Your private real admin (live workspace). Required in production. |
| `COOKIE_SECURE` | `true` | Cookies only over HTTPS. |
| `APP_SECRET` | generated | Signs sessions, encrypts verifiers and seals breach-watch data. Keep it stable between deploys. |
| `PRIVPASS_BREACH_WATCH_MINUTES` | `360` | How often the server re-checks every account against HIBP (`0` = only at sign-in / on demand). |

## Other hosts (Railway, Fly.io, a VM)
```bash
docker build -t privpass-shield .
docker run -p 8000:8000 -e APP_ENV=production -e PRIVPASS_PUBLIC_DEMO=true -e PRIVPASS_DEMO_AUTOSEED=true \
  -e APP_SECRET=<long random string> -e COOKIE_SECURE=true \
  -e PRIVPASS_ADMIN_EMAIL=you@example.com -e PRIVPASS_ADMIN_PASSWORD='<15+ character passphrase>' privpass-shield
```
The container honours `$PORT`, trusts the proxy's `X-Forwarded-Proto` (needed for passkeys behind HTTPS), and
`.dockerignore` keeps `.env` and `runtime/` out of the image.
