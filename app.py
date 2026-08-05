#!/usr/bin/env python3
"""
Victim-VM server for the Network Forensics & Incident Reconstruction project.
Styled like a picoCTF "WebNet" challenge: a real TLS session gets captured,
a private key gets leaked via IDOR, and the session is decrypted after the
fact to recover a "confidential" image with a flag hidden in its EXIF data.

THIS SERVER IS INTENTIONALLY VULNERABLE. Run it ONLY on an isolated,
host-only VirtualBox network (Step 0.2) -- never on a real network.

Runs TWO listeners from the same Flask app:
  - Port 8000, plain HTTP  -> the nice-looking upload/browsing UI.
    (Deliberately NOT on the weak-TLS port: real browsers increasingly
    refuse non-forward-secret cipher suites, so keeping the UI on plain
    HTTP means you can actually look at it in Chrome/Firefox while
    testing. It's not part of the "encrypted session" you're meant to
    capture -- Step 3.1 in the guide already uses curl, not a browser,
    for exactly that reason.)
  - Port 8443, HTTPS, weak RSA-only TLS -> the actual attack surface:
    /private/<file>, /private-key, /download.php. THIS is the traffic
    you capture and later decrypt.

Vulnerabilities, on purpose:
  1. Weak TLS (Step 1.3): RSA key-exchange only, no ECDHE/DHE -> no
     forward secrecy -> a key stolen later decrypts sessions captured
     earlier.
  2. IDOR key leak (Step 1.5): /private-key and /download.php?file=...
     hand back server.key with zero auth.
"""

import os
import ssl
import subprocess
import threading
from flask import Flask, request, send_from_directory, abort, Response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
KEY_PATH = os.path.join(BASE_DIR, "server.key")
CERT_PATH = os.path.join(BASE_DIR, "server.crt")
FLAG_COMMENT = "You Thought it was a secure site -_- Nice!!"

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>victim-vm :: file portal</title>
<style>
  :root {{
    --bg: #0b0f0c;
    --panel: #111813;
    --border: #1f2e22;
    --green: #39ff88;
    --green-dim: #1fae5c;
    --text: #c9d6cd;
    --muted: #6b7d70;
    --danger: #ff5c5c;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    min-height: 100vh;
    background:
      radial-gradient(circle at 20% -10%, rgba(57,255,136,0.08), transparent 40%),
      var(--bg);
    color: var(--text);
    font-family: "JetBrains Mono", "Fira Code", ui-monospace, "Courier New", monospace;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 32px;
  }}
  .card {{
    width: 100%;
    max-width: 560px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    box-shadow: 0 0 0 1px rgba(57,255,136,0.05), 0 20px 60px rgba(0,0,0,0.5);
    overflow: hidden;
  }}
  .titlebar {{
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    background: #0e140f;
    border-bottom: 1px solid var(--border);
  }}
  .dot {{ width: 10px; height: 10px; border-radius: 50%; }}
  .dot.r {{ background: #ff5f56; }}
  .dot.y {{ background: #ffbd2e; }}
  .dot.g {{ background: #27c93f; }}
  .titlebar span.label {{
    margin-left: 8px;
    color: var(--muted);
    font-size: 12px;
    letter-spacing: 0.05em;
  }}
  .content {{ padding: 28px 26px 30px; }}
  .kicker {{
    color: var(--green-dim);
    font-size: 12px;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin: 0 0 6px;
  }}
  h1 {{
    font-size: 20px;
    margin: 0 0 18px;
    color: #eafff2;
    font-weight: 600;
  }}
  h1 .prompt {{ color: var(--green); }}
  .drop {{
    border: 1px dashed var(--border);
    border-radius: 8px;
    padding: 22px;
    text-align: center;
    background: #0d130f;
    transition: border-color 0.15s ease;
  }}
  .drop:hover {{ border-color: var(--green-dim); }}
  input[type="file"] {{
    color: var(--muted);
    font-family: inherit;
    font-size: 13px;
    width: 100%;
  }}
  button {{
    margin-top: 16px;
    width: 100%;
    padding: 11px 16px;
    background: linear-gradient(180deg, #1fae5c, #178a49);
    color: #06120a;
    font-weight: 700;
    border: none;
    border-radius: 6px;
    font-family: inherit;
    font-size: 13px;
    letter-spacing: 0.03em;
    cursor: pointer;
  }}
  button:hover {{ filter: brightness(1.08); }}
  .actions {{
    display: flex;
    gap: 12px;
    margin-top: 16px;
    flex-wrap: wrap;
  }}
  .actions button,
  .actions .btn-link {{
    margin-top: 0;
    flex: 1;
    min-width: 140px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    text-decoration: none;
    text-align: center;
  }}
  .actions .btn-link {{
    background: linear-gradient(180deg, #16201a, #0e150f);
    color: #eafff2;
    border: 1px solid var(--border);
  }}
  .rule {{ border: none; border-top: 1px solid var(--border); margin: 22px 0; }}
  .meta {{
    font-size: 12px;
    line-height: 1.7;
    color: var(--muted);
  }}
  .meta code {{
    color: var(--green);
    background: #0d130f;
    border: 1px solid var(--border);
    padding: 1px 6px;
    border-radius: 4px;
  }}
  .flash {{
    margin-top: 16px;
    padding: 10px 12px;
    border-radius: 6px;
    font-size: 13px;
    background: #0d1a12;
    border: 1px solid var(--green-dim);
    color: var(--green);
  }}
  .flash.err {{
    border-color: var(--danger);
    color: var(--danger);
    background: #1a0d0d;
  }}
  a {{ color: var(--green); }}
</style>
</head>
<body>
  <div class="card">
    <div class="titlebar">
      <div class="dot r"></div><div class="dot y"></div><div class="dot g"></div>
      <span class="label">Welcome to the most secure vault to protect your file!</span>
    </div>
    <div class="content">
      <p class="kicker">secure vault / confidential archive</p>
      <h1><span class="prompt">â—‰</span> protect your confidential information</h1>
      <p class="meta">Store sensitive files in a protected vault and keep your private information organized, guarded, and ready to review whenever you need it.</p>
      <form method="POST" action="/upload" enctype="multipart/form-data">
        <div class="drop">
          <input type="file" name="file" required>
        </div>
        <div class="actions">
          <button type="submit">Protect file</button>
          <a class="btn-link" href="/uploads">View uploads</a>
        </div>
      </form>
      {flash}
      <hr class="rule">
      <p class="meta">
        Your files are stored in the vault area for safekeeping and can be reviewed from the upload view when needed.<br><br>
        This interface remains a simple portal for managing sensitive content while preserving the existing server behavior and transport setup.
      </p>
    </div>
  </div>
</body>
</html>
"""


def render(flash_html=""):
    return PAGE.format(flash=flash_html)


@app.route("/", methods=["GET"])
def index():
    return render()


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        return render('<div class="flash err">No file provided.</div>'), 400

    dest = os.path.join(UPLOAD_DIR, "confidential.jpg")
    f.save(dest)

    # Mirror Step 1.4: embed a hidden marker via exiftool, matching the
    # picoCTF WebNet-style "flag survives after decryption" pattern.
    # Falls back quietly if exiftool isn't installed on this VM yet.
    exif_status = "no marker embedded (exiftool not found -- run: sudo apt install exiftool)"
    try:
        subprocess.run(
            ["exiftool", "-overwrite_original", f"-Comment={FLAG_COMMENT}", dest],
            check=True,
            capture_output=True,
            timeout=10,
        )
        exif_status = "hidden EXIF comment embedded"
    except Exception:
        pass

    return render(
        f'<div class="flash">Saved as confidential.jpg ({exif_status}). '
        f'Now fetch it over the weak-TLS port to generate the traffic you\'ll '
        f'capture:<br><code>curl -k https://&lt;host&gt;:8443/private/confidential.jpg -o daily_download.jpg</code></div>'
    )


@app.route("/uploads")
def view_uploads():
    if not os.path.isdir(UPLOAD_DIR):
        return render('<div class="flash">No uploads have been stored yet.</div>')

    files = sorted(os.listdir(UPLOAD_DIR))
    if not files:
        return render('<div class="flash">No uploads have been stored yet.</div>')

    items = "".join(
        f'<li><a href="/private/{name}" target="_blank"><code>{name}</code></a></li>'
        for name in files
    )
    return render(f'<div class="flash">Stored vault items:<ul>{items}</ul></div>')


@app.route("/private/<path:filename>")
def serve_private(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# --- Vulnerability: IDOR key leak (Step 1.5 / Step 3.4) ---------------------

@app.route("/private-key")
def leak_private_key_simple():
    if not os.path.exists(KEY_PATH):
        abort(404)
    with open(KEY_PATH, "rb") as fh:
        data = fh.read()
    return Response(data, mimetype="application/x-pem-file")


@app.route("/download.php")
def leak_private_key_idor():
    filename = request.args.get("file", "")
    if not filename:
        abort(400, "file parameter required")
    target = os.path.join(BASE_DIR, os.path.basename(filename))
    if not os.path.exists(target):
        abort(404)
    with open(target, "rb") as fh:
        data = fh.read()
    return Response(data, mimetype="application/octet-stream")


def _weak_tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    # RSA key-exchange only -- no ECDHE/DHE anywhere in this list.
    ctx.set_ciphers("AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA")
    ctx.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
    return ctx


def _run_https():
    ctx = _weak_tls_context()
    print("[*] Weak-TLS attack surface on https://0.0.0.0:8443")
    print("    (RSA key-exchange only, no forward secrecy)")
    print("    IDOR: /private-key  and  /download.php?file=server.key")
    app.run(host="0.0.0.0", port=8443, ssl_context=ctx, threaded=True, use_reloader=False)


if __name__ == "__main__":
    if not (os.path.exists(KEY_PATH) and os.path.exists(CERT_PATH)):
        raise SystemExit("server.key / server.crt not found. Run ./setup.sh first.")

    https_thread = threading.Thread(target=_run_https, daemon=True)
    https_thread.start()

    print("[*] Upload UI on http://0.0.0.0:8000 (plain HTTP, browser-friendly)")
    app.run(host="0.0.0.0", port=8000, threaded=True, use_reloader=False)