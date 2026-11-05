import os
import subprocess
import time

html_path = os.path.abspath("presentation.html")
pdf_output = os.path.abspath("DUETCLOCK - Information Security Presentation Deck.pdf")

# Remove duplicate PDF if present
duplicate_pdf = os.path.abspath("DUETCLOCK · Information Security Presentation Deck.pdf")
if os.path.exists(duplicate_pdf):
    try:
        os.remove(duplicate_pdf)
        print(f"Removed duplicate PDF: '{duplicate_pdf}'")
    except Exception as e:
        print(f"Note: Could not remove duplicate PDF: {e}")

chrome_candidates = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
]

browser_exe = None
for candidate in chrome_candidates:
    if os.path.exists(candidate):
        browser_exe = candidate
        break

if not browser_exe:
    raise RuntimeError("Neither Chrome nor Edge was found on this system.")

print(f"Using browser: {browser_exe}")
print(f"Source HTML: {html_path}")

cmd = [
    browser_exe,
    "--headless=new",
    "--disable-gpu",
    "--no-pdf-header-footer",
    "--virtual-time-budget=8000",
    "--run-all-compositor-stages-before-draw",
    f"--print-to-pdf={pdf_output}",
    f"file:///{html_path.replace(os.sep, '/')}"
]

print("Running command:", " ".join(cmd))
res = subprocess.run(cmd, capture_output=True, text=True)
time.sleep(1)

if os.path.exists(pdf_output):
    size = os.path.getsize(pdf_output)
    print(f"SUCCESS: Generated '{pdf_output}' ({size:,} bytes)")
else:
    print(f"ERROR: PDF was not created. Stdout: {res.stdout}, Stderr: {res.stderr}")

