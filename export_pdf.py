import os
import subprocess
import time

html_path = os.path.abspath("presentation.html")
# We will output to both the original filename and a clean filename
pdf_names = [
    "DUETCLOCK · Information Security Presentation Deck.pdf",
    "DUETCLOCK - Information Security Presentation Deck.pdf"
]

chrome_candidates = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
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

primary_output = os.path.abspath(pdf_names[0])

cmd = [
    browser_exe,
    "--headless=new",
    "--disable-gpu",
    "--no-pdf-header-footer",
    f"--print-to-pdf={primary_output}",
    f"file:///{html_path.replace(os.sep, '/')}"
]

print("Running command:", " ".join(cmd))
res = subprocess.run(cmd, capture_output=True, text=True)
time.sleep(1)

if os.path.exists(primary_output):
    size = os.path.getsize(primary_output)
    print(f"SUCCESS: Generated '{pdf_names[0]}' ({size:,} bytes)")
    
    # Also write clean ASCII filename for compatibility
    import shutil
    clean_output = os.path.abspath(pdf_names[1])
    shutil.copy2(primary_output, clean_output)
    print(f"SUCCESS: Copied to '{pdf_names[1]}'")
else:
    print(f"ERROR: PDF was not created. Stdout: {res.stdout}, Stderr: {res.stderr}")

