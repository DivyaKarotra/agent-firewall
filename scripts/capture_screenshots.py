"""
Headless browser screenshot script using Edge CDP.
Captures:
1. docs/img/dashboard_poisoned_blocked.png
2. docs/img/dashboard_normal_allowed.png
"""

import asyncio
import base64
import json
import os
import subprocess
import time
import urllib.request

import websockets

EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PORT = 9226
STREAMLIT_URL = "http://localhost:8505"
DOCS_IMG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "img")
os.makedirs(DOCS_IMG_DIR, exist_ok=True)


async def send_cmd(ws, method, params=None, req_id=1, timeout=15):
    payload = {"id": req_id, "method": method, "params": params or {}}
    await ws.send(json.dumps(payload))
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            data = json.loads(resp)
            if data.get("id") == req_id:
                if "error" in data:
                    print(f"[ERROR] CDP {method} failed: {data['error']}", flush=True)
                    return None
                return data.get("result", {})
        except asyncio.TimeoutError:
            pass
    print(f"[TIMEOUT] Waiting for response to req_id {req_id} ({method})", flush=True)
    return None


async def eval_js(ws, js_code, req_id=100):
    res = await send_cmd(ws, "Runtime.evaluate", {"expression": js_code, "returnByValue": True}, req_id=req_id)
    if res and "result" in res:
        return res["result"].get("value")
    return None


async def capture_png(ws, file_path, req_id=200):
    print(f"Capturing screenshot to {os.path.basename(file_path)}...", flush=True)
    res = await send_cmd(ws, "Page.captureScreenshot", {"format": "png"}, req_id=req_id, timeout=20)
    if res and "data" in res:
        data = base64.b64decode(res["data"])
        with open(file_path, "wb") as f:
            f.write(data)
        print(f"Successfully saved: {file_path} ({len(data)} bytes)", flush=True)
    else:
        print(f"Failed to capture screenshot for {file_path}: {res}", flush=True)


async def main():
    temp_profile = os.path.join(os.environ["TEMP"], f"edge_cdp_{int(time.time())}")
    os.makedirs(temp_profile, exist_ok=True)

    proc = subprocess.Popen([
        EDGE_PATH,
        "--headless=new",
        "--disable-gpu",
        f"--remote-debugging-port={PORT}",
        f"--user-data-dir={temp_profile}",
        "--window-size=1280,1050",
        STREAMLIT_URL,
    ])

    try:
        ws_url = None
        for _ in range(25):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(f"http://localhost:{PORT}/json/list", timeout=1) as resp:
                    tabs = json.loads(resp.read().decode())
                    if tabs:
                        ws_url = tabs[0].get("webSocketDebuggerUrl")
                        if ws_url:
                            break
            except Exception:
                pass

        if not ws_url:
            raise RuntimeError("Could not connect to Edge CDP endpoint")

        print(f"Connected to CDP: {ws_url}", flush=True)
        async with websockets.connect(ws_url, max_size=30_000_000) as ws:
            await send_cmd(ws, "Page.enable", req_id=1)
            await send_cmd(ws, "Runtime.enable", req_id=2)
            await send_cmd(ws, "Emulation.setDeviceMetricsOverride", {
                "width": 1280,
                "height": 950,
                "deviceScaleFactor": 1,
                "mobile": False,
            }, req_id=3)

            print("Waiting for Streamlit app to load...", flush=True)
            for _ in range(30):
                has_tabs = await eval_js(ws, "document.querySelectorAll('button[data-baseweb=\"tab\"]').length > 0", req_id=101)
                if has_tabs:
                    break
                await asyncio.sleep(0.5)

            await asyncio.sleep(2)

            # --- Screenshot 1: Poisoned Email Blocked ---
            print("Switching to Demo tab...", flush=True)
            await eval_js(ws, """
                (() => {
                    const tabs = Array.from(document.querySelectorAll("button[data-baseweb='tab']"));
                    const demoTab = tabs.find(t => t.textContent.includes("Unprotected vs Protected"));
                    if (demoTab) demoTab.click();
                })()
            """, req_id=102)
            await asyncio.sleep(2)

            print("Clicking Simulate Agent Tool Execution for Poisoned Email...", flush=True)
            await eval_js(ws, """
                (() => {
                    const btns = Array.from(document.querySelectorAll("button"));
                    const runBtn = btns.find(b => b.textContent.includes("Simulate Agent Tool Execution"));
                    if (runBtn) runBtn.click();
                })()
            """, req_id=103)
            await asyncio.sleep(3)

            blocked_path = os.path.join(DOCS_IMG_DIR, "dashboard_poisoned_blocked.png")
            await capture_png(ws, blocked_path, req_id=104)

            # --- Screenshot 2: Normal Email Allowed ---
            print("Selecting Normal Email radio option...", flush=True)
            await eval_js(ws, """
                (() => {
                    const labels = Array.from(document.querySelectorAll("label"));
                    const normalRadio = labels.find(l => l.textContent.includes("Normal Email"));
                    if (normalRadio) normalRadio.click();
                })()
            """, req_id=105)
            await asyncio.sleep(2)

            print("Clicking Simulate Agent Tool Execution for Normal Email...", flush=True)
            await eval_js(ws, """
                (() => {
                    const btns = Array.from(document.querySelectorAll("button"));
                    const runBtn = btns.find(b => b.textContent.includes("Simulate Agent Tool Execution"));
                    if (runBtn) runBtn.click();
                })()
            """, req_id=106)
            await asyncio.sleep(3)

            allowed_path = os.path.join(DOCS_IMG_DIR, "dashboard_normal_allowed.png")
            await capture_png(ws, allowed_path, req_id=107)

        print("Finished screenshot routine successfully!", flush=True)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    asyncio.run(main())
