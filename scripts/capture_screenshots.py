"""
Headless browser screenshot script using Edge CDP.
Captures screenshots at 1440px (Desktop) and 390px (Mobile):
- docs/img/dashboard_hero.png & dashboard_hero_390.png
- docs/img/dashboard_poisoned_blocked.png & dashboard_poisoned_blocked_390.png
- docs/img/dashboard_normal_allowed.png & dashboard_normal_allowed_390.png
- docs/img/dashboard_footer.png & dashboard_footer_390.png
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


async def capture_suite(width: int, height: int, suffix: str):
    temp_profile = os.path.join(os.environ["TEMP"], f"edge_cdp_{width}_{int(time.time())}")
    os.makedirs(temp_profile, exist_ok=True)

    proc = subprocess.Popen([
        EDGE_PATH,
        "--headless=new",
        "--disable-gpu",
        f"--remote-debugging-port={PORT}",
        f"--user-data-dir={temp_profile}",
        f"--window-size={width},{height + 100}",
        STREAMLIT_URL,
    ])

    try:
        ws_url = None
        for _ in range(25):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(f"http://localhost:{PORT}/json/list", timeout=1) as resp:
                    tabs = json.loads(resp.read().decode())
                    page_tabs = [
                        t for t in tabs
                        if t.get("type") == "page" and "8505" in t.get("url", "")
                    ]
                    if page_tabs:
                        ws_url = page_tabs[0].get("webSocketDebuggerUrl")
                        break
            except Exception:
                pass

        if not ws_url:
            raise RuntimeError(f"Could not connect to Edge CDP endpoint for width {width}")

        print(f"Connected to CDP page ({width}px): {ws_url}", flush=True)
        async with websockets.connect(ws_url, max_size=30_000_000) as ws:
            await send_cmd(ws, "Page.enable", req_id=1)
            await send_cmd(ws, "Runtime.enable", req_id=2)
            await send_cmd(ws, "Emulation.setDeviceMetricsOverride", {
                "width": width,
                "height": height,
                "deviceScaleFactor": 1,
                "mobile": width <= 500,
            }, req_id=3)

            print(f"Waiting for Streamlit app to render at {width}px...", flush=True)
            for _ in range(30):
                has_hero = await eval_js(
                    ws,
                    "document.querySelectorAll('.hero-container').length > 0",
                    req_id=101,
                )
                if has_hero:
                    break
                await asyncio.sleep(0.5)

            await asyncio.sleep(2)

            # 1. Hero Screenshot (top view)
            await eval_js(ws, "window.scrollTo(0, 0)", req_id=102)
            await asyncio.sleep(1)
            hero_name = "dashboard_hero.png" if suffix == "" else f"dashboard_hero_{suffix}.png"
            hero_path = os.path.join(DOCS_IMG_DIR, hero_name)
            await capture_png(ws, hero_path, req_id=103)

            # 2. Poisoned Email Blocked View (scroll down slightly into Demo)
            print(f"Selecting Poisoned Email at {width}px...", flush=True)
            await eval_js(ws, """
                (() => {
                    const labels = Array.from(document.querySelectorAll("label"));
                    const poisonRadio = labels.find(l => l.textContent.includes("Poisoned Email"));
                    if (poisonRadio) poisonRadio.click();
                    const demoEl = document.getElementById("demo");
                    if (demoEl) demoEl.scrollIntoView({ behavior: 'instant', block: 'start' });
                })()
            """, req_id=104)
            await asyncio.sleep(2)
            blocked_name = "dashboard_poisoned_blocked.png" if suffix == "" else f"dashboard_poisoned_blocked_{suffix}.png"
            blocked_path = os.path.join(DOCS_IMG_DIR, blocked_name)
            await capture_png(ws, blocked_path, req_id=105)

            # 3. Normal Email Allowed View
            print(f"Selecting Normal Email at {width}px...", flush=True)
            await eval_js(ws, """
                (() => {
                    const labels = Array.from(document.querySelectorAll("label"));
                    const normalRadio = labels.find(l => l.textContent.includes("Normal Email"));
                    if (normalRadio) normalRadio.click();
                    const demoEl = document.getElementById("demo");
                    if (demoEl) demoEl.scrollIntoView({ behavior: 'instant', block: 'start' });
                })()
            """, req_id=106)
            await asyncio.sleep(2)
            allowed_name = "dashboard_normal_allowed.png" if suffix == "" else f"dashboard_normal_allowed_{suffix}.png"
            allowed_path = os.path.join(DOCS_IMG_DIR, allowed_name)
            await capture_png(ws, allowed_path, req_id=107)

            # 4. Footer View
            print(f"Scrolling to footer at {width}px...", flush=True)
            await eval_js(ws, """
                (() => {
                    const footer = document.querySelector(".site-footer");
                    if (footer) footer.scrollIntoView({ behavior: 'instant', block: 'end' });
                    else window.scrollTo(0, document.body.scrollHeight);
                })()
            """, req_id=108)
            await asyncio.sleep(1.5)
            footer_name = "dashboard_footer.png" if suffix == "" else f"dashboard_footer_{suffix}.png"
            footer_path = os.path.join(DOCS_IMG_DIR, footer_name)
            await capture_png(ws, footer_path, req_id=109)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()


async def main():
    print("=== CAPTURING 1440px DESKTOP SCREENSHOTS ===", flush=True)
    await capture_suite(width=1440, height=960, suffix="")

    print("=== CAPTURING 390px MOBILE SCREENSHOTS ===", flush=True)
    await capture_suite(width=390, height=844, suffix="390")

    print("All screenshots generated successfully!", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
