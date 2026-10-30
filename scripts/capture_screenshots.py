"""
Headless browser screenshot script using Edge CDP.
Captures screenshots at 1920px, 1440px, 1024px, and 390px:
- hero
- example grid
- BLOCKED verdict
- layer cards
- footer
- scrolled-with-header
Also asserts computed font size of all visible text nodes is >= 14px.
"""

import asyncio
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request

import websockets

EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PORT = 9226
STREAMLIT_URL = "http://localhost:8505"
DOCS_IMG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "img")
os.makedirs(DOCS_IMG_DIR, exist_ok=True)


def ensure_streamlit_running():
    try:
        with urllib.request.urlopen("http://localhost:8505/_stcore/health", timeout=1) as resp:
            if resp.status == 200:
                print("Streamlit already running on http://localhost:8505", flush=True)
                return None
    except Exception:
        pass
    print("Starting Streamlit on port 8505...", flush=True)
    st_proc = subprocess.Popen([
        sys.executable,
        "-m",
        "streamlit",
        "run",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard", "app.py"),
        "--server.port=8505",
        "--server.headless=true",
    ])
    for _ in range(30):
        time.sleep(1)
        try:
            with urllib.request.urlopen("http://localhost:8505/_stcore/health", timeout=1) as resp:
                if resp.status == 200:
                    print("Streamlit successfully started!", flush=True)
                    return st_proc
        except Exception:
            pass
    return st_proc


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


async def assert_no_text_under_14px(ws, width: int):
    js_check = """
    (() => {
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
            acceptNode: (node) => {
                if (!node.textContent || !node.textContent.trim()) return NodeFilter.FILTER_REJECT;
                const el = node.parentElement;
                if (!el) return NodeFilter.FILTER_REJECT;
                const style = window.getComputedStyle(el);
                if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                    return NodeFilter.FILTER_REJECT;
                }
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) return NodeFilter.FILTER_REJECT;
                return NodeFilter.FILTER_ACCEPT;
            }
        });
        const under14 = [];
        while (walker.nextNode()) {
            const node = walker.currentNode;
            const el = node.parentElement;
            const fs = parseFloat(window.getComputedStyle(el).fontSize);
            if (fs < 13.99) {
                under14.push({
                    text: node.textContent.trim().substring(0, 40),
                    tag: el.tagName,
                    className: el.className,
                    fontSize: fs,
                });
            }
        }
        return under14;
    })()
    """
    violations = await eval_js(ws, js_check)
    if violations:
        print(f"[FAIL] Found {len(violations)} text nodes with font size < 14px at {width}px:", flush=True)
        for v in violations[:10]:
            print(f"  - {v['fontSize']}px in <{v['tag']} class='{v.get('className')}'>: '{v['text']}'", flush=True)
        raise AssertionError(f"Detected text elements below 14px at width {width}px!")
    print(f"[PASS] All visible text nodes computed font-size >= 14px at {width}px width.", flush=True)


async def capture_suite_for_width(width: int, height: int, suffix: str):
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

            # Assert font size requirement (nothing below 14px)
            await assert_no_text_under_14px(ws, width)

            # 1. Hero Screenshot (top view)
            await eval_js(ws, """
                (() => {
                    const scroller = document.querySelector('[data-testid="stMain"]') || document.querySelector('main');
                    if (scroller) scroller.scrollTop = 0;
                    window.scrollTo(0, 0);
                })()
            """, req_id=102)
            await asyncio.sleep(1)
            hero_name = f"dashboard_hero_{suffix}.png"
            await capture_png(ws, os.path.join(DOCS_IMG_DIR, hero_name), req_id=103)
            if suffix == "1440":
                await capture_png(ws, os.path.join(DOCS_IMG_DIR, "dashboard_hero.png"), req_id=104)

            # 2. Poisoned Email Blocked Verdict Screenshot
            print(f"Selecting Poisoned Email at {width}px...", flush=True)
            await eval_js(ws, """
                (() => {
                    const tabs = Array.from(document.querySelectorAll('button[data-baseweb="tab"]'));
                    if (tabs.length > 0) tabs[0].click();
                    const labels = Array.from(document.querySelectorAll("label"));
                    const poisonRadio = labels.find(l => l.textContent.includes("Poisoned Email"));
                    if (poisonRadio) poisonRadio.click();
                    const demoEl = document.getElementById("demo");
                    if (demoEl) demoEl.scrollIntoView({ behavior: 'instant', block: 'start' });
                })()
            """, req_id=105)
            await asyncio.sleep(2)
            blocked_name = f"dashboard_poisoned_blocked_{suffix}.png"
            await capture_png(ws, os.path.join(DOCS_IMG_DIR, blocked_name), req_id=106)
            if suffix == "1440":
                await capture_png(ws, os.path.join(DOCS_IMG_DIR, "dashboard_poisoned_blocked.png"), req_id=107)

            # 3. Normal Email Allowed View (for standard widths)
            if suffix in ["1440", "390"]:
                print(f"Selecting Normal Email at {width}px...", flush=True)
                await eval_js(ws, """
                    (() => {
                        const labels = Array.from(document.querySelectorAll("label"));
                        const normalRadio = labels.find(l => l.textContent.includes("Normal Email"));
                        if (normalRadio) normalRadio.click();
                        const demoEl = document.getElementById("demo");
                        if (demoEl) demoEl.scrollIntoView({ behavior: 'instant', block: 'start' });
                    })()
                """, req_id=108)
                await asyncio.sleep(2)
                allowed_name = f"dashboard_normal_allowed_{suffix}.png"
                await capture_png(ws, os.path.join(DOCS_IMG_DIR, allowed_name), req_id=109)
                if suffix == "1440":
                    await capture_png(ws, os.path.join(DOCS_IMG_DIR, "dashboard_normal_allowed.png"), req_id=110)

            # 4. Switch to Interactive Scanner Tab -> Capture Example Grid & Layer Cards
            print(f"Switching to Interactive Scanner Tab at {width}px...", flush=True)
            await eval_js(ws, """
                (() => {
                    const tabs = Array.from(document.querySelectorAll('button[role="tab"], [data-baseweb="tab"], button'));
                    const scannerTab = tabs.find(t => t.textContent && t.textContent.includes("Interactive Content Scanner"));
                    if (scannerTab) {
                        scannerTab.scrollIntoView({ behavior: 'instant', block: 'center' });
                        scannerTab.click();
                        scannerTab.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
                    }
                })()
            """, req_id=111)
            await asyncio.sleep(3)

            # Verify font sizes again on Tab 2
            await assert_no_text_under_14px(ws, width)

            # 4a. Example Grid Screenshot
            print(f"Scrolling to Example Grid at {width}px...", flush=True)
            await eval_js(ws, """
                (() => {
                    const headings = Array.from(document.querySelectorAll('h2, h3, h4, p, span, div'));
                    const exHeading = headings.find(h => h.textContent && h.textContent.includes("Benchmark Example"));
                    if (exHeading) {
                        exHeading.scrollIntoView({ behavior: 'instant', block: 'start' });
                    } else {
                        const scannerEl = document.getElementById("scanner");
                        if (scannerEl) scannerEl.scrollIntoView({ behavior: 'instant', block: 'start' });
                    }
                })()
            """, req_id=112)
            await asyncio.sleep(2)
            ex_grid_name = f"dashboard_example_grid_{suffix}.png"
            await capture_png(ws, os.path.join(DOCS_IMG_DIR, ex_grid_name), req_id=113)
            if suffix == "1440":
                await capture_png(ws, os.path.join(DOCS_IMG_DIR, "dashboard_example_grid.png"), req_id=114)

            # 4b. Layer Cards Screenshot
            print(f"Scrolling to Layer Cards at {width}px...", flush=True)
            await eval_js(ws, """
                (() => {
                    const headings = Array.from(document.querySelectorAll('h2, h3, h4, p, span, div'));
                    const breakdownHeading = headings.find(h => h.textContent && h.textContent.includes("Three-Layer Defense Breakdown"));
                    if (breakdownHeading) {
                        breakdownHeading.scrollIntoView({ behavior: 'instant', block: 'start' });
                    } else {
                        const layerGrid = document.querySelector('.layer-cards-grid');
                        if (layerGrid) layerGrid.scrollIntoView({ behavior: 'instant', block: 'center' });
                    }
                })()
            """, req_id=115)
            await asyncio.sleep(2)
            layer_cards_name = f"dashboard_layer_cards_{suffix}.png"
            await capture_png(ws, os.path.join(DOCS_IMG_DIR, layer_cards_name), req_id=116)
            if suffix == "1440":
                await capture_png(ws, os.path.join(DOCS_IMG_DIR, "dashboard_layer_cards.png"), req_id=117)

            # 5. Scrolled with Header Screenshot (scrolled down ~800px showing 68px header)
            print(f"Scrolling down 800px to capture fixed header view at {width}px...", flush=True)
            await eval_js(ws, """
                (() => {
                    const scroller = document.querySelector('[data-testid="stMain"]') || document.querySelector('main');
                    if (scroller) scroller.scrollTop = 800;
                })()
            """, req_id=118)
            await asyncio.sleep(1.5)
            scrolled_name = f"dashboard_scrolled_header_{suffix}.png"
            await capture_png(ws, os.path.join(DOCS_IMG_DIR, scrolled_name), req_id=119)
            if suffix == "1440":
                await capture_png(ws, os.path.join(DOCS_IMG_DIR, "dashboard_scrolled_header.png"), req_id=120)

            # 6. Footer Screenshot
            print(f"Scrolling to footer at {width}px...", flush=True)
            await eval_js(ws, """
                (() => {
                    const scroller = document.querySelector('[data-testid="stMain"]') || document.querySelector('main');
                    if (scroller) scroller.scrollTop = scroller.scrollHeight;
                })()
            """, req_id=121)
            await asyncio.sleep(2)
            footer_name = f"dashboard_footer_{suffix}.png"
            await capture_png(ws, os.path.join(DOCS_IMG_DIR, footer_name), req_id=122)
            if suffix == "1440":
                await capture_png(ws, os.path.join(DOCS_IMG_DIR, "dashboard_footer.png"), req_id=123)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()


async def main():
    st_proc = ensure_streamlit_running()
    try:
        print("=== CAPTURING 1920px WIDE DESKTOP SCREENSHOTS ===", flush=True)
        await capture_suite_for_width(width=1920, height=1080, suffix="1920")

        print("=== CAPTURING 1440px STANDARD DESKTOP SCREENSHOTS ===", flush=True)
        await capture_suite_for_width(width=1440, height=960, suffix="1440")

        print("=== CAPTURING 1024px TABLET SCREENSHOTS ===", flush=True)
        await capture_suite_for_width(width=1024, height=768, suffix="1024")

        print("=== CAPTURING 390px MOBILE SCREENSHOTS ===", flush=True)
        await capture_suite_for_width(width=390, height=844, suffix="390")

        print("All screenshots generated and validated successfully!", flush=True)
    finally:
        if st_proc:
            print("Stopping background Streamlit process...", flush=True)
            st_proc.terminate()
            try:
                st_proc.wait(timeout=3)
            except Exception:
                st_proc.kill()


if __name__ == "__main__":
    asyncio.run(main())
