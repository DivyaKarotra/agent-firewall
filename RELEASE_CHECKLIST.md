# Release Checklist for agent-firewall

A step-by-step operational checklist for publishing `agent-firewall` to GitHub, PyPI, Hugging Face, and social channels.

---

## 1. Create GitHub Repository and Push Code

```bash
# 1.1 Verify you are on the main branch with a clean git status
git status

# 1.2 Create the remote repository on GitHub using GitHub CLI (or via github.com/new)
gh repo create agent-firewall --public --source=. --remote=origin --description "A risk-aware firewall for LLM agent tool calls (prompt injection defence)"

# 1.3 Push code and tags to GitHub
git branch -M main
git push -u origin main
```

---

## 2. Enable GitHub Actions and GitHub Pages

1. **GitHub Actions (CI)**:
   - Navigate to `https://github.com/DivyaKarotra/agent-firewall/actions`.
   - Ensure the `CI` workflow (`.github/workflows/ci.yml`) runs and passes on `main`.
2. **GitHub Pages (Documentation Site)**:
   - **Step 1**: In the GitHub repository, navigate to **Settings** $\rightarrow$ **Pages**.
   - **Step 2**: Under **Build and deployment**, set **Source** to **GitHub Actions** (uses `.github/workflows/docs.yml` with `actions/upload-pages-artifact` and `actions/deploy-pages`).
   - **Step 3**: Push to `main` (or run **Deploy Documentation** via the **Actions** tab) and verify docs are live at `https://DivyaKarotra.github.io/agent-firewall/`.

---

## 3. Publish to PyPI (via Trusted Publishing or Token) - [x] Completed (live on PyPI as `agent-firewall-cascade` 0.1.0)

### Option A: Trusted Publishing via GitHub Actions (Recommended)
1. Go to [pypi.org/manage/account/publishing/](https://pypi.org/manage/account/publishing/).
2. Add a new pending publisher:
   - PyPI Project Name: `agent-firewall-cascade`
   - Owner: `DivyaKarotra`
   - Repository name: `agent-firewall`
   - Workflow name: `release.yml`
3. Create a GitHub release or tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

### Option B: Manual Publishing via Twine
```bash
# 3.1 Build clean artifacts
python -m build

# 3.2 Verify artifacts
python -m twine check dist/*

# 3.3 (Optional) Test on TestPyPI first
python -m twine upload --repository testpypi dist/*

# 3.4 Upload to production PyPI
python -m twine upload dist/*
```

---

## 4. Upload Dataset to Hugging Face Hub - [x] Completed (live on Hugging Face as DivyaKarotra/agent-firewall-benchmark)

Live at: https://huggingface.co/datasets/DivyaKarotra/agent-firewall-benchmark

```bash
# 4.1 Prepare the formatted dataset directory
python scripts/prepare_hf_dataset.py --output-dir hf_dataset

# 4.2 Log in to Hugging Face CLI (requires your HF write token)
huggingface-cli login

# 4.3 Create the dataset repository on Hugging Face Hub
huggingface-cli repo create agent-firewall-benchmark --type dataset

# 4.4 Upload the dataset directory
huggingface-cli upload DivyaKarotra/agent-firewall-benchmark hf_dataset . --repo-type dataset
```

## 5. Publish Social Announcements & Technical Posts

1. **Blog Post**:
   - Copy contents from [publish/blog_post.md](publish/blog_post.md) to your personal blog, Medium, Substack, or Dev.to.
   - Replace placeholder blog link (`YOUR_BLOG_URL`) with your live URL.
2. **LinkedIn Announcement**:
   - Copy contents from [publish/linkedin_post.md](publish/linkedin_post.md).
   - Paste into LinkedIn and verify preview cards for the GitHub repository and blog post.
3. **Resume Updates**:
   - Review [publish/resume_bullets.md](publish/resume_bullets.md) and integrate matching bullet points into your CV.
4. **Interview Preparation**:
   - Reference [publish/interview_qa.md](publish/interview_qa.md) for technical discussions and architecture walkthroughs.

---

## 6. Keeping the Demo Awake

The public Streamlit Community Cloud demo (`https://agent-firewall.streamlit.app/`) automatically goes to sleep after ~12 hours of inactivity.

A dedicated GitHub Actions workflow [keep-awake.yml](.github/workflows/keep-awake.yml) prevents dormancy:

1. **How It Works**:
   - Runs every 6 hours (`cron: "17 */6 * * *"`) using headless Chromium (Playwright).
   - Opens `https://agent-firewall.streamlit.app/`.
   - If Streamlit shows the wake-up button (`"Yes, get this app back up!"`), clicks it and logs `"App was asleep; woke it"`. Otherwise logs `"App already awake"`.
   - Waits up to 120 seconds for the app text `"AgentFirewall"` to render, remains on the page for ~20 seconds to establish an active session, and logs `"OK: app content loaded"`.
2. **Default Branch Requirement**:
   - GitHub Actions scheduled cron workflows run **only** from the repository's default branch (`main`).
3. **60-Day Inactivity Rule**:
   - GitHub automatically disables scheduled workflows on public repositories after 60 days of repository inactivity (no commits). A commit or push to the repository re-enables them.
4. **Manual Dispatch**:
   - The workflow can be triggered manually at any time from the **Actions** tab $\rightarrow$ **Keep demo awake** $\rightarrow$ **Run workflow**.

