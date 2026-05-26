# LogSec (ai-sec-analyzer)

An enterprise-grade, decentralized **Log Ingestion & Real-Time AI Security Analyst** built with Next.js 14 App Router, TypeScript, Vanilla CSS, PostgreSQL + pgvector, and BullMQ background workers. 

Designed for Security Operations Center (SOC) teams, `ai-sec-analyzer` automatically ingests unstructured system, web application, and Cloud logs, sniffs their formats, runs multi-stage threat signature detectors, index-stores logs chunks as high-dimensional OpenAI embeddings, and feeds a real-time conversational GPT-4o Security Analyst Chatbot using dynamic pgvector Retrieval-Augmented Generation (RAG).

---

## 🛠 Architectural Pipeline Diagram

```
       [Raw Logs File Upload] (.log, .json, .csv, .txt)
                  │
                  ▼
   [ sniffer.sniffFormat() Ingestion Gateway ]
                  │
                  ├──► Syslog Parser (RFC 5424/BSD)
                  ├──► Apache/Nginx Combined Parser
                  ├──► AWS CloudTrail JSON Event Parser
                  └──► Generic key=value Fallback Parser
                  │
                  ▼
         [ PostgreSQL DB ] ──► Store parsed LogEntries
                  │
                  ▼
     [ Signature Scanning Rules Engine ]
                  │
                  ├──► SSH_BRUTE_FORCE (>10 failed attempts / IP / 5m)
                  ├──► WEB_BRUTE_FORCE (>20 HTTP 401/403 / IP / 5m)
                  ├──► PORT_SCAN (>20 distinct ports / IP / 1m)
                  ├──► PRIVILEGE_ESCALATION (sudo/su -/passwd vectors)
                  └──► OFF_HOURS_ACCESS (Operator login 23:00 - 05:00 UTC)
                  │
                  ▼
         [ PostgreSQL DB ] ──► Persist Findings & Alerts
                  │
                  ▼
     [ Sliding-Window Chunking (75 lines, 15 overlap) ]
                  │
                  ▼
     [ OpenAI text-embedding-3-small Embeddings Pipeline ]
                  │
                  ▼
         [ PostgreSQL DB ] ──► Store vectors inside pgvector schema
                  │
                  ▼
       =======================================
       │    REAL-TIME FORENSICS CHAT INTERFACE │
       =======================================
                  │
        [ Operator Query Input ] 
                  │
                  ▼
     [ embedText() Search Embedding ] ──► pgvector Cosine Similarity
                  │
                  ▼
       [ assembleContext() (Capped 6k tokens) ]
                  │
                  ▼
   [ GPT-4o Streaming CISO Threat Report ] ──► Render Formatted Reports
                                           ──► Log Q&A to qa_history
                                           ──► Stream Report PDF Exporter
```

---

## ⚡ Features & Capabilities

- **Automated Snout Sniffer & Ingestion**: Drag-and-drop log uploader with auto-detected formats (RFC 5424, Nginx/Apache Combined, AWS CloudTrail, Generic KV pairs).
- **BullMQ Background Processing**: Multi-stage worker queue emitting SSE live progress events (reading, sniffing, parsing, scanning, vectorizing, completing).
- **pgvector Vector Database Indices**: Custom Cosine Similarity HNSW index mapping to semantic search targets.
- **Upstash Edge Rate Limiting**: Multi-tier edge limiters protecting APIs dynamically (20 Q&As/hr, 10 uploads/day, 5 PDF reports/day).
- **NextAuth Secure Access**: Persisted OAuth (Google & GitHub) credentials guarding dashboard analytics routes.
- **Executive PDF Report Exporter**: One-click dynamic PDF incident reports featuring custom covers, CISO executive summaries, threat logs lists, chronologies, and Appendix IOC lists.

---

## 🔧 Environment Configuration Parameters

Copy `.env.example` to `.env.local` and configure these variables:

| Variable | Description | Example / Default |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL connection string with pgvector enabled | `postgresql://postgres:postgres@localhost:5432/db` |
| `OPENAI_API_KEY` | OpenAI API access token | `sk-proj-...` |
| `REDIS_URL` | Redis broker URL for BullMQ jobs | `redis://127.0.0.1:6379` |
| `UPSTASH_REDIS_REST_URL` | Edge-compatible Upstash Redis endpoint URL | `https://...upstash.io` |
| `UPSTASH_REDIS_REST_TOKEN` | Edge-compatible Upstash API credential token | `AgVk...` |
| `NEXTAUTH_URL` | Root URL of deployment client | `http://localhost:3000` |
| `NEXTAUTH_SECRET` | NextAuth session signing key | `openssl rand -hex 32` |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID | `cb82...` |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret | `4ea1...` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | `1039...` |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | `GOCSPX-...` |

---

## 📖 Step-by-Step Installation & Operations Guide

Follow these steps to set up `ai-sec-analyzer` on your local system from scratch:

### Step 1: Install System Prerequisites
Make sure your development machine is equipped with:
- **Node.js**: Version 18.0 or higher.
- **PostgreSQL**: Version 12+ with the `pgvector` extension compiled.
  > [!TIP]
  > On macOS, install pgvector using `brew install pgvector`. On Windows, pgvector is included automatically in EnterpriseDB installers, or you can install it using pre-compiled binaries from the pgvector GitHub page.
- **Redis Server**: Version 6.0+ running on port `6379`.

### Step 2: Clone & Install Dependencies
Open your local terminal and execute:
```bash
# Clone the repository
git clone https://github.com/your-username/ai-sec-analyzer.git
cd ai-sec-analyzer

# Install package definitions
npm install
```

### Step 3: Configure Environment
Create a `.env.local` file by copying the template:
```bash
cp .env.example .env.local
```
Fill out the parameters inside `.env.local` (such as `DATABASE_URL`, `OPENAI_API_KEY`, `REDIS_URL`, and NextAuth credentials).

### Step 4: Run Database Migrations
Start your PostgreSQL instance and make sure the `vector` extension is registered:
```sql
CREATE EXTENSION IF NOT EXISTS vector;
```
The application will automatically build all required tables (`sessions`, `log_entries`, `findings`, `chunks`, `qa_history`, and `users`) and indexes on startup!
To force a manual, idempotent database rebuild, simply execute our Jest suite:
```bash
npm run test
```

### Step 5: Start the BullMQ Async Worker
Open a secondary terminal pane in your project workspace and launch the background task queue processor:
```bash
npx ts-node -r tsconfig-paths/register lib/queue/worker.ts
```
> [!NOTE]
> The worker listens on the `log-processing` Redis channel, executing parsing, threat scanning, embedding, and vector insertion steps in the background.

### Step 6: Launch the Forensic Simulation test
To see the analyzer process a real multi-stage attack (SSH brute force + Sudo privilege escalation) and generate local incident logs, execute:
```bash
npx jest __tests__/real_problem.test.ts
```
This script immediately:
1. Sniffs and parses 15 real BSD syslog entries chronologically.
2. Identifies matching threat signatures.
3. Spits out overlapping sliding window chunks.
4. Saves a structured JSON report to the workspace root: [`Incident_Report_Real_Problem.json`](file:///d:/AK5/LogSec/ai-sec-analyzer/Incident_Report_Real_Problem.json).

### Step 7: Start the Frontend App Dev Server
Run the local next development environment:
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) inside your web browser. 

---

## 🖥 Dashboard Operations & Interface Guide

When you open the web application, follow this operational checklist:

1. **OAuth Operator Sign-in**: Sign in using GitHub or Google credentials. The system automatically upserts your operator email into the PostgreSQL `users` registry.
2. **Log File Ingestion**: Click the drag-and-drop zone and select a log file (e.g. `.log`, `.txt`, or `.json` up to 10MB).
3. **Sniffer & Pipeline Progress**: The Sniffing gateway determines the log structure. The dashboard will show live progress loaders (BullMQ socket events) indicating parsing, rules signatures, and embedding vector operations.
4. **Forensics Tab & PDF Export**: Once complete, review findings. Press the **"EXPORT PDF"** button to automatically fetch dynamic OpenAI executive CISO summaries and download an incident PDF report.
5. **Interactive RAG Threat Q&A**: Navigate to the Q&A tab and ask the AI Analyst questions like: *"Which IP address executed sudo commands, and what was the impact?"* The database executes similarity cosine searches over the `chunks` index, feeding contextual evidence to the GPT-4o streaming model.

---

## ☁ Deploying to Vercel & Railway

### Deploy PostgreSQL & Redis on Railway
1. Sign in to [Railway.app](https://railway.app/).
2. Click **New Project** -> Select **Provision PostgreSQL**.
3. Under the PostgreSQL settings, access the Query Editor or connect via psql and make sure `pgvector` is enabled:
   ```sql
   CREATE EXTENSION IF NOT EXISTS vector;
   ```
4. Click **New Service** -> Select **Provision Redis**.
5. Copy both the `DATABASE_URL` and `REDIS_URL` connection parameters.

### Deploy Frontend on Vercel
1. Push your code repository to GitHub/Google.
2. Sign in to [Vercel](https://vercel.com/) and choose **Add New Project** -> Select your `ai-sec-analyzer` repository.
3. Add all parameters listed inside the Environment Configuration table to Vercel's **Environment Variables** panel.
4. Click **Deploy**. Vercel will build the Next.js production bundles and serve your dashboard immediately.

---

## 🧠 How it Works: The RAG Pipeline Explained in Plain English

**Retrieval-Augmented Generation (RAG)** is the technique of feeding relevant historical database facts directly to a large language model (LLM like GPT-4o) so that its answers are accurate, grounded, and free of hallucinations.

Here is exactly how `ai-sec-analyzer` executes this in 4 clear stages:

1. **Sliding-Window Logs Chunking**: Large log files are impossible to send to an LLM all at once because of size limits. The analyzer slides a "window" of **75 log lines** down the file, keeping a **15-line overlap** between consecutive windows to make sure no threat alert context is cut in half. These windows are joined together with newline (`\n`) characters as text chunks.
2. **Generating Vector Embeddings**: Each text chunk is sent to OpenAI's `text-embedding-3-small` model, which converts the text into a **1,536-dimensional array of numbers (an embedding)**. This vector represents the *semantic meaning* of the logs. For example, a chunk containing SSH failed login attempts will have a vector very similar to another chunk containing password brute-forcing, even if the actual IP addresses or log formats are completely different.
3. **pgvector Indexing**: These vectors are saved directly inside a PostgreSQL table using a special database index called `HNSW` (Hierarchical Navigable Small World). This lets the database query millions of log records instantly.
4. **Context Retrieval & GPT-4o Streaming**: When a security analyst asks a question (like *"Is there evidence of privilege escalation?"*), the analyzer converts the question into an embedding. It then runs a similarity search in PostgreSQL, pulling the **top 15 log chunks** that are most semantically related to the query. These chunks are labeled with their exact line numbers, joined together, capped at **6,000 tokens** to prevent context overload, and sent to GPT-4o. GPT-4o reviews this context and streams a highly detailed JSON threat report back to the UI!
