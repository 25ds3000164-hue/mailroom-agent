# Mailroom Agent — deployment guide

This is a **second, separate Render service**. It reuses what you already have:

- the same **Gemini API key**;
- the same **Neon database** (it uses its own tables, `mr_evaluations` and `mr_decisions`, so it won't touch the invoice agent's data).

---

## Step 1 — New GitHub repo

1. Go to https://github.com/new, name it `mailroom-agent`, and click **Create repository**.
2. Click **uploading an existing file**.
3. Unzip `mailroom-agent.zip` on your computer **first**.
4. Drag in the files `app.py`, `requirements.txt`, `README.md` and `test_mailroom.py` so they sit at the **top level**, not inside a folder.
5. Click **Commit changes**.

## Step 2 — New Render web service

1. In Render, click **New → Web Service** and pick `mailroom-agent`.
2. Fill in:
   - **Region:** Singapore
   - **Language:** Python 3
   - **Branch:** main
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app:app --host 0.0.0.0 --port $PORT`
   - **Instance Type:** Free
3. Add these **Environment Variables**:

   | Name | Value |
   |---|---|
   | `GEMINI_API_KEY` | same `AIza...` key as before |
   | `DATABASE_URL` | same Neon `postgresql://...` string as before |
   | `PYTHON_VERSION` | `3.12.7` |

4. Click **Deploy Web Service** and wait for **Live**.

## Step 3 — Your endpoint URL

Your endpoint URL is simply the Render address shown at the top, e.g.

```
https://mailroom-agent-xyz1.onrender.com/
```

Paste that into **"Deployed mailroom agent endpoint URL"**. Both `propose` and `commit` go to this one URL.

Quick check: opening it in a browser should show `ok`.

## Step 4 — Test before spending a Check

On your computer:

```
pip install requests cryptography
python test_mailroom.py https://mailroom-agent-xyz1.onrender.com/
```

You want `0 failed`. In the printed proposals, the first dossier should be a `create_draft` for
`priya@example.com` / `ORD-5521` / `shipped`, and the second should be a `quarantine_item`.

If both show `no_action` with `INFORMATIONAL`, Gemini isn't being reached. Open the Render **Logs** tab and look for `[gemini]` lines.

## Step 5 — Check

- **Wake the app first:** open the URL in your browser and wait for `ok`, then click Check.
  Free Render apps sleep after 15 minutes idle.
- The first Check is the slowest, because it sends all 64 dossiers to Gemini in 4 parallel batches.
  Later Checks reuse saved core decisions and only call Gemini for the 6 new audit dossiers.

## If the feedback shows problems

| Feedback is about | Try |
|---|---|
| Timeouts on the first Check | Set `GEMINI_THINKING_BUDGET=0`, or `MODEL_CHUNK_SIZE=10` (more, smaller parallel calls). |
| Action accuracy | Set `GEMINI_THINKING_BUDGET=4096`, only if timing is fine. |
| Gemini model errors in Logs | Set `GEMINI_MODEL` to a current model name from https://ai.google.dev/gemini-api/docs/models |

After changing anything that affects decisions, clear the saved ones in the Neon **SQL Editor**:

```sql
DELETE FROM mr_decisions;
```

Don't delete `mr_evaluations` while a Check is running.

## How it stays safe

- Gemini only *suggests* an action. Plain code builds the exact target and payload. It fixes the template names, queue IDs and codes, and drops any value that looks like a secret or canary.
- It refuses to propose a send unless the recipient, reference and status appear in the dossier.
- Commit verifies every Ed25519 signature with that evaluation's own key **before** recording anything. One bad, missing, duplicated or swapped signature rejects the whole commit.
- Replays return the stored response byte for byte, with no model call.
- Reusing an `evaluationId` with different content returns 409.
- Malformed input returns 400/422 before any AI work.
