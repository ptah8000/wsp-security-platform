### Task 13: End-to-end Compose hardening + README

**Files:**
- Modify: `deploy/*`, `README.md`, `deploy/env.example`
- Create: `docs/architecture.md` short notes

**README sections:**
1. What is WSP  
2. Architecture diagram (text)  
3. Requirements (Linux, Docker)  
4. Quick start `docker compose up -d --build`  
5. First-run wizard  
6. Client proxy + CA install  
7. Default ports  
8. CASB coverage matrix  
9. RBI limitations  
10. Security notes (Docker socket, data key, fail_open)  
11. Config env reference  
12. Future roadmap hooks  

- [ ] **Step 1: Generate strong default `WSP_DATA_KEY` instructions** (must set in `.env`)

- [ ] **Step 2: Smoke script** `deploy/smoke.sh` — healthz, setup status

- [ ] **Step 3: Full manual test checklist in README**

- [ ] **Step 4: Commit** `docs: README and compose production-ready defaults`

---
