### Task 11: React admin SPA

**Files:**
- Create: `web/` full Vite React TS app with Tailwind + shadcn components as needed
- Routes: `/setup`, `/login`, `/`, `/health`, `/settings/*`, `/policy/*`, `/objects`, `/logs`, `/audit`, `/client-setup`
- API client: `web/src/api.ts` fetch credentials include

**UX requirements (design §10):**
- Progressive disclosure on policy editor (tabs: General, Web, RBI, CASB, Malware)
- Policy list drag reorder or up/down
- Simulation form
- Log filters + session expand
- Health status badges
- Empty states with guidance

- [ ] **Step 1: Scaffold Vite React-TS + Tailwind**

- [ ] **Step 2: Auth gate + setup redirect if `GET /api/v1/setup/status` incomplete**

- [ ] **Step 3: Implement all main pages** (functional, clean, not dark-mode)

- [ ] **Step 4: Build into `web/dist`; Go embed `//go:embed all:web/dist`**

- [ ] **Step 5: Commit** `feat: embed React admin UI for all main sections`

---
