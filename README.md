# PentestSyndicate

PentestSyndicate là đề tài VSOC-04 của nhóm P-077: một web app điều phối nhiều AI agent để hỗ trợ kiểm thử bảo mật trong môi trường staging hoặc lab đã được cấp phép. Operator tạo phiên kiểm tra; Supervisor điều phối Recon, Fuzzing và Exploit; Approver là con người quyết định trước hành động rủi ro; hệ thống tổng hợp bằng chứng và tạo báo cáo.

## Gate 1 — Chốt bài toán và thiết kế

Toàn bộ hồ sơ Gate 1 nằm tại:

**[Mở bộ hồ sơ Gate 1](docs/gate-1/README.md)**

| Deliverable | Link |
|---|---|
| One-page Brief | [docs/gate-1/01-one-page-brief.md](docs/gate-1/01-one-page-brief.md) |
| PRD | [docs/gate-1/02-prd.md](docs/gate-1/02-prd.md) |
| Wireframe & UI Flow | [docs/gate-1/03-wireframe-ui-flow.md](docs/gate-1/03-wireframe-ui-flow.md) |
| GitHub Repo & AI Log Setup | [docs/gate-1/04-github-ai-log-setup.md](docs/gate-1/04-github-ai-log-setup.md) |
| Checklist nộp Gate | [docs/gate-1/05-gate-submission-checklist.md](docs/gate-1/05-gate-submission-checklist.md) |

## Trạng thái hiện tại

Recon Day 1 đã có luồng thực thi từ task đến kết quả và bằng chứng. FastAPI/LangGraph starter vẫn nằm trong repo; workflow nhiều agent, frontend, phân quyền, HITL và report thuộc thiết kế mục tiêu.

**Recon Day-1 backbone đã triển khai:**

- Hợp đồng dữ liệu có kiểu cho `ReconTask`, `ReconPlan` và `CapabilityRequest`.
- `PolicyService` từ chối mặc định các IP, cổng và capability ngoài scope.
- `ToolExecutionGateway` là điểm điều phối thực thi; `request_id` được claim nguyên tử trước policy và adapter để tránh chạy tool hai lần.
- Adapter HTTP probe, Nmap và WhatWeb với tham số cố định, giới hạn thực thi; parser Nmap/WhatWeb xác định.
- SQLite lưu task, execution claim, policy decision, tool result, metadata evidence và Recon result.
- `EvidenceStore` giới hạn kích thước và kiểm tra toàn vẹn SHA-256 khi đọc.
- `ReconPlanner` tạo plan xác định từ scope; `ReconAgent` chạy trực tiếp từ `task_id`.
- Test đầu cuối HTTP trên `127.0.0.1` đi qua Agent, Policy, Gateway, adapter, Evidence và Repository.

Kiểm tra cục bộ gần nhất: **25 test pass**, Ruff pass. Xem [kiến trúc Day 1](ARCHITECTURE.md).

## Vai trò

| Vai trò | Người hay AI | Trách nhiệm |
|---|---|---|
| Operator | Người | Chọn staging/scope, tạo và theo dõi run |
| Approver | Người | Duyệt hoặc từ chối action rủi ro |
| Supervisor | AI agent | Lập kế hoạch, điều phối, đối chiếu |
| Recon | AI agent | Khảo sát trong allowlist |
| Fuzzing | AI agent | Kiểm tra hữu hạn các điểm đã tìm thấy |
| Exploit | AI agent | Đề xuất bước kiểm chứng; không tự vượt approval |

## Workflow mục tiêu

```mermaid
flowchart LR
    A[Operator chọn staging và scope] --> B[Supervisor]
    B --> C[Recon / Fuzzing / Exploit đề xuất tool call]
    C --> G{Guard: quyền + scope + tool + budget + risk}
    G -->|Ngoài scope/cấm| J[Chặn và audit]
    G -->|An toàn| I[Runner thực thi]
    G -->|Rủi ro| H[Approver]
    H -->|Duyệt hợp lệ| I
    H -->|Từ chối/hết hạn| J
    I --> K[Evidence trả về Supervisor]
    J --> K
    K -->|Còn bước| B
    K -->|Đủ kết quả| L[Report]
```

## Nguyên tắc an toàn của MVP

- Chỉ chạy trên target lab/staging được cho phép.
- Deny by default với target ngoài allowlist.
- Mọi tool call qua permission/scope/tool/budget/risk guard; hành động rủi ro dừng trước khi chạy.
- Approval gắn với đúng run, target, action, parameter hash và thời hạn.
- Runner kiểm tra lại scope và approval ngay trước khi thực thi.
- Nội dung từ target được coi là dữ liệu không tin cậy.
- Finding phải có evidence và verification status.
- Không đưa dữ liệu cá nhân, secret hoặc dữ liệu nhạy cảm thật vào hệ thống.

## Chạy backend starter hiện tại

Yêu cầu: Python 3.11.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn src.main:app --reload --port 8000
```

Swagger UI: <http://localhost:8000/docs>

## Kiểm tra

```powershell
.\.venv\Scripts\python.exe -B -m ruff check --no-cache src tests
.\.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider tests -q
```

## AI usage logging

Mỗi thành viên phải dùng `AI_LOG_API_KEY` riêng, lưu trong file `.env` cục bộ và cài hook sau khi clone:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_hooks.ps1
Test-Path .git\hooks\pre-push
```

Không commit `.env` hoặc `.ai-log/*.jsonl`. Hướng dẫn và checklist cho bốn người nằm tại [GitHub Repo & AI Log Setup](docs/gate-1/04-github-ai-log-setup.md).

## Cấu trúc chính

```text
docs/gate-1/       Hồ sơ Gate 1
src/recon/         Recon Agent Day 1, policy, gateway, adapter và storage
src/               FastAPI và LangGraph starter
tests/             Unit test và HTTP localhost E2E
scripts/           AI log hooks và utilities
eval/              Nơi lưu bằng chứng evaluation
presentation/      Slide và video demo
docs/guide/        Technical Guidebook của chương trình
```

Không chỉnh `docs/guide` cho deliverable của đội; đây là nguồn Technical Book dùng chung.

## Tài liệu chương trình

Technical Guidebook: <https://phoenix.note.transformerlabs.ai/technical-book>

## License

[MIT](LICENSE)
