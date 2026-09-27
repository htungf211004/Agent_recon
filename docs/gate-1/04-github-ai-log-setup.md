# GitHub Repo & AI Log Setup — PentestSyndicate

## 1. Mục đích

Tài liệu này giúp bốn thành viên dùng đúng repo chính thức, ghi lại quá trình sử dụng AI bằng key cá nhân và tự kiểm tra trước khi nộp Gate 1.

## 2. Kết quả đối chiếu repo ngày 20/09/2026

| Hạng mục | Bằng chứng quan sát được | Kết luận |
|---|---|---|
| Remote | `https://github.com/AI20K-Build-Phase-Cohort-4/P-077.git` | Đúng repo của đội trong tổ chức chương trình |
| Nhánh làm việc | `an1-tech`, tracking `origin/an1-tech` | Có nhánh cá nhân; cần PR vào main để CI chạy |
| CI | `.github/workflows/ci.yml` | Có Ruff và pytest trên Python 3.11 |
| Test hiện tại | 5/5 test pass | Chỉ xác nhận starter API/graph, chưa xác nhận sản phẩm PentestSyndicate |
| Lint hiện tại | Ruff pass | Mã template hiện tại không có lỗi lint |
| AI log config | Có cấu hình cho Claude, Cursor, Codex, Gemini, Copilot và Antigravity | Hạ tầng ghi log đã có trong repo |
| Pre-push hook trên máy đang audit | `.git/hooks/pre-push` tồn tại | Máy này đã cài hook; không suy ra máy ba thành viên còn lại đã cài |
| Local log metadata | Có file pending và archive cục bộ | Chỉ chứng minh có log local; chưa chứng minh hook là nguồn tạo hoặc server đã nhận |
| Bảo vệ secret | `.env` và `.ai-log/*.jsonl` bị Git ignore | Cấu hình đúng; từng thành viên vẫn phải tránh dán secret vào tài liệu/commit |

### Khoảng trống cần xử lý

- Lịch sử Git hiện chưa chứng minh đủ bốn thành viên đã có commit hoặc PR có ý nghĩa.
- Không thể xác nhận log đã vào tài khoản Phoenix của từng người nếu không xem dashboard tương ứng.
- CI không tự chạy khi chỉ push vào nhánh `an1-tech`; CI sẽ chạy khi mở pull request vào `main`, hoặc push vào `main`/`develop` theo workflow hiện tại.
- Root source hiện là starter template. Việc pass 5 test không có nghĩa workflow pentest, HITL hay giao diện đã hoàn thành.

## 3. Quy tắc cho cả nhóm

1. Mỗi thành viên dùng tài khoản GitHub của chính mình.
2. Mỗi thành viên tạo `AI_LOG_API_KEY` riêng trên Phoenix; không dùng chung key.
3. Key chỉ nằm trong file `.env` cục bộ.
4. Không commit `.env`, file JSONL của AI log, token, cookie hoặc mật khẩu.
5. Mỗi thay đổi đi qua branch cá nhân và pull request có review chéo.
6. Prompt quan trọng liên quan quyết định sản phẩm hoặc code phải được log.
7. Dùng AI để hỗ trợ nhưng người commit chịu trách nhiệm đọc, kiểm thử và giải thích đầu ra.

## 4. Thiết lập lần đầu cho từng thành viên

### Bước 1 — Clone repo chính thức

```powershell
git clone https://github.com/AI20K-Build-Phase-Cohort-4/P-077.git
Set-Location P-077
git remote -v
```

Kết quả mong đợi: origin trỏ tới repo `AI20K-Build-Phase-Cohort-4/P-077`.

### Bước 2 — Tạo môi trường Python

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Bước 3 — Kiểm tra danh tính Git

```powershell
git config user.name
git config user.email
```

Hai giá trị phải là danh tính của chính thành viên đang làm việc. Script logging dùng `git config user.email` làm trường định danh `student`; email sai sẽ làm log gắn nhầm người.

Nếu chưa có, cấu hình trong repo hiện tại:

```powershell
git config user.name "Ho va ten"
git config user.email "email-cua-ban@example.com"
```

### Bước 4 — Tạo file môi trường cục bộ

```powershell
Copy-Item .env.example .env
```

Mở `.env` và điền:

- `AI_LOG_API_KEY`: key riêng của thành viên trên Phoenix.
- `OPENAI_API_KEY` và các biến model cần thiết khi bắt đầu phát triển.
- Giữ `AI_LOG_SERVER` theo cấu hình do chương trình cung cấp.

Không gửi nội dung file `.env` lên chat hoặc chụp màn hình có hiển thị key.

### Bước 5 — Cài AI logging hook

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_hooks.ps1
Test-Path .git\hooks\pre-push
```

Linux, macOS hoặc Git Bash:

```bash
bash scripts/setup_hooks.sh
test -f .git/hooks/pre-push
```

Kết quả mong đợi là `True` trên PowerShell hoặc exit code 0 trên shell.

Trên Windows, script hiện ghi hook bằng UTF-8 không BOM và chuẩn hóa LF để shebang nằm ở byte đầu tiên. Kiểm tra thêm:

```powershell
$bytes = [System.IO.File]::ReadAllBytes(".git\hooks\pre-push")
$prefix = ($bytes[0..2] | ForEach-Object { $_.ToString("X2") }) -join " "
Get-Content .git\hooks\pre-push -TotalCount 1
$prefix
```

Dòng đầu phải là `#!/usr/bin/env bash` và prefix không được là `EF BB BF`. Máy có Git Bash có thể chạy thêm `bash -n .git/hooks/pre-push` để kiểm tra cú pháp mà không gửi log.

### Bước 6 — Kiểm tra file nhạy cảm bị ignore

```powershell
git check-ignore -v .env
git check-ignore -v .ai-log\session.jsonl
```

Hai lệnh phải trả về quy tắc trong `.gitignore`. Nếu không có output, dừng trước khi commit và sửa ignore.

### Bước 7 — Tạo một AI log thử

Nếu dùng một trong các công cụ đã tích hợp, gửi một prompt có ý nghĩa cho dự án và kiểm tra local log được tạo. Nếu dùng ChatGPT web:

```powershell
python scripts\log_manual.py --tool chatgpt --prompt "Review phạm vi MVP PentestSyndicate và chỉ ra một rủi ro."
```

Không dùng dữ liệu nhạy cảm làm prompt thử.

### Bước 8 — Làm việc trên branch cá nhân

Quy ước đề xuất:

| Thành viên | Branch gợi ý | Phạm vi Gate 1 |
|---|---|---|
| PM / Supporting BA | `pm/gate1-scope` | Brief, scope, quyết định và checklist |
| BA chính | `ba/gate1-prd` | PRD, user story, acceptance criteria |
| Developer 1 | `dev1/gate1-architecture` | Kiến trúc, feasibility, review kỹ thuật |
| Developer 2 | `dev2/gate1-wireframe` | Wireframe, UI flow, review khả năng triển khai |

Tên branch chỉ là đề xuất; nhóm có thể dùng quy ước khác nhưng không cùng sửa trực tiếp một nhánh.

### Bước 9 — Test trước khi push

```powershell
.\.venv\Scripts\python.exe -B -m ruff check --no-cache src tests
.\.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider tests -q
git status --short
```

### Bước 10 — Push và xác nhận log

```powershell
git push -u origin <ten-branch>
```

Ví dụ cho branch PM trong bảng trên:

```powershell
git push -u origin pm/gate1-scope
```

Pre-push hook sẽ thử gửi log. Sau đó mỗi thành viên phải tự mở dashboard Phoenix và xác nhận:

- Đúng tài khoản/thành viên.
- Có bản ghi mới gắn với repo P-077.
- Thời gian và công cụ khớp với lần thử.
- Không có secret trong nội dung prompt.

Repo không thể tự chứng minh server đã nhận log; dashboard là nguồn xác nhận cuối cùng.

## 5. Quy trình pull request

1. Đồng bộ nhánh đích mới nhất.
2. Tạo branch theo phạm vi cá nhân.
3. Commit nhỏ, thông điệp nêu rõ thay đổi.
4. Push để hook gửi AI log.
5. Mở PR vào `main`.
6. Gắn một người khác review.
7. Chờ CI Ruff và pytest xanh.
8. Sửa feedback, rồi merge theo quy ước nhóm.

Ví dụ commit message:

- `docs(gate1): define MVP scope and success metrics`
- `docs(gate1): add approval rules and exception flows`
- `docs(gate1): add operator and approver wireframes`

## 6. Bảng xác nhận bốn thành viên

Chỉ đánh dấu sau khi chính thành viên đó đã kiểm tra.

| Thành viên | GitHub |
|---|:---:|
| PM / Supporting BA — [Đỗ Quốc An] | [https://github.com/AI20K-Build-Phase-Cohort-4/P-077/tree/an1-tech ] | 
| BA chính — [Nguyễn Hoàng Sơn] | [https://github.com/AI20K-Build-Phase-Cohort-4/P-077/tree/son101 ] | 
| Developer 1 — [Nguyễn Hồng Phi] | [ https://github.com/AI20K-Build-Phase-Cohort-4/P-077/tree/hongphi] | 
| Developer 2 — [Trịnh Hoàng Tùng] | [ https://github.com/AI20K-Build-Phase-Cohort-4/P-077/tree/htungf] | 

link chứng minh log trên dashboard : "https://drive.google.com/drive/folders/1zmrfY9JhlZ7fsppleTIDuNFmU_05Ek3N?usp=drive_link"
## 7. Phân biệt đã có và chưa có

### Đã có trong repo

- FastAPI/LangGraph starter.
- Dockerfile và docker-compose.
- CI với Ruff và pytest.
- Script setup hook, manual logging và submit logging.
- Cấu hình hook cho sáu công cụ AI.


