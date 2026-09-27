# One-page Brief — PentestSyndicate

| Mã đề | Giai đoạn | Phiên bản | Trạng thái |
|---|---|---|---|
| VSOC-04 — An ninh mạng | Gate 1 | 1.0 — 20/09/2026 | Đề xuất để mentor xác nhận |

## Vấn đề và giá trị

Một đợt pentest cần phối hợp khảo sát, dò điểm yếu, kiểm chứng và tổng hợp bằng chứng. Khi các bước nằm ở nhiều công cụ, trạng thái và quyết định khó truy vết; hành động vượt phạm vi có thể gây rủi ro.

PentestSyndicate điều phối nhiều AI agent trong staging/lab đã được cấp phép. Hệ thống gom workflow, evidence và report vào một luồng; action rủi ro dừng trước khi thực thi để con người quyết định.

## Người dùng và workflow

| Vai trò | Loại | Nhu cầu/trách nhiệm |
|---|---|---|
| Operator | Con người | Chọn staging/scope, tạo run, theo dõi và xem report |
| Approver | Con người | Xem action, rủi ro, evidence rồi duyệt hoặc từ chối |
| Supervisor, Recon, Fuzzing, Exploit | AI agent | Điều phối, khảo sát, kiểm tra và đề xuất kiểm chứng |

**Luồng:** Operator chọn staging/scope → Supervisor điều phối Recon, Fuzzing, đối chiếu và Exploit → trước mọi tool call, runner kiểm tra quyền/scope/tool/budget/risk → action an toàn được chạy; action rủi ro chờ Approver → tổng hợp evidence và report.

## MVP

### Must have

- Web app online; hai vai trò Operator và Approver.
- Một lab/staging; target ngoài allowlist bị chặn.
- Bốn AI agent; workflow có state, trace, tool-use và xử lý lỗi.
- Scope guard tại mọi tool call; HITL tại runner trước action rủi ro.
- Finding gắn evidence và verification status; có report và eval cơ bản.

### Ngoài MVP

- Production, target chưa cấp phép, payload phá hủy hoặc autonomous exploit.
- Multi-tenant, marketplace và RAG/GraphRAG.

## Chỉ số thành công

- Action rủi ro chạy thiếu approval: mục tiêu bắt buộc bằng 0.
- Tool call ngoài allowlist: mục tiêu bắt buộc bằng 0.
- Tỷ lệ run có report; tỷ lệ lỗi; thời gian/chi phí mỗi run.
- Precision/recall trên lab có nhãn; tỷ lệ finding có evidence đúng.

## Căn cứ và điểm cần chốt

**Dữ kiện:** Đề bài yêu cầu web/app online, hai vai trò, workflow có state/tool-use, HITL, failure cases và eval. Repo mới là FastAPI/LangGraph starter; chưa có UI, bốn agent, auth, HITL hay report.

**Giả định:** Có một lab hợp pháp; Operator và Approver dùng hai tài khoản; action có tác động cao phải duyệt.

**Đề xuất cần mentor xác nhận:** Hybrid SaaS gồm control plane online và một runner trong mạng lab, kết nối outbound.
