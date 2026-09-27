## Epic 1 — Truy cập và quản lý run

| ID | User story | Tiêu chí chấp nhận |
| --- | --- | --- |
| US-01 | Là **người dùng hệ thống**, tôi muốn đăng nhập bằng danh tính hợp lệ để sử dụng các chức năng được bảo vệ. | Tài khoản hợp lệ đăng nhập được; thông tin không hợp lệ bị từ chối. Yêu cầu tới chức năng được bảo vệ phải có phiên đăng nhập hợp lệ. |
| US-02 | Là **Operator**, tôi muốn chỉ sử dụng chức năng thuộc quyền của mình để không thực hiện thao tác ngoài thẩm quyền. | Operator không thể phê duyệt hành động của mình qua UI hoặc gọi trực tiếp API; server từ chối và ghi audit log. |
| US-03 | Là **Operator**, tôi muốn chọn mục tiêu từ danh sách lab được cấp phép để tránh kiểm thử nhầm hệ thống. | Chỉ mục tiêu đã đăng ký và được cấp phép mới dùng để tạo run; mục tiêu không hợp lệ bị từ chối trước khi run bắt đầu. |
| US-04 | Là **Operator**, tôi muốn xác định phạm vi kiểm thử để agent chỉ hoạt động trong khu vực được cấp phép. | Mỗi tool call được kiểm tra phạm vi trước khi gửi. Redirect hoặc mục tiêu phát sinh ngoài phạm vi bị chặn trước request tiếp theo; hành động bị chặn được ghi log. |
| US-05 | Là **Operator**, tôi muốn tạo run với cấu hình và giới hạn rõ ràng để kiểm soát quá trình kiểm thử. | Run lưu ID, mục tiêu, phạm vi, thời điểm, giới hạn và trạng thái ban đầu. Thiếu dữ liệu bắt buộc hoặc mục tiêu không hợp lệ thì không tạo run. |
| US-06 | Là **Operator**, tôi muốn dừng run đang hoạt động để ngăn hành động mới. | Khi run bị dừng hoặc chạm giới hạn, hệ thống không khởi tạo hành động mới; lưu lý do, thời điểm và cập nhật trạng thái cuối. |
| US-07 | Là **Operator**, tôi muốn xem tiến trình từng agent để biết run đang ở giai đoạn nào. | UI hiển thị trạng thái từ hệ thống; tải lại trang không làm sai trạng thái. Mỗi bước thể hiện agent, trạng thái, thời gian và lỗi nếu có. |

## Epic 2 — Điều phối agent và phép thử

| ID | User story | Tiêu chí chấp nhận |
| --- | --- | --- |
| US-08 | Là **Operator**, tôi muốn Supervisor điều phối Recon trên lab đã chọn để thu thập thông tin ban đầu. | Recon chỉ dùng công cụ được cấp quyền; kết quả gắn với run và mục tiêu. Timeout hoặc kết quả rỗng có trạng thái rõ ràng và không tự sinh finding. |
| US-09 | Là **Operator**, tôi muốn Fuzzing chạy các phép thử được phép trong giới hạn an toàn để tìm dấu hiệu bất thường. | Chỉ chạy nhóm phép thử đã chốt cho MVP; tuân thủ giới hạn số request và thời gian. Kết quả lưu đầu vào, phản hồi, nguồn và evidence liên quan. |

## Epic 3 — Phê duyệt và kiểm soát thực thi

| ID | User story | Tiêu chí chấp nhận |
| --- | --- | --- |
| US-10 | Là **Approver**, tôi muốn nhận đề xuất kiểm chứng có cấu trúc từ Exploit Agent để có đủ thông tin quyết định. | Yêu cầu nêu mục tiêu, hành động, tham số, lý do, ảnh hưởng dự kiến, rủi ro và hạn hiệu lực. Trước phê duyệt hợp lệ, lớp thực thi không gọi công cụ rủi ro. |
| US-11 | Là **Approver**, tôi muốn duyệt hoặc từ chối hành động rủi ro để kiểm soát việc thực thi. | Chỉ Approver hợp lệ được quyết định. Hệ thống lưu người quyết định, thời gian, nội dung yêu cầu và kết quả; lưu ghi chú nếu được cung cấp. Từ chối hoặc hết hạn không dẫn tới thực thi. |
| US-12 | Là **Approver**, tôi muốn phê duyệt chỉ áp dụng cho đúng hành động đã xem xét để tránh tái sử dụng sai mục đích. | Phê duyệt gắn với một request cụ thể. Đổi mục tiêu, hành động hoặc tham số buộc tạo yêu cầu phê duyệt mới; phê duyệt cũ không cho phép thực thi nội dung đã đổi. |
| US-13 | Là **Approver**, tôi muốn sự kiện phê duyệt lặp không làm hành động rủi ro chạy nhiều lần. | Callback lặp hoặc gửi lại cùng quyết định không tạo lần thực thi thứ hai; trạng thái quyết định và số lần thực thi đối chiếu được bằng log. |
| US-14 | Là **người chịu trách nhiệm lab**, tôi muốn giới hạn quyền công cụ theo agent để agent không thể tự mở rộng quyền hoặc phạm vi. | Lớp thực thi kiểm tra quyền và phạm vi trước mỗi tool call. Nội dung từ mục tiêu không thể thay đổi quyền, mục tiêu hoặc bỏ qua phê duyệt; hành động bị chặn có audit log. |
| US-23 | Là **Approver**, tôi muốn nhận và xử lý yêu cầu phê duyệt qua một kênh Slack hoặc Teams đã chọn để phản hồi kịp thời. | Yêu cầu trên kênh dẫn tới đúng approval request. Server kiểm tra lại danh tính, quyền, hiệu lực và nội dung quyết định trước khi thực thi. Khi gửi thông báo thất bại hoặc phản hồi không xác thực được, request vẫn chờ hoặc chuyển sang trạng thái lỗi rõ ràng; không được tự duyệt. |

## Epic 4 — Finding và bằng chứng

| ID | User story | Tiêu chí chấp nhận |
| --- | --- | --- |
| US-15 | Là **người đọc kết quả**, tôi muốn mỗi finding liên kết với evidence để kiểm tra căn cứ kết luận. | Finding có ID, run ID, mục tiêu, nguồn, thời điểm và evidence ID. Evidence truy được về bước hoặc tool call đã tạo ra nó. |
| US-16 | Là **người đọc kết quả**, tôi muốn phân biệt finding chưa đủ bằng chứng với finding đã xác minh để không hiểu sai kết quả. | Finding thiếu evidence hoặc có kết quả mâu thuẫn được đánh dấu `Chưa xác minh`; báo cáo không trình bày nó như lỗ hổng đã xác nhận. |

## Epic 5 — Lỗi, khôi phục và báo cáo

| ID | User story | Tiêu chí chấp nhận |
| --- | --- | --- |
| US-17 | Là **Operator**, tôi muốn thấy timeout và lỗi agent/công cụ để biết phần đã hoàn thành và phần thất bại. | Run hiển thị lỗi hoặc kết quả một phần, giữ evidence đã có. Retry nằm trong giới hạn được phép và không tự lặp hành động rủi ro. |
| US-18 | Là **Operator**, tôi muốn khôi phục trạng thái run an toàn sau khi hệ thống khởi động lại để không bỏ qua phê duyệt hoặc lặp hành động. | Run đang chờ duyệt vẫn chờ sau restart. Hành động đã thực thi không tự chạy lại; yêu cầu chưa được duyệt không tự đổi thành đã duyệt. |
| US-19 | Là **người nhận báo cáo**, tôi muốn xem báo cáo của run để hiểu kết quả và giới hạn kiểm thử. | Báo cáo nêu phạm vi, finding, trạng thái xác minh, ảnh hưởng, evidence và bước chưa hoàn thành. Run không có finding không được kết luận hệ thống hoàn toàn an toàn. |
| US-20 | Là **người nhận báo cáo**, tôi muốn tải báo cáo để sử dụng kết quả ngoài hệ thống. | Người có quyền tải được báo cáo của đúng run ở định dạng MVP đã chốt; nội dung tải khớp nội dung hiển thị và không lộ khóa hoặc dữ liệu nhạy cảm không cần thiết. |
| US-21 | Là **người dùng được cấp quyền**, tôi muốn báo cáo và evidence chỉ được người phù hợp truy cập để bảo vệ dữ liệu kiểm thử. | Người không có quyền bị từ chối cả ở UI lẫn API; truy cập trái quyền được ghi log. |
| US-22 | Là **người kiểm tra**, tôi muốn xem lịch sử hành động của người dùng, agent và hệ thống để tái dựng run. | Audit ghi actor, action, resource, result, timestamp, run ID và trace ID. Phê duyệt, từ chối và tool execution truy vết được theo run. |
