import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import { Workbook, SpreadsheetFile } from '@oai/artifact-tool';

const outputDir='D:/P-077/outputs/01a0a659-f4e2-7900-929d-8c26a48c60f8';
const workDir='D:/P-077/tmp/team-plan';
// Dates are a proposed schedule, not a confirmed submission deadline.
// id, week, first/last business-day offset, estimated hours, task, done criteria, dependencies, reviewer
const tasks={
PM:[
 ['PM01',1,0,0,2,'Khởi động nhóm. Chốt tên, giờ có thể làm, kênh trao đổi và lịch họp. Xác nhận hạn nộp thực tế.','Có người nhận từng vai trò, cam kết giờ/tuần và danh sách điều chưa rõ. Nếu hạn khác lịch mẫu, cập nhật kế hoạch trước khi cam kết.','Không','Cả nhóm'],
 ['PM02',1,1,2,4,'Chốt mục tiêu, MVP và tiêu chí an toàn. Cùng BA phân biệt yêu cầu bắt buộc với gợi ý công nghệ. Chọn một ứng dụng lab và nhóm kiểm tra hữu hạn.','Danh sách Must/Should/Could/Won’t được cả nhóm xác nhận. Có định nghĩa chỉ số đo, ngân sách thử nghiệm dự kiến và chủ sở hữu môi trường.','PM01, BA01','BA'],
 ['PM03',1,3,4,4,'Duyệt backlog và phụ thuộc. Kiểm tra demo khung. Lập sổ rủi ro, quyết định và phương án nếu dev chưa làm chủ mã AI sinh.','G0 có bằng chứng. Mỗi task có một người làm và một người kiểm tra. Cắt công nghệ không phục vụ MVP; đặt người hỗ trợ kỹ thuật nếu cần.','PM02, BA02','BA; 2 Dev'],
 ['PM04',2,5,6,3,'Kiểm tra kế hoạch tuần và bản giao diện. Giải quyết câu hỏi nghiệp vụ trong một ngày làm việc. Chốt tài khoản dùng cho demo.','Không còn quyết định về phạm vi, vai trò hoặc màn hình cản hai dev. Yêu cầu thay đổi được ghi rõ tác động.','PM03','BA'],
 ['PM05',2,7,8,3,'Chọn một kênh Slack hoặc Teams cho phê duyệt và xác nhận quyền tích hợp. Hỗ trợ BA rà soát tình huống âm tính và lỗi.','Có người sở hữu kênh, cách cấu hình và tài khoản thử. Nếu không có quyền tích hợp, ghi rủi ro và xác nhận phạm vi với BTC.','PM04','BA; Dev2'],
 ['PM06',2,9,9,3,'Chủ trì G1. Thử tạo đợt trên lab, xem Recon và bằng chứng thật. So sánh việc hoàn thành với tiêu chí đã chốt.','Có biên bản G1 và 3 việc ưu tiên tuần 3. Dữ liệu mô phỏng được gắn nhãn, không tính thành kết quả AI thực tế.','PM05','BA; 2 Dev'],
 ['PM07',3,10,11,3,'Duyệt nội dung yêu cầu phê duyệt. Chốt ai duyệt, thời hạn, hành động và mục tiêu được phép. Duyệt giới hạn lượt chạy/chi phí.','Không có phê duyệt chung cho mọi hành động. Quy tắc đổi tham số, hết hạn, từ chối và dừng đợt được BA ghi rõ.','PM06, BA03','BA; Dev1'],
 ['PM08',3,12,13,3,'Theo dõi tích hợp HITL. Gỡ vướng giữa hai dev và BA. Ưu tiên lỗi làm vượt quyền hoặc mất trạng thái.','Mọi lỗi chặn có người xử lý, hạn khắc phục và tác động. Không thêm tính năng nâng cao khi HITL chưa chạy đúng.','PM07','BA'],
 ['PM09',3,14,14,3,'Chủ trì G2. Đóng vai Operator để BA thử Approver. Xem cả duyệt, từ chối, hết hạn và mất kết nối.','Chỉ chấp nhận G2 khi hành động bị chặn đúng tại lớp thực thi. Ghi kết quả thật và việc chưa đạt.','PM08','BA; 2 Dev'],
 ['PM10',4,15,16,3,'Rà báo cáo dưới góc nhìn người nhận. Kiểm tra mục tiêu, kết quả, bằng chứng, ảnh hưởng và giới hạn có dễ hiểu không.','Báo cáo phân biệt đã xác minh, nghi vấn và không kiểm chứng được. Không dùng lời khẳng định vượt bằng chứng.','PM09, BA09','BA'],
 ['PM11',4,17,18,3,'Khóa phạm vi tính năng. Bỏ Could và hoãn Should chưa cần thiết. Kiểm tra chi phí, thời gian và năng lực còn lại.','Có danh sách tính năng khóa, việc hoãn và lý do. Tuần 5 chỉ hoàn thiện Must, sửa lỗi và đánh giá.','PM10','Cả nhóm'],
 ['PM12',4,19,19,3,'Chủ trì G3 sau baseline. Cùng BA chốt ngưỡng chất lượng AI trước khi mở tập đánh giá giữ riêng.','Có kết quả đo trên tập phát triển và tiêu chí nghiệm thu AI đã ghi ngày/phiên bản. Không đặt lại ngưỡng để chạy theo kết quả holdout.','PM11','BA; 2 Dev'],
 ['PM13',5,20,21,3,'Điều phối sửa lỗi. Ưu tiên lỗi an toàn, sai kết luận, mất dữ liệu, không chạy được luồng chính. Kiểm soát yêu cầu mới.','Mỗi lỗi có mức độ, người sửa và người kiểm lại. Lỗi chặn không bị đổi tên thành hạn chế để thông qua.','PM12','BA'],
 ['PM14',5,22,23,3,'Tham gia UAT: kiểm thử nghiệm thu dưới vai Operator. Kiểm tra báo cáo và luồng dùng thực tế.','Hoàn thành các bước theo kịch bản BA; ghi rõ đạt/chưa đạt, phiên bản và bằng chứng. BA giữ vai Approver khi kiểm thử tách quyền.','PM13, BA13','BA'],
 ['PM15',5,24,24,3,'Chủ trì G4 và quyết định bản ứng viên bàn giao. Chốt phần có thể trình diễn và các giới hạn phải công bố.','Không còn lỗi nghiêm trọng ảnh hưởng an toàn, luồng chính hoặc bằng chứng. Mọi Must có kết quả nghiệm thu; lưu quyết định phát hành.','PM14','BA; 2 Dev'],
 ['PM16',6,25,26,4,'Làm nội dung thuyết trình: vấn đề, người dùng, giá trị, giải pháp, kết quả đo và giới hạn. Hỗ trợ BA biên tập tài liệu.','Số liệu trong slide có nguồn từ eval hoặc đo thực tế. Lợi ích ước tính được ghi là ước tính, không trình bày như tiết kiệm đã chứng minh.','PM15','BA'],
 ['PM17',6,27,28,3,'Tổ chức hai lần diễn tập: luồng chính và tình huống lỗi. Chia lời trình bày. Kiểm tra video dự phòng và gói bàn giao.','Bốn người biết phần mình nói. Demo có điểm phê duyệt và bằng chứng; video dự phòng ghi rõ là bản quay, không giả là chạy trực tiếp.','PM16','Cả nhóm'],
 ['PM18',6,29,29,3,'Chủ trì G5. Rà đủ hồ sơ, URL và quyền truy cập của người nhận. Phân công người nộp và người xác nhận nộp.','Có checklist ký xác nhận, bản mã nguồn tương ứng, đường dẫn bàn giao và bằng chứng nộp khi nhóm thực hiện nộp.','PM17','BA; 2 Dev'],
],
BA:[
 ['BA01',1,0,1,4,'Đọc đề tài và quy định. Mô tả Operator, Approver, người nhận báo cáo; nhu cầu, AS-IS và giả định. Kiểm tra mục tiêu lab dự kiến.','Một bản yêu cầu ngắn phân biệt dữ kiện, giả định và câu hỏi. Không coi phỏng đoán là kết quả phỏng vấn. PM xác nhận vấn đề và người dùng.','PM01','PM'],
 ['BA02',1,2,2,4,'Vẽ TO-BE và trạng thái đợt kiểm thử. Viết quy tắc phạm vi, quyền, phê duyệt và bằng chứng. Định nghĩa dữ liệu nghiệp vụ chính.','Luồng có tạo, chạy, chờ duyệt, tiếp tục/bỏ qua, thất bại, hủy và kết thúc. Nêu rõ hết hạn, đổi hành động, mất kết nối và không có phát hiện.','BA01','PM; 2 Dev'],
 ['BA03',1,3,4,5,'Viết user story và Given–When–Then cho Must. Phác màn hình Operator/Approver và mẫu báo cáo. Nối yêu cầu với task dev.','Mỗi Must có tiêu chí kiểm thử được và luồng lỗi. Hai dev hiểu cùng một định nghĩa trạng thái, quyền và nội dung báo cáo.','BA02','PM; 2 Dev'],
 ['BA04',2,5,6,5,'Lập bộ eval mô phỏng 24 ca với đáp án kỳ vọng. Đề xuất 8 ca có phát hiện, 4 ca sạch, 6 ca quyền/HITL, 4 ca lỗi, 2 ca chỉ dẫn độc hại.','Lưu nguồn/đáp án và quy tắc chấm. Tách 16 ca phát triển, 8 ca giữ riêng; phân bố có ca dương tính, âm tính, an toàn và lỗi ở cả hai phần.','BA03','PM; Dev1'],
 ['BA05',2,7,8,4,'Kiểm thử đăng nhập, tách vai trò, nhập phạm vi và tạo đợt. Kiểm tra màn hình với tiêu chí và dữ liệu hợp lệ/không hợp lệ.','Lỗi có bước tái hiện, kỳ vọng, thực tế, mức độ và bằng chứng. Thử gọi API trực tiếp cho quyền, không chỉ nhìn nút trên UI.','BA04, D204','Dev2; PM'],
 ['BA06',2,9,9,3,'Kiểm thử luồng Recon tích hợp tại G1. Đối chiếu đầu vào, trạng thái và bằng chứng trên lab.','Ghi rõ thành phần nào dùng công cụ thật, phần nào còn mô phỏng. Xác nhận mục tiêu ngoài phạm vi bị chặn.','BA05, D105, D205','PM; Dev1'],
 ['BA07',3,10,11,4,'Chuẩn bị ma trận HITL: chờ, duyệt, từ chối, hết hạn, sai vai trò, đổi tham số, thao tác lặp và hệ thống khởi động lại.','Từng ca có điều kiện trước, thao tác, kỳ vọng và dữ liệu thử. Nội dung Approver nhìn thấy đủ để quyết định đúng hành động.','BA06','PM; 2 Dev'],
 ['BA08',3,12,13,4,'Chạy tập phát triển phù hợp với Recon/Fuzzing. Phân loại phát hiện đúng, sai, bỏ sót và thiếu bằng chứng.','Kết quả gắn với mã ca, phiên bản và evidence ID. Trường hợp chưa rõ chuyển dev xác minh, không tự gán là lỗ hổng thật.','BA07, D107','Dev1; PM'],
 ['BA09',3,14,14,5,'Kiểm thử HITL xuyên suốt với hai tài khoản và kênh đã chọn. Kiểm tra dừng khi thông báo hoặc phê duyệt lỗi.','Có bằng chứng cho các nhánh của G2. Hệ thống không thực thi khi không có phê duyệt hợp lệ; không thực thi hai lần vì thao tác lặp.','BA08, D108, D208','PM; 2 Dev'],
 ['BA10',4,15,16,4,'Chuẩn hóa nội dung báo cáo và thang đánh giá ảnh hưởng. Đối chiếu phát hiện với bằng chứng và phạm vi kiểm thử.','Mẫu báo cáo có phát hiện, căn cứ, mức độ xác minh, ảnh hưởng, giới hạn và bước khuyến nghị. Phát hiện thiếu bằng chứng không được xác nhận.','BA09','PM; Dev1'],
 ['BA11',4,17,18,5,'Chạy kiểm thử hệ thống: lỗi agent/tool, dừng đợt, dữ liệu độc hại, vượt phạm vi, báo cáo rỗng hoặc thiếu một phần.','Test log tách lỗi ứng dụng với lỗi chất lượng AI. Báo cáo giữ kết quả đã có và ghi bước chưa hoàn thành.','BA10, D110, D210','2 Dev; PM'],
 ['BA12',4,19,19,4,'Tổng hợp baseline 16 ca phát triển, thời gian, chi phí và failure case. Đề xuất ngưỡng chất lượng để PM chốt trước holdout.','Có công thức, mẫu số và số ca thực đo. Không lấy các ca HITL/lỗi để làm tăng độ chính xác phát hiện lỗ hổng.','BA11','PM; Dev1'],
 ['BA13',5,20,21,5,'Đánh giá 8 ca giữ riêng trên phiên bản đã ghi nhận. So đáp án và phân tích sai. Duy trì bộ ca riêng để sửa lỗi nếu cần.','Lưu từng lần chạy. Nếu dùng holdout để chỉnh hệ thống, công bố tập đã được dùng và giới hạn đánh giá; không gọi đó là đánh giá độc lập mới.','BA12, PM12','PM; Dev1'],
 ['BA14',5,22,23,4,'Điều phối UAT với PM làm Operator. BA làm Approver; chạy luồng chính, thay thế và lỗi theo checklist.','Mỗi Must có người xác nhận và bằng chứng. Dev giải thích vấn đề kỹ thuật; BA xác nhận hành vi nghiệp vụ thay vì tự duyệt mã nguồn.','BA13','PM; 2 Dev'],
 ['BA15',5,24,24,4,'Kiểm thử hồi quy các lỗi đã sửa. Hoàn thiện ma trận yêu cầu → test → kết quả → bằng chứng.','G4 có danh sách lỗi còn mở và kết luận đạt/chưa đạt. Không để ô chưa chạy nhưng ghi đạt.','BA14','PM'],
 ['BA16',6,25,26,4,'Viết hướng dẫn Operator và Approver, gồm điều kiện trước, thao tác và xử lý lỗi thường gặp.','Một thành viên khác dùng tài khoản demo làm theo được. Có giải thích staging, HITL, bằng chứng và giới hạn của AI.','BA15','PM; Dev2'],
 ['BA17',6,27,28,4,'Chốt kịch bản demo, kết quả eval và ma trận truy vết. Rà nội dung slide so với sản phẩm thực tế.','Cùng phiên bản giữa mã nguồn, báo cáo, video và tài liệu. Mọi số liệu trên slide có thể đối chiếu với kết quả lưu.','BA16','PM; 2 Dev'],
 ['BA18',6,29,29,3,'Chạy kiểm tra nhanh bản bàn giao. Kiểm tra hai vai trò, approve/reject, xuất báo cáo và quyền xem tài liệu.','G5 có kết quả kiểm tra cuối. Tài liệu liệt kê rõ các hạn chế và ca chưa hỗ trợ.','BA17','PM'],
],
Dev1:[
 ['D101',1,0,1,4,'Chạy khung backend/agent và test có sẵn. Kiểm kê phần dùng được. Khi dùng AI viết mã, đọc lại luồng đầu vào, công cụ và lỗi.','Chạy được ứng dụng và test nền. Giải thích được agent nào gọi công cụ nào và trạng thái được giữ ở đâu. Không coi code mẫu là tính năng đã xong.','PM01','Dev2'],
 ['D102',1,2,3,5,'Thiết kế Supervisor, 3 agent chuyên trách, trạng thái và dữ liệu bằng chứng. Chốt hợp đồng API với Dev2.','Có schema run, step, finding, evidence và approval dùng chung. BA duyệt nghĩa trạng thái; Dev2 dùng được dữ liệu mẫu để làm UI.','D101, BA01','Dev2; BA'],
 ['D103',1,4,4,4,'Lắp một luồng nhỏ với 4 agent dùng kết quả mô phỏng. Thêm trace từng bước và một lỗi có kiểm soát.','Luồng chạy hết trên máy dev, trạng thái lỗi không biến thành thành công. Dữ liệu giả được gắn nhãn rõ; Dev2 chạy lại được.','D102','Dev2'],
 ['D104',2,5,6,5,'Làm Supervisor điều phối tuần tự, lưu trạng thái và phục hồi. Giới hạn số bước, thời gian và quyền công cụ theo agent.','Khởi động lại đọc được trạng thái. Agent không tự thêm công cụ/phạm vi. Có test cho luồng chính và bước lỗi.','D103','Dev2'],
 ['D105',2,7,8,5,'Kết nối Recon với công cụ khảo sát chỉ đọc trên lab được phép. Chuẩn hóa điểm tìm thấy và lưu bằng chứng.','Kết quả có mục tiêu, thời gian, nguồn công cụ và evidence ID. Chặn mục tiêu/redirect ngoài phạm vi trước khi công cụ chạy.','D104, D204','Dev2; BA'],
 ['D106',2,9,9,3,'Tích hợp Recon với API và UI. Kiểm thử quyền gọi công cụ, timeout và kết quả rỗng.','G1 chạy bằng công cụ thật trên lab. Các bước Fuzzing/Exploit chưa xong phải hiển thị đúng là chưa hỗ trợ/mô phỏng.','D105, D205','Dev2; BA'],
 ['D107',3,10,11,5,'Làm Fuzzing với nhóm phép thử hữu hạn đã duyệt. Giới hạn số yêu cầu và thời gian. Liên kết kết quả với điểm Recon.','Có kết quả lặp lại được trên lab mẫu. Hành động có thể thay đổi trạng thái phải qua cùng cổng phê duyệt, kể cả từ Fuzzing.','D106, BA04','Dev2'],
 ['D108',3,12,13,5,'Làm Exploit đề xuất bước kiểm chứng có cấu trúc. Bảo vệ lớp gọi công cụ bằng phạm vi và phê duyệt còn hiệu lực.','Không chạy khi thiếu/sai/hết hạn phê duyệt. Phê duyệt gắn đúng run, hành động, mục tiêu, tham số và người duyệt. Đổi tham số phải duyệt lại.','D107, D207','Dev2'],
 ['D109',3,14,14,3,'Tích hợp chờ duyệt, tiếp tục và bỏ qua. Kiểm tra sự kiện lặp, dừng đợt và khởi động lại khi đang chờ.','Hành động chỉ thực hiện một lần. Từ chối/hết hạn không tự chuyển thành được duyệt; có test bằng chứng tại lớp thực thi.','D108, D208','Dev2; BA'],
 ['D110',4,15,16,5,'Tổng hợp phát hiện trùng hoặc mâu thuẫn. Sinh nội dung báo cáo gắn evidence ID và mức xác minh.','Kết luận không có căn cứ bị hạ thành nghi vấn hoặc không kiểm chứng được. Mâu thuẫn giữa agent được ghi rõ, không chọn ngẫu nhiên.','D109, BA09','Dev2; BA'],
 ['D111',4,17,18,4,'Hoàn thiện timeout, retry giới hạn và chống chỉ dẫn độc hại từ mục tiêu. Giữ bằng chứng khi một agent thất bại.','Nội dung mục tiêu không thay đổi quyền/công cụ. Retry không lặp lại hành động rủi ro đã thực thi; báo cáo ghi bước thiếu.','D110','Dev2'],
 ['D112',4,19,19,4,'Ghi thời gian, lỗi, số lần gọi, token/chi phí nếu nguồn cung cấp. Hỗ trợ chạy baseline và lưu phiên bản cấu hình.','Có dữ liệu đo cho từng run và trace tìm được lỗi. Chi phí không đo được phải ghi chưa có, không gán bằng 0.','D111','Dev2; BA'],
 ['D113',5,20,21,5,'Sửa lỗi agent và bằng chứng từ bộ phát triển/kiểm thử. Ưu tiên vượt quyền, sai trạng thái, sai kết luận và thiếu nguồn.','Mỗi lỗi có test tái hiện, bản sửa và kiểm tra chéo. Không dùng sửa prompt để thay cho kiểm soát quyền ở lớp thực thi.','D112, BA12','Dev2'],
 ['D114',5,22,23,5,'Kiểm thử kỹ thuật cổng thực thi: phê duyệt lặp, đổi mục tiêu, thu hồi, khởi động lại và quyền riêng từng agent. Tối ưu trên tập phát triển.','Toàn bộ test an toàn bắt buộc đạt. Ghi ảnh hưởng của chỉnh cấu hình tới chi phí/độ trễ; báo BA nếu thay phiên bản sau đánh giá.','D113','Dev2'],
 ['D115',5,24,24,3,'Đóng gói bản agent ứng viên bàn giao. Cập nhật kiến trúc, giới hạn, cách chạy test và đầu ra đánh giá.','Có phiên bản được cố định và hướng dẫn Dev2 chạy lại. Bằng chứng báo cáo/eval trỏ đúng bản đã bàn giao.','D114','Dev2; BA'],
 ['D116',6,25,26,4,'Hoàn thiện hướng dẫn cấu hình backend, công cụ, quyền và khôi phục trạng thái. Hỗ trợ kiểm tra cài lại.','Người khác chạy được từ tài liệu và dữ liệu mẫu. Không cần dùng khóa/tài khoản cá nhân của tác giả để hiểu hướng dẫn.','D115','Dev2'],
 ['D117',6,27,28,4,'Chạy agent trong hai lượt diễn tập. Sửa lỗi nhỏ phát sinh và kiểm tra lại phần bị tác động.','Luồng chính và tình huống lỗi có trace đầy đủ. Mọi thay đổi sau bản ứng viên được ghi nhận và BA kiểm lại.','D116','Dev2; BA'],
 ['D118',6,29,29,3,'Kiểm tra backend cuối: quyền công cụ, phiên chờ, giới hạn chạy và dữ liệu mẫu. Bàn giao mã/test/log tương ứng.','Backend phản hồi ổn định, có người khác biết cách dừng và chạy lại. G5 lưu đúng phiên bản triển khai.','D117','Dev2; BA'],
],
Dev2:[
 ['D201',1,0,1,5,'Dựng lab mô phỏng tách biệt, dữ liệu giả và cách reset. Chạy khung ứng dụng, Docker, test/CI. Chốt giao diện và cách triển khai đơn giản với Dev1.','Dev1 chạy lại được lab. Ghi rõ dữ liệu, kết nối và giới hạn; không dùng hệ thống thật. Liệt kê phần có sẵn và phần phải làm.','PM01','Dev1'],
 ['D202',1,2,3,5,'Thiết kế dữ liệu tài khoản, vai trò, run, approval và evidence. Chốt API với Dev1, phác màn hình theo BA.','Có hợp đồng API chung và dữ liệu mẫu. Quyền được kiểm tra ở server, không chỉ ẩn nút. BA xác nhận nội dung màn hình.','D201, BA01','Dev1; BA'],
 ['D203',1,4,4,3,'Làm giao diện khung và triển khai URL thử. Kết nối một API kiểm tra trạng thái. Cấu hình biến môi trường phù hợp.','Dev1/BA mở URL được và biết bản nào đang chạy. Không công khai khóa bí mật; chưa có dữ liệu thật trong môi trường.','D202','Dev1'],
 ['D204',2,5,6,5,'Làm đăng nhập, Operator/Approver, danh sách mục tiêu lab cho phép và tạo run. Lưu dữ liệu qua API.','Hai tài khoản có quyền khác nhau; nhập phạm vi sai bị server từ chối. Người tạo run không tự duyệt hành động của run đó.','D203, BA03','Dev1; BA'],
 ['D205',2,7,8,5,'Làm màn hình tiến trình đọc trạng thái thật của Supervisor. Hiển thị run, bước, lỗi và liên kết bằng chứng Recon.','Tải lại trang không mất phiên. Hiển thị đang chạy/đã lỗi/đã dừng đúng với backend, không dùng tiến trình giả.','D204, D104','Dev1'],
 ['D206',2,9,9,3,'Tích hợp trên URL thử. Kiểm tra login, quyền, tạo run và bằng chứng bằng trình duyệt khác.','G1 chạy được bởi BA. Lưu hướng dẫn truy cập và các API đã hỗ trợ; lỗi quyền có test tự động.','D205, D105','Dev1; BA'],
 ['D207',3,10,11,5,'Làm yêu cầu phê duyệt và màn hình Approver. Hiển thị lý do, ảnh hưởng, mục tiêu, hành động, tham số và hạn hiệu lực.','Approve/reject được server xác thực đúng người và trạng thái. Lưu người duyệt, thời điểm, nội dung đã duyệt; thiếu dữ kiện thì giữ chờ.','D206, BA03','Dev1; BA'],
 ['D208',3,12,12,4,'Tích hợp một kênh Slack hoặc Teams. Gửi yêu cầu và liên kết/quy trình Approve/Reject đã được nhóm xác nhận.','Thông báo gắn đúng run; danh tính người duyệt được xác thực. Kênh lỗi không làm agent tự tiếp tục. Hình thức tích hợp được PM/BA xác nhận phù hợp đề.','D207, PM05','Dev1; BA'],
 ['D209',3,13,14,4,'Kết nối quyết định với Supervisor. Chống gửi lặp, hiển thị hết hạn/từ chối và giữ nhật ký sau tải lại.','G2 có cả duyệt và từ chối. Yêu cầu trùng không tạo hai lần thực thi; callback cũ không mở quyền cho hành động mới.','D208','Dev1; BA'],
 ['D210',4,15,16,5,'Làm trang báo cáo và tải báo cáo HTML/JSON. Hiển thị bằng chứng, phát hiện, ảnh hưởng và bước chưa kiểm tra.','Báo cáo xuất được, đọc được và khớp với run. Không tự ghi an toàn khi không có phát hiện hoặc một agent thất bại.','D209, BA09','Dev1; BA'],
 ['D211',4,17,18,4,'Hoàn thiện thông báo lỗi, dừng đợt, retry hợp lệ và quyền xem báo cáo/log. Rà dữ liệu nhạy cảm trong UI/log.','Không lộ khóa hoặc dữ liệu không thuộc quyền người xem. Tải lại trang và truy cập báo cáo đúng vai trò đều được kiểm tra.','D210','Dev1; BA'],
 ['D212',4,19,19,4,'Hoàn thiện triển khai, giám sát lỗi/độ trễ và hạn mức. Kiểm tra kết nối UI–API–agent–kho dữ liệu trên môi trường online.','G3 chạy trọn luồng với dữ liệu lab. Có cách xem log theo run và nhận biết lỗi dịch vụ; quyền mạng chỉ tới mục tiêu cho phép.','D211','Dev1'],
 ['D213',5,20,21,5,'Sửa lỗi UI, API và quyền theo kết quả BA. Thêm kiểm thử hồi quy cho từng lỗi nghiêm trọng.','Lỗi có bước tái hiện, bản sửa, test và người kiểm lại. Lỗi quyền được thử bằng API trực tiếp.','D212, BA11','Dev1; BA'],
 ['D214',5,22,23,5,'Triển khai bản ứng viên. Thử sao lưu, khôi phục dữ liệu và khởi động lại khi có run chờ duyệt.','Dữ liệu và quyết định còn nguyên sau khôi phục. Chạy lại không lặp hành động đã thực hiện; có hướng dẫn phục hồi thực tế.','D213','Dev1'],
 ['D215',5,24,24,3,'Kiểm tra URL, tài khoản demo, healthcheck, log và phiên bản. Chuẩn bị gói dữ liệu mẫu và cấu hình không chứa khóa.','G4 có bản online dùng được và bản có thể cài lại. BA nhận được hướng dẫn truy cập đúng vai trò.','D214','Dev1; BA'],
 ['D216',6,25,26,4,'Hoàn thiện README vận hành: cài đặt, cấu hình, deploy, xem log, khôi phục và quản lý tài khoản.','Dev1 hoặc BA làm theo từ đầu được phần tương ứng. Ghi cách cung cấp khóa riêng; không đưa khóa thật vào hồ sơ.','D215','Dev1'],
 ['D217',6,27,28,4,'Hỗ trợ quay video, diễn tập và chuẩn bị dữ liệu reset demo. Kiểm tra giao diện trên thiết bị trình chiếu.','Video mở được; mẫu dữ liệu reset không làm mất bằng chứng cần bàn giao. Có phương án demo dự phòng đã thử.','D216','PM; BA'],
 ['D218',6,29,29,3,'Kiểm tra URL cuối và tài khoản bằng phiên trình duyệt mới. Rà quyền tải hồ sơ và cách dừng dịch vụ.','G5 có URL, tài khoản demo và hướng dẫn dùng được. Không dùng liên kết chỉ mở được trên máy của Dev2.','D217','Dev1; BA'],
]};

const gates=[
 ['G0',4,'Chốt phạm vi và chạy khung','Một lab, nhóm phép thử hữu hạn, backlog Must, API chung và luồng 4 agent mô phỏng có nhãn. Hai dev giải thích được mã và chạy lại phần của nhau.','PM','Nếu chưa chạy/hiểu được khung: giảm công nghệ, thu nhỏ phép thử và tìm hỗ trợ kỹ thuật; chưa hứa toàn bộ tính năng.'],
 ['G1',9,'Operator → Recon → bằng chứng','URL thử có hai vai trò. Tạo run đúng phạm vi, Recon dùng công cụ thật, lưu trạng thái/bằng chứng. Ngoài phạm vi bị chặn.','PM + BA','Nếu tích hợp trễ: ưu tiên nối một luồng hoàn chỉnh; hoãn dashboard đẹp và tính năng phụ.'],
 ['G2',14,'Fuzzing, Exploit và HITL','Approve/reject/hết hạn/sai quyền/đổi tham số được thử. Agent không vượt cổng thực thi. Một kênh Slack/Teams đã kết nối theo phạm vi được xác nhận.','BA + 2 Dev','Nếu kiểm soát an toàn lỗi: khóa thực thi bước rủi ro, sửa trước khi mở lại; không bỏ cổng để kịp demo.'],
 ['G3',19,'MVP đủ luồng và baseline','Có báo cáo gắn bằng chứng, xử lý lỗi và số liệu 16 ca phát triển. Chốt ngưỡng AI trước holdout. Khóa tính năng.','PM + BA','Cắt toàn bộ Could; ưu tiên Must còn thiếu. Công bố giới hạn và chốt lại lịch nếu Must không thể hoàn thành.'],
 ['G4',24,'Ứng viên bàn giao','8 ca giữ riêng được đo có phiên bản. UAT và kiểm thử hồi quy đạt; không còn lỗi an toàn/luồng chính/bằng chứng nghiêm trọng. Thử khôi phục thành công.','PM + BA','Không phát hành như bản đạt khi lỗi chặn còn mở. Dùng dự phòng tuần 6, cập nhật phạm vi hoặc hạn với nhóm.'],
 ['G5',29,'Demo và bàn giao','Hai lượt diễn tập, luồng chính và lỗi, URL dùng được, đủ 10 đầu ra theo README và yêu cầu BTC đã xác nhận. Mã nguồn, eval, video cùng phiên bản.','PM','Nếu live lỗi: dùng bản quay đã ghi nhãn; nói rõ trạng thái thực tế, khắc phục và thông báo người nhận.'],
];

const deliveries=[
 ['BG01',29,'Mã nguồn và dữ liệu mẫu','Có bản cố định, test và dữ liệu lab không nhạy cảm; người khác tải và chạy lại được.','Dev1 + Dev2'],
 ['BG02',28,'README và hướng dẫn vận hành','Cài đặt, cấu hình, tài khoản demo, deploy, xem log và khôi phục.','Dev2'],
 ['BG03',28,'Sơ đồ kiến trúc','Luồng dữ liệu, agent, công cụ, quyền, trạng thái, HITL và lưu bằng chứng.','Dev1'],
 ['BG04',29,'AI logs và trace','Dấu vết sử dụng AI/agent theo quy định BTC, không chứa khóa; nhóm tự xác nhận cách nộp hợp lệ.','Cả nhóm'],
 ['BG05',29,'URL chạy thật','Mở từ thiết bị khác, đăng nhập hai vai trò, chạy luồng được hỗ trợ.','Dev2'],
 ['BG06',28,'Video demo','Luồng chính và một lỗi; cùng phiên bản sản phẩm bàn giao.','Dev2 + PM'],
 ['BG07',28,'Slide thuyết trình','Vấn đề, người dùng, giá trị, phạm vi, kiến trúc, kết quả đo và giới hạn.','PM'],
 ['BG08',29,'Nhật ký quyết định','Lý do chọn phạm vi/công nghệ, thay đổi quan trọng và bài học.','PM'],
 ['BG09',29,'Worklog nhóm','Ai làm gì, thời gian thực tế, kết quả và liên kết bằng chứng.','Cả nhóm'],
 ['BG10',28,'Bằng chứng đánh giá','Bộ ca, đáp án, phiên bản, kết quả từng ca, chỉ số, lỗi và cải tiến; có truy vết yêu cầu.','BA + Dev1'],
];

const acceptance=[
 ['AC01','Quyền','Có tài khoản Operator và Approver','Operator gọi API phê duyệt hoặc tự duyệt run của mình','Server từ chối; không có thực thi và có nhật ký.','BA + Dev2'],
 ['AC02','Phạm vi','Chỉ lab đã đăng ký được phép','Nhập mục tiêu ngoài phạm vi hoặc công cụ gặp redirect ngoài phạm vi','Chặn trước khi gửi yêu cầu tới mục tiêu ngoài phạm vi.','Dev1 + Dev2'],
 ['AC03','Luồng chính','Lab sẵn sàng, phạm vi hợp lệ','Operator khởi tạo run','Supervisor gọi đúng agent; UI và kho dữ liệu cùng trạng thái.','BA'],
 ['AC04','Bằng chứng','Recon/Fuzzing có kết quả từ công cụ','Xem một phát hiện','Có run ID, nguồn, thời gian, mục tiêu và evidence ID đối chiếu được.','BA + Dev1'],
 ['AC05','HITL chờ','Bước có rủi ro vừa được đề xuất','Chưa có phê duyệt hợp lệ','Run/bước chờ; không gọi công cụ rủi ro. Kiểm tra tại lớp thực thi.','Dev1 + BA'],
 ['AC06','HITL duyệt','Approver đúng quyền và yêu cầu còn hiệu lực','Duyệt đúng hành động và tham số','Chỉ hành động đó tiếp tục trong phạm vi; lưu người và thời điểm duyệt.','BA'],
 ['AC07','Từ chối/hết hạn','Một yêu cầu đang chờ','Bị từ chối hoặc hết thời hạn','Không thực thi; bỏ qua/dừng theo quy tắc; báo cáo nêu bước chưa kiểm chứng.','BA'],
 ['AC08','Thay đổi/lặp','Hành động đã được duyệt','Đổi mục tiêu/tham số hoặc nhận callback lặp','Thay đổi cần duyệt lại; sự kiện lặp không làm thực thi hai lần.','Dev1 + Dev2'],
 ['AC09','Lỗi kênh','Đang gửi yêu cầu tới Slack/Teams','Kênh lỗi hoặc trả kết quả không xác thực được','Giữ chờ/thất bại rõ; không coi lỗi gửi là được duyệt.','BA + Dev2'],
 ['AC10','Khôi phục','Run đang chờ duyệt hoặc đã chạy một bước','Khởi động lại/khôi phục dữ liệu','Giữ trạng thái và bằng chứng; không tự bỏ qua cổng hoặc lặp bước rủi ro.','2 Dev'],
 ['AC11','Agent/tool lỗi','Một agent đang chạy','Công cụ timeout hoặc dịch vụ lỗi','Retry trong giới hạn nếu được phép; kết thúc một phần/thất bại rõ, giữ bằng chứng đã có.','BA + Dev1'],
 ['AC12','Dữ liệu độc hại','Mục tiêu trả nội dung cố ra lệnh cho AI','Agent đọc nội dung đó','Nội dung không tăng quyền, đổi mục tiêu hay vượt bước phê duyệt.','Dev1 + BA'],
 ['AC13','Kết luận','Hai agent mâu thuẫn hoặc bằng chứng thiếu','Hệ thống tổng hợp báo cáo','Đánh dấu chưa xác minh/mâu thuẫn; không khẳng định lỗ hổng không có bằng chứng.','BA'],
 ['AC14','Không phát hiện','Run không có phát hiện hoặc bị gián đoạn','Xuất báo cáo','Nêu phạm vi đã kiểm tra và giới hạn; không kết luận hệ thống hoàn toàn an toàn.','BA + PM'],
 ['AC15','Giới hạn/dừng','Run gần hạn số bước/thời gian hoặc bị hủy','Chạm hạn hoặc Operator dừng','Không phát sinh thêm hành động không được phép; trạng thái cuối và lý do được lưu.','2 Dev + BA'],
 ['AC16','Báo cáo','Run có kết quả và bằng chứng','Người được phép xem/tải báo cáo','Nội dung tải khớp run; người không có quyền bị từ chối; không lộ khóa.','BA + Dev2'],
 ['AC17','Đánh giá AI','Bộ ca có nhãn và phiên bản cấu hình cố định','Chạy đánh giá','Lưu từng kết quả, số ca, mẫu số và thất bại. Không trình bày dữ liệu mô phỏng như thành tích kiểm thử thực tế.','BA + Dev1'],
 ['AC18','Bàn giao','Bản ứng viên đã nghiệm thu','Thành viên khác mở URL và làm theo hướng dẫn','Đăng nhập hai vai trò, chạy ca được hỗ trợ và mở báo cáo; biết cách dừng/khôi phục.','PM + BA'],
];

const wb=Workbook.create();
for(const name of ['Tong quan','PM','BA','Dev1','Dev2','Checkpoint','Nghiem thu'])wb.worksheets.add(name);
const colors={navy:'#183852',blue:'#315C86',pale:'#F0F4F8',ink:'#172B3A',amber:'#FFF2CC',line:'#D6DEE6',red:'#FCE5E5'};
function base(name,lastCol,lastRow,widths){
 const s=wb.worksheets.getItem(name);s.showGridLines=false;
 s.getRange(`A1:${lastCol}${lastRow}`).format.font={name:'Arial',size:11,color:colors.ink};
 s.getRange(`A1:${lastCol}${lastRow}`).format.rowHeight=24;
 s.getRange(`A1:${lastCol}${lastRow}`).format.verticalAlignment='center';
 widths.forEach((w,i)=>s.getRangeByIndexes(0,i,lastRow,1).format.columnWidthPx=w);
 return s;
}
function title(s,text,lastCol){s.getRange('A2').values=[[text]];s.getRange('A2').format.font={name:'Arial',size:16,bold:true,color:colors.navy};s.getRange(`A3:${lastCol}3`).format.borders={bottom:{style:'thin',color:colors.line}};}
function header(s,range){s.getRange(range).format={fill:colors.navy,font:{name:'Arial',size:11,bold:true,color:'#FFFFFF'},wrapText:true,horizontalAlignment:'center',verticalAlignment:'center',rowHeight:38};}
function dateFormula(offset){return `=WORKDAY('Tong quan'!$B$5-1,${offset+1})`;}
const taskStates=['Chưa bắt đầu','Đang làm','Bị chặn','Chờ kiểm tra','Hoàn thành'];
const overview=base('Tong quan','I',61,[172,116,116,116,116,116,116,136,190]);
title(overview,'PentestSyndicate | Kế hoạch nhóm 4 người','I');overview.tabColor=colors.navy;
overview.getRange('A4').values=[['Lịch đề xuất 6 tuần. Hạn nộp và thời gian mỗi người chưa được nhóm xác nhận.']];
overview.getRange('A5:B8').values=[['Ngày bắt đầu',new Date('2026-09-21T00:00:00Z')],['Họp/người/tuần (giờ)',1.5],['Dự phòng/người/tuần',3],['Review/người/tuần',2]];
overview.getRange('B5').setNumberFormat('dd/mm/yyyy');overview.getRange('B5:B8').format.fill=colors.amber;
overview.getRange('D5').values=[['Hạn kế hoạch']];overview.getRange('E5').formulas=[[dateFormula(29)]];overview.getRange('E5').setNumberFormat('dd/mm/yyyy');
overview.getRange('D6').values=[['Mốc giờ']];overview.getRange('E6').values=[['18:00, giờ Việt Nam']];
overview.getRange('D7').values=[['Lưu ý lịch']];overview.getRange('E7').values=[['Tính thứ Hai–thứ Sáu. Chưa trừ ngày nghỉ riêng của nhóm.']];
overview.getRange('A10:I10').values=[['Người','Việc (giờ)','Họp/review (giờ)','Dự phòng (giờ)','Tổng (giờ)','Đã nghiệm thu','Bị chặn','Tổng việc','Vai trò']];header(overview,'A10:I10');
const roleDesc={PM:'Bạn: PM, hỗ trợ BA',BA:'BA chính, kiểm thử nghiệp vụ',Dev1:'Agent, công cụ, kiểm thử lõi',Dev2:'UI, API, dữ liệu, triển khai'};
for(const [idx,name]of Object.keys(tasks).entries()){
 const r=11+idx;overview.getRange(`A${r}`).values=[[name]];overview.getRange(`I${r}`).values=[[roleDesc[name]]];
 overview.getRange(`B${r}:H${r}`).formulas=[[
 `=SUM('${name}'!$E$8:$E$25)`,`=SUM($B$6,$B$8)*6`,`=$B$7*6`,`=SUM(B${r}:D${r})`,
 `=COUNTIFS('${name}'!$O$8:$O$25,"Đã nghiệm thu")`,`=COUNTIFS('${name}'!$J$8:$J$25,"Bị chặn")`,`=COUNTA('${name}'!$A$8:$A$25)`]];
}
overview.getRange('A11:I14').format.rowHeight=42;overview.getRange('I11:I14').format.wrapText=true;
overview.getRange('F11:H14').format.horizontalAlignment='center';
overview.getRange('A17:I17').values=[['Tải công việc','Tuần 1','Tuần 2','Tuần 3','Tuần 4','Tuần 5','Tuần 6','Giờ/tuần cam kết','Tuần vượt mức']];header(overview,'A17:I17');
Object.keys(tasks).forEach((name,i)=>{
 const r=18+i;overview.getRange(`A${r}`).values=[[name]];
 overview.getRange(`B${r}:G${r}`).formulas=[[1,2,3,4,5,6].map(w=>`=SUMIFS('${name}'!$E$8:$E$25,'${name}'!$B$8:$B$25,${w})+SUM($B$6:$B$8)`)];
 overview.getRange(`H${r}`).values=[[20]];overview.getRange(`I${r}`).formulas=[[`=COUNTIFS(B${r}:G${r},">"&H${r})`]];
});
overview.getRange('H18:H21').format.fill=colors.amber;overview.getRange('B18:H21').setNumberFormat('0.0');
overview.getRange('I18:I21').conditionalFormats.add('cellIs',{operator:'greaterThan',formula:0,format:{fill:colors.red,font:{bold:true,color:'#9C2424'}}});
const notes=[
 'Cách dùng và giả định',
 'Ô vàng là dữ liệu cần cập nhật. Các task là đề xuất, chưa được xác nhận là đã hoàn thành.',
 'Mỗi người cập nhật trạng thái, kết quả kiểm tra, bằng chứng, giờ thực tế và vướng mắc tại tab của mình.',
 'Chỉ tính Đã nghiệm thu khi trạng thái Hoàn thành, người kiểm tra chọn Đạt và có liên kết bằng chứng.',
 'Đổi B5 sẽ dời ngày bắt đầu và deadline. Tuần được tính bằng 5 ngày làm việc; chưa có lịch nghỉ lễ riêng.',
 'Đổi giờ cam kết ở H18:H21. Nếu có tuần vượt mức, PM giảm phạm vi hoặc chốt lại lịch trước khi cam kết.',
 'Mỗi tuần thêm 1,5 giờ họp, 2 giờ kiểm tra chéo và 3 giờ dự phòng/người ngoài giờ task.',
 'Hai dev đều dùng AI viết mã. Phân công theo đầu ra, chưa giả định có chuyên môn AI/backend/frontend.',
 'Dev phải giải thích luồng chính, quyền và lỗi của mã mình nhận. Dev còn lại chạy kiểm tra chéo.',
 'BA viết yêu cầu và kiểm thử nghiệp vụ. PM chốt phạm vi, gỡ vướng, hỗ trợ BA và quyết định nghiệm thu.',
 'PM/BA không thay thế kiểm tra kỹ thuật. Hai dev chịu trách nhiệm code, test, quyền và vận hành.',
 'Một lab mô phỏng, dữ liệu giả/ẩn danh, nhóm phép thử hữu hạn. Không kiểm thử hệ thống thật.',
 'Must: hai vai trò, 4 agent có trạng thái/tool-use, quyền công cụ, HITL, bằng chứng, báo cáo, lỗi, eval, deploy.',
 'Một kênh Slack hoặc Teams được đưa vào kế hoạch theo ràng buộc đề tài. Chốt hình thức tại PM05.',
 'Should: cải thiện biểu diễn chuỗi kiểm thử, chống trùng phát hiện, khả năng phục hồi và hướng dẫn rõ.',
 'Could: PDF đẹp, nhiều lab, RAG/GraphRAG nâng cao, dashboard phong phú. Chỉ làm sau khi Must đạt.',
 'Won’t trong MVP: production, tự mở rộng mục tiêu, payload tùy ý hoặc hành động rủi ro không được duyệt.',
 'Nếu chọn RAG, phải có đánh giá truy xuất theo tiêu chí đề; không thêm chỉ để đủ tên công nghệ.',
 'Đầu tuần họp 20 phút; giữa tuần tích hợp 20 phút; cuối tuần demo/checkpoint 50 phút.',
 'Mỗi ngày cập nhật ngắn: đã làm, tiếp theo, vướng mắc. Vướng quá một ngày làm việc phải báo PM.',
 'Mỗi dev giữ tối đa một việc chính đang làm. Yêu cầu mới phải có lý do, công sức và phần bị ảnh hưởng.',
 'Sau G3 khóa tính năng; sau G4 chỉ sửa lỗi và hoàn thiện bàn giao. Dự phòng không dùng để thêm Could.',
 'Nguồn và phạm vi xác nhận',
 'Người dùng: 4 người gồm PM/hỗ trợ BA, BA chính, 2 dev; cả hai dev dùng AI hỗ trợ viết mã.',
 'Ảnh quy định chung và ảnh VSOC-04: đầu ra, staging/mô phỏng, HITL, phân quyền, eval và hồ sơ bàn giao.',
 'README.md tại D:/P-077: khung AI20K và 10 đầu ra Demo Day. WORKLOG.md đang là mẫu.',
 'Đã xem README.md, ARCHITECTURE.md và src/agents/graph.py. Đây là quan sát một phần, chưa audit toàn repo.',
 'Ngày, giờ, 24 ca eval và khối lượng là đề xuất lập kế hoạch. Chưa có số liệu tiến độ hoặc hiệu quả thực đo.',
 'Chuỗi phụ thuộc chính: BA02/D102/D202 → Recon → HITL → báo cáo → eval/UAT → bàn giao.',
 'Deadline: ngày trong task lúc 18:00. Khi phụ thuộc cùng ngày, bàn giao phần cần dùng trước ca tích hợp.',
 'Số ca eval nhỏ phục vụ demo, không chứng minh sản phẩm phát hiện đầy đủ lỗ hổng ngoài môi trường này.',
 'Trước chạy hành động có rủi ro, nhóm cần người có năng lực xác nhận lab và cơ chế kiểm soát phù hợp.',
];
notes.forEach((t,i)=>{overview.getRange(`A${24+i}`).values=[[t]];overview.getRange(`A${24+i}:I${24+i}`).format.rowHeight=26;});
overview.getRange('A24').format.font={bold:true,size:13,color:colors.navy};overview.getRange('A46').format.font={bold:true,size:13,color:colors.navy};

for(const [name,rows] of Object.entries(tasks)){
 const s=base(name,'O',25,[92,48,94,94,58,360,390,165,108,142,126,180,88,220,155]);
 title(s,`${name} | ${roleDesc[name]}`,'O');
 s.getRange('A4').values=[['Ngày tự dời theo Tong quan!B5. Giờ là ước tính. Ô vàng dùng để cập nhật tiến độ và kiểm tra.']];
 s.getRange('A5').values=[['Hoàn thành = có đầu ra + người kiểm tra chọn Đạt + bằng chứng. Hai dev kiểm tra chéo mã do AI hỗ trợ tạo.']];
 s.getRange('A7:O7').values=[['Mã việc','Tuần','Bắt đầu','Deadline','Giờ dự kiến','Công việc cần làm','Hoàn thành khi','Phụ thuộc','Người kiểm tra','Trạng thái','Kết quả kiểm tra','Liên kết bằng chứng','Giờ thực tế','Vướng mắc / cập nhật','Nghiệm thu']];header(s,'A7:O7');
 s.getRange('A8:O25').values=rows.map(t=>[t[0],t[1],null,null,t[4],t[5],t[6],t[7],t[8],'Chưa bắt đầu','Chưa kiểm tra',null,null,null,null]);
 s.getRange('C8:D25').formulas=rows.map(t=>[dateFormula(t[2]),dateFormula(t[3])]);s.getRange('C8:D25').setNumberFormat('dd/mm/yyyy');
 s.getRange('O8').formulas=[['=IF(J8="Hoàn thành",IF(AND(K8="Đạt",L8<>""),"Đã nghiệm thu","Thiếu xác nhận"),J8)']];s.getRange('O8:O25').fillDown();
 s.getRange('A8:O25').format.wrapText=true;s.getRange('A8:O25').format.verticalAlignment='top';s.getRange('A8:O25').format.rowHeight=80;
 s.getRange('B8:E25').format.horizontalAlignment='center';s.getRange('J8:N25').format.fill=colors.amber;s.getRange('O8:O25').format.fill=colors.pale;
 s.getRange('J8:J25').dataValidation={rule:{type:'list',values:taskStates}};
 s.getRange('K8:K25').dataValidation={rule:{type:'list',values:['Chưa kiểm tra','Cần sửa','Đạt']}};
 s.getRange('O8:O25').conditionalFormats.add('containsText',{text:'Thiếu xác nhận',format:{fill:colors.red,font:{color:'#9C2424',bold:true}}});
 s.getRange('J8:J25').conditionalFormats.add('containsText',{text:'Bị chặn',format:{fill:colors.red,font:{color:'#9C2424',bold:true}}});
 s.getRange('D8:D25').conditionalFormats.addCustom('AND($D8<TODAY(),$O8<>"Đã nghiệm thu")',{fill:colors.red,font:{color:'#9C2424'}});
 for(let i=0;i<6;i++)s.getRange(`A${8+3*i}:O${8+3*i}`).format.borders={top:{style:'thin',color:colors.line}};
 const table=s.tables.add('A7:O25',true,`${name}Tasks`);table.showFilterButton=true;table.style='TableStyleLight9';
 s.freezePanes.freezeRows(7);s.freezePanes.freezeColumns(2);
}

const cp=base('Checkpoint','H',27,[82,96,280,430,120,132,200,290]);title(cp,'Checkpoint và hồ sơ bàn giao','H');
cp.getRange('A4').values=[['PM chủ trì đánh giá. Người kiểm tra lưu bằng chứng và chọn Đạt/Chưa đạt; ngày là mốc đề xuất.']];
cp.getRange('A6:H6').values=[['Mốc','Deadline','Đầu ra cần xem','Điều kiện qua mốc','Người xác nhận','Kết quả','Bằng chứng','Nếu chưa đạt']];header(cp,'A6:H6');
cp.getRange('A7:H12').values=gates.map(g=>[g[0],null,g[2],g[3],g[4],'Chưa kiểm tra',null,g[5]]);
cp.getRange('B7:B12').formulas=gates.map(g=>[dateFormula(g[1])]);cp.getRange('B7:B12').setNumberFormat('dd/mm/yyyy');
cp.getRange('A7:H12').format.wrapText=true;cp.getRange('A7:H12').format.rowHeight=80;cp.getRange('A7:H12').format.verticalAlignment='top';cp.getRange('F7:G12').format.fill=colors.amber;
cp.getRange('F7:F12').dataValidation={rule:{type:'list',values:['Chưa kiểm tra','Chưa đạt','Đạt']}};
cp.getRange('A15').values=[['10 đầu ra bàn giao theo README hiện có; đối chiếu yêu cầu BTC trước khi nộp.']];
cp.getRange('A17:H17').values=[['Mã','Deadline','Hạng mục','Điều kiện bàn giao','Chủ trì','Kết quả','Bằng chứng','Ghi chú']];header(cp,'A17:H17');
cp.getRange('A18:H27').values=deliveries.map(d=>[d[0],null,d[2],d[3],d[4],'Chưa kiểm tra',null,null]);
cp.getRange('B18:B27').formulas=deliveries.map(d=>[dateFormula(d[1])]);cp.getRange('B18:B27').setNumberFormat('dd/mm/yyyy');
cp.getRange('A18:H27').format.wrapText=true;cp.getRange('A18:H27').format.rowHeight=80;cp.getRange('A18:H27').format.verticalAlignment='top';cp.getRange('F18:H27').format.fill=colors.amber;
cp.getRange('F18:F27').dataValidation={rule:{type:'list',values:['Chưa kiểm tra','Chưa đạt','Đạt']}};cp.freezePanes.freezeRows(6);

const ac=base('Nghiem thu','H',41,[85,115,300,290,420,125,120,185]);title(ac,'Checklist nghiệm thu và cách đo','H');
ac.getRange('A4').values=[['Given = điều kiện trước. When = thao tác. Then = kết quả cần kiểm tra. Đây là đề xuất, chưa có kết quả thực tế.']];
ac.getRange('A6:H6').values=[['Mã','Nhóm','Given — Đã có','When — Khi','Then — Phải xảy ra','Người kiểm tra','Kết quả','Bằng chứng']];header(ac,'A6:H6');
ac.getRange('A7:H24').values=acceptance.map(a=>[...a,'Chưa chạy',null]);ac.getRange('A7:H24').format.wrapText=true;ac.getRange('A7:H24').format.rowHeight=64;ac.getRange('A7:H24').format.verticalAlignment='top';ac.getRange('G7:H24').format.fill=colors.amber;
ac.getRange('G7:G24').dataValidation={rule:{type:'list',values:['Chưa chạy','Đạt','Chưa đạt','Bị chặn']}};ac.freezePanes.freezeRows(6);ac.freezePanes.freezeColumns(2);
ac.getRange('A27').values=[['Chỉ số đánh giá: BA định nghĩa và Dev1 xuất dữ liệu. Không có số đo sẵn trong kế hoạch.']];
ac.getRange('A29:F29').values=[['Mã','Chỉ số','Cách tính / ghi nhận','Phạm vi','Ngưỡng / cách dùng','Chủ trì']];header(ac,'A29:F29');
ac.getRange('A30:F37').values=[
 ['M01','Precision','TP / (TP + FP). TP: phát hiện khớp nhãn; FP: phát hiện sai.','Chỉ ca/đơn vị phát hiện có nhãn nhất quán.','PM/BA chốt ngưỡng tại G3 trước holdout. Mẫu số 0 ghi không áp dụng.','BA + Dev1'],
 ['M02','Recall','TP / (TP + FN). FN: phát hiện kỳ vọng nhưng bị bỏ sót.','Cùng loại lỗ hổng, mục tiêu và cách gán nhãn.','PM/BA chốt tại G3; không cộng ca kiểm thử HITL vào mẫu số.','BA + Dev1'],
 ['M03','Báo động sai','FP / (FP + TN). TN: ca sạch được nhận đúng.','Đơn vị phân loại dương/âm thống nhất từ BA04.','Nếu đo theo finding, phải thống nhất TN trước; không thay bằng 1 - precision.','BA + Dev1'],
 ['M04','Có bằng chứng','Số kết luận đã xác minh có evidence đối chiếu được / tổng kết luận đã xác minh.','Mỗi kết luận đã xác minh trong báo cáo.','Đề xuất 100%; kết luận thiếu bằng chứng phải hạ mức xác minh.','BA'],
 ['M05','Vượt quyền/HITL','Số ca thực thi ngoài phạm vi hoặc thiếu phê duyệt hợp lệ.','Toàn bộ ca an toàn bắt buộc.','Đề xuất 0 vi phạm; mọi ca an toàn bắt buộc phải đạt trước G4.','2 Dev + BA'],
 ['M06','Thời gian chạy','Ghi thời điểm bắt đầu, kết thúc, thời gian chờ duyệt và xử lý riêng.','Cùng lab, cấu hình, phiên bản; ghi số lượt đo.','Theo dõi trung vị/p95 khi đủ lượt; không đưa ngưỡng hiệu năng chưa đo.','Dev1 + Dev2'],
 ['M07','Chi phí/run','Tổng chi phí có nguồn đo cho từng run; ghi nguồn và hạng mục chưa đo.','Không gán chi phí chưa biết bằng 0.','PM chốt ngân sách thử ở tuần 1, rà theo số đo mỗi tuần.','Dev1 + PM'],
 ['M08','Hoàn tất/hồi phục','Đếm run hoàn tất, một phần, lỗi; run phục hồi thành công / run được thử phục hồi.','Tách lỗi kỹ thuật với từ chối hợp lệ của Approver.','Không coi bỏ qua do từ chối là lỗi hệ thống; ghi rõ các loại kết quả.','BA + 2 Dev'],
];ac.getRange('A30:F37').format.wrapText=true;ac.getRange('A30:F37').format.rowHeight=86;ac.getRange('A30:F37').format.verticalAlignment='top';
ac.getRange('A40').values=[['24 ca eval là tập minh họa đề xuất; checklist trên và các test kỹ thuật bổ sung có thể dùng nhiều lượt hơn.']];
ac.getRange('A41').values=[['Không dùng holdout để chỉnh rồi báo lại như đánh giá độc lập. Công bố giới hạn và lịch sử thay đổi phiên bản.']];

// Independent checks on schedule, references, estimates and human completion gates.
const all=Object.values(tasks).flat();const ids=new Set(all.map(t=>t[0]));assert.equal(ids.size,72);
for(const [name,rows]of Object.entries(tasks)){
 assert.equal(rows.length,18);
 for(const t of rows){assert(t[2]<=t[3]);assert(t[2]>=5*(t[1]-1)&&t[3]<5*t[1]);}
 for(let w=1;w<=6;w++){const h=rows.filter(t=>t[1]===w).reduce((a,t)=>a+t[4],0)+6.5;assert(h<=20,`${name} week ${w}: ${h}`);}
 for(const t of rows){for(const dep of t[7].split(',').map(s=>s.trim()).filter(s=>s!=='Không'))assert(ids.has(dep),`${t[0]} missing ${dep}`);}
}
const byId=new Map(all.map(t=>[t[0],t]));
const visiting=new Set(),visited=new Set();
function visit(id){if(visited.has(id))return;assert(!visiting.has(id),`Cycle: ${id}`);visiting.add(id);const t=byId.get(id);for(const dep of t[7].split(',').map(x=>x.trim()).filter(x=>x!=='Không')){assert(byId.get(dep)[3]<=t[2],`Dependency too late: ${dep} -> ${id}`);visit(dep);}visiting.delete(id);visited.add(id);}
for(const id of ids)visit(id);
wb.recalculate();
const pm=wb.worksheets.getItem('PM');
pm.getRange('J8').values=[['Hoàn thành']];assert.equal(pm.getRange('O8').values[0][0],'Thiếu xác nhận');
pm.getRange('K8').values=[['Đạt']];assert.equal(pm.getRange('O8').values[0][0],'Thiếu xác nhận');
pm.getRange('L8').values=[['https://example.test/evidence']];assert.equal(pm.getRange('O8').values[0][0],'Đã nghiệm thu');
assert.equal(overview.getRange('F11').values[0][0],1);
pm.getRange('J8:L8').values=[['Chưa bắt đầu','Chưa kiểm tra',null]];
assert.equal(overview.getRange('F11').values[0][0],0);
const before=pm.getRange('D8').values[0][0];overview.getRange('B5').values=[[new Date('2026-09-28T00:00:00Z')]];
const after=pm.getRange('D8').values[0][0];assert.equal(after-before,7);
overview.getRange('B5').values=[[new Date('2026-09-21T00:00:00Z')]];
overview.getRange('H19').values=[[10]];assert.equal(overview.getRange('I19').values[0][0],6);overview.getRange('H19').values=[[20]];
wb.recalculate();
console.log((await wb.inspect({kind:'table',range:'Tong quan!A10:I21',include:'values,formulas',tableMaxRows:12,tableMaxCols:9,maxChars:2500})).ndjson);
console.log((await wb.inspect({kind:'match',searchTerm:'#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A|#NUM!|#NULL!|#SPILL!|#CALC!',options:{useRegex:true,maxResults:30},summary:'Final formula error scan',maxChars:1000})).ndjson);
await fs.mkdir(outputDir,{recursive:true});
for(const [sheetName,range]of [['Tong quan','A1:I22'],['PM','A1:I11'],['BA','A1:I11'],['Dev1','A1:I11'],['Dev2','A1:I11'],['Checkpoint','A1:H12'],['Nghiem thu','A1:H12']]){
 const blob=await wb.render({sheetName,range,scale:1,format:'png'});await fs.writeFile(`${workDir}/${sheetName}.png`,new Uint8Array(await blob.arrayBuffer()));
}
for(const [sheetName,range,file]of [['PM','J7:O11','task-controls'],['BA','A17:I25','later-tasks'],['Checkpoint','A15:H27','handover'],['Nghiem thu','A27:F37','metrics'],['Tong quan','A24:I55','notes']]){const blob=await wb.render({sheetName,range,scale:1,format:'png'});await fs.writeFile(`${workDir}/${file}.png`,new Uint8Array(await blob.arrayBuffer()));}
const xlsx=await SpreadsheetFile.exportXlsx(wb);await xlsx.save(`${outputDir}/PentestSyndicate_Ke_hoach_4_nguoi.xlsx`);
await fs.writeFile(`${workDir}/plan-data.json`,JSON.stringify({tasks,gates,deliveries,acceptance},null,2));
console.log(JSON.stringify({output:`${outputDir}/PentestSyndicate_Ke_hoach_4_nguoi.xlsx`,taskCount:all.length,hours:Object.fromEntries(Object.entries(tasks).map(([n,ts])=>[n,ts.reduce((a,t)=>a+t[4],0)])),checks:'schedule, formula errors, completion prerequisites, changing start date, capacity'}));
