# Ransomware Analysis Portal

Hệ thống phân tích ransomware và IOC (Indicators of Compromise) tích hợp với VirusTotal API và Google Gemini AI, cung cấp nền tảng phân tích bảo mật chuyên nghiệp cho các security analyst và SOC teams.

## 📋 Tổng Quan

Ransomware Analysis Portal là một ứng dụng web full-stack cho phép người dùng:

- **Quét và phân tích IOC**: Hash (MD5, SHA1, SHA256), Domain, IP Address, URL
- **Upload file để phân tích**: Tải file lên và quét với 70+ security engines từ VirusTotal
- **Phân tích AI thông minh**: Sử dụng Google Gemini AI để đánh giá rủi ro và đưa ra khuyến nghị bảo mật
- **Quản lý lịch sử**: Lưu trữ và theo dõi tất cả các lần quét
- **Cộng đồng**: Chia sẻ threat intelligence và thảo luận về các mối đe dọa
- **Quản lý người dùng**: Hệ thống xác thực với JWT, OTP email, và 2FA

## 🛠️ Công Nghệ

### Backend
- **Framework**: Flask (Python)
- **Database**: MySQL/SQLite với SQLAlchemy ORM
- **Authentication**: JWT (PyJWT), bcrypt
- **Email Service**: Flask-Mail (OTP, verification)
- **AI Integration**: Google Gemini API
- **External API**: VirusTotal API v3
- **Security**: PyOTP (2FA), rate limiting, input validation

### Frontend
- **Framework**: React 18.2
- **Routing**: React Router DOM v6
- **UI Library**: React Bootstrap 5.3, Bootstrap Icons
- **HTTP Client**: Axios
- **Build Tool**: Vite
- **Styling**: Custom CSS với Dark Theme và Glassmorphism effects

## 🚀 Cài Đặt và Chạy

### Yêu Cầu
- Python 3.8+
- Node.js 16+
- MySQL (hoặc SQLite cho development)
- API Keys: VirusTotal, Google Gemini, SMTP email

### Backend Setup

```bash
cd backend
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

Tạo file `.env` trong thư mục `backend/`:

```env
# Database
DATABASE_URL=mysql+pymysql://user:password@host:port/database
# Hoặc sử dụng SQLite
ALLOW_SQLITE_FALLBACK=1

# VirusTotal API
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Gemini AI
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-pro-exp

# JWT Secret
JWT_SECRET_KEY=your_secret_key

# Email SMTP
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
```

Chạy backend:

```bash
python app.py
```

Backend sẽ chạy tại `http://localhost:5001`

### Frontend Setup

```bash
cd frontend
npm install
```

Tạo file `.env` trong thư mục `frontend/`:

```env
VITE_BACKEND_URL=http://localhost:5001
```

Chạy frontend:

```bash
npm run dev
```

Frontend sẽ chạy tại `http://localhost:5173`

## 📁 Cấu Trúc Dự Án

```
KLTN/
├── backend/                 # Flask Backend
│   ├── app.py              # Main application
│   ├── models.py           # Database models
│   ├── database.py         # Database connection
│   ├── auth_utils.py       # JWT management
│   ├── middleware.py       # Rate limiting, IP tracking
│   ├── validators.py       # Input validation
│   ├── email_service.py    # Email sending
│   ├── two_factor_service.py # 2FA support
│   ├── gemini_service.py   # Gemini AI integration
│   └── requirements.txt    # Python dependencies
│
├── frontend/               # React Frontend
│   ├── src/
│   │   ├── components/     # Reusable components
│   │   ├── pages/          # Page components
│   │   ├── utils/          # Utility functions
│   │   └── App.jsx         # Main app & routing
│   └── package.json
│
└── uploads/                # File upload storage
```

## 🔑 Tính Năng Chính

### 1. Phân Tích IOC
- Quét hash (MD5, SHA1, SHA256), domain, IP address, URL
- Tích hợp VirusTotal API với 70+ security engines
- Hiển thị kết quả chi tiết với thống kê phát hiện

### 2. Upload và Phân Tích File
- Upload file lên đến 32MB
- Quét tự động với VirusTotal
- Polling real-time để theo dõi tiến trình
- Tự động phân tích hash sau khi quét xong

### 3. Phân Tích AI (Gemini)
- Phân tích thông minh dựa trên kết quả VirusTotal
- Đánh giá mức độ rủi ro (Low/Medium/High/Critical)
- Đưa ra khuyến nghị bảo mật cụ thể
- Dịch sang tiếng Việt dễ hiểu

### 4. Quản Lý Lịch Sử
- Lưu trữ tất cả lần quét trong database
- Tìm kiếm và lọc theo loại, ngày tháng
- Phân tích lại từ lịch sử

### 5. Community Platform
- Tạo và quản lý bài viết về threat intelligence
- Phân loại theo categories (News, Help, Prevention, etc.)
- Bình luận và thảo luận
- Admin có thể verify bài viết

### 6. Xác Thực và Bảo Mật
- Đăng ký/đăng nhập với email và password
- Xác thực email qua OTP (6 chữ số, hết hạn sau 10 phút)
- JWT token authentication
- Two-Factor Authentication (2FA) với TOTP
- Đổi mật khẩu yêu cầu OTP
- Rate limiting để bảo vệ API
- Role-based access control (admin, analyst, viewer)

### 7. Quản Lý Profile
- Cập nhật thông tin cá nhân
- Thiết lập 2FA
- Xem lịch sử hoạt động

### 8. Admin Panel
- Quản lý người dùng (CRUD)
- Kiểm duyệt bài viết community
- Reset mật khẩu người dùng

## 🔒 Bảo Mật

- **Password Hashing**: bcrypt
- **JWT Tokens**: HS256 algorithm, 1 giờ expiry
- **OTP System**: 6 chữ số, hết hạn sau 10 phút
- **Rate Limiting**: Giới hạn số request/giờ
- **Input Validation**: Kiểm tra và sanitize tất cả input
- **SQL Injection Prevention**: SQLAlchemy ORM với parameterized queries
- **Account Lockout**: Khóa tài khoản sau nhiều lần đăng nhập sai
- **CORS**: Cấu hình cho phép cross-origin requests

## 📊 Database Schema

Hệ thống sử dụng các bảng chính:

- `users`: Thông tin người dùng, roles, 2FA settings
- `user_profiles`: Profile chi tiết người dùng
- `email_otps`: Quản lý OTP gửi qua email
- `scan_requests`: Lưu trữ các yêu cầu quét IOC
- `vt_responses`: Lưu trữ phản hồi từ VirusTotal
- `community_posts`: Bài viết trong cộng đồng
- `community_comments`: Bình luận trên bài viết
- `community_categories`: Danh mục bài viết

## 🌐 API Endpoints

### Authentication
- `POST /api/auth/register` - Đăng ký
- `POST /api/auth/login` - Đăng nhập
- `GET /api/auth/verify-email` - Xác thực email
- `POST /api/auth/2fa/setup` - Thiết lập 2FA

### Analysis
- `POST /api/analyze` - Phân tích hash/domain/IP
- `POST /api/upload-file` - Upload file để quét
- `POST /api/upload-url` - Phân tích URL
- `GET /api/analysis/<id>` - Lấy trạng thái phân tích
- `POST /api/ai/analyze` - Phân tích AI (Gemini)

### User Management
- `GET /api/user/profile` - Lấy profile
- `PUT /api/user/profile` - Cập nhật profile
- `POST /api/user/change-password` - Đổi mật khẩu

### History
- `GET /api/history` - Lấy lịch sử quét
- `DELETE /api/history` - Xóa lịch sử

### Community
- `GET /api/community/posts` - Lấy danh sách bài viết
- `POST /api/community/posts` - Tạo bài viết
- `GET /api/community/posts/<id>` - Chi tiết bài viết
- `POST /api/community/posts/<id>/comments` - Thêm bình luận

## 🎨 Giao Diện

- **Dark Theme**: Giao diện tối đồng nhất
- **Glassmorphism**: Hiệu ứng glass cho cards
- **Responsive**: Tương thích mobile và desktop
- **Loading States**: Progress bars và spinners
- **Error Handling**: Thông báo lỗi thân thiện

## 📝 Ghi Chú

- Database sẽ tự động được khởi tạo khi chạy backend lần đầu
- File upload được lưu tạm thời và tự động xóa sau khi xử lý
- VirusTotal API có rate limits, cần API key hợp lệ
- Gemini AI yêu cầu API key từ Google Cloud

## 👥 Đối Tượng Sử Dụng

- **SOC Teams**: Phân tích nhanh IOC trong incident response
- **Security Analysts**: Nghiên cứu và phân tích malware
- **Threat Intelligence Teams**: Chia sẻ thông tin về threats
- **Ransomware Researchers**: Workflow phân tích ransomware chuyên nghiệp

## 📄 License

[Specify license]

---

**Phiên bản**: 1.0.0  
**Cập nhật**: 2025-11-30

