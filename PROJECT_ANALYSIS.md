# PHÂN TÍCH VÀ TỔNG HỢP DỰ ÁN RANSOMWARE ANALYSIS PORTAL

## 📋 MỤC LỤC

1. [Tổng Quan Dự Án](#1-tổng-quan-dự-án)
2. [Kiến Trúc Hệ Thống](#2-kiến-trúc-hệ-thống)
3. [Luồng Hoạt Động](#3-luồng-hoạt-động)
4. [API Endpoints](#4-api-endpoints)
5. [Database Schema](#5-database-schema)
6. [Bảo Mật](#6-bảo-mật)
7. [Tính Năng Nổi Bật](#7-tính-năng-nổi-bật)
8. [Cấu Hình Môi Trường](#8-cấu-hình-môi-trường)
9. [Kết Luận](#9-kết-luận)

---

## 1. TỔNG QUAN DỰ ÁN

### 1.1. Mục Đích

Hệ thống **Ransomware Analysis Portal** là một nền tảng phân tích ransomware và IOC (Indicators of Compromise) tích hợp với:
- **VirusTotal API**: Quét và phân tích file, URL, domain, IP address
- **Google Gemini AI**: Phân tích thông minh và đưa ra khuyến nghị bảo mật
- **Community Platform**: Chia sẻ threat intelligence giữa các analyst
- **User Management**: Quản lý người dùng với phân quyền và xác thực OTP

### 1.2. Công Nghệ Sử Dụng

#### **Backend:**
- **Framework**: Flask (Python)
- **Database**: MySQL/SQLite (SQLAlchemy ORM)
- **Authentication**: JWT (PyJWT), bcrypt
- **Email Service**: Flask-Mail (OTP, verification)
- **AI Integration**: Google Gemini API
- **External API**: VirusTotal API v3
- **Other**: PyOTP (2FA), QRCode generation

#### **Frontend:**
- **Framework**: React 18.2
- **Routing**: React Router DOM v6
- **UI Library**: React Bootstrap 5.3, Bootstrap Icons
- **HTTP Client**: Axios
- **Build Tool**: Vite
- **Styling**: Custom CSS (Dark Theme, Glassmorphism effects)

---

## 2. KIẾN TRÚC HỆ THỐNG

### 2.1. Cấu Trúc Thư Mục

```
KLTN/
├── backend/                    # Flask Backend
│   ├── app.py                 # Main Flask application (2420+ lines)
│   ├── models.py              # SQLAlchemy database models
│   ├── database.py            # Database connection & initialization
│   ├── auth_utils.py          # JWT token management
│   ├── middleware.py          # Rate limiting, IP tracking
│   ├── validators.py          # Input validation
│   ├── email_service.py       # Email sending (OTP, verification)
│   ├── two_factor_service.py  # 2FA/TOTP support
│   ├── gemini_service.py       # Gemini AI integration
│   └── requirements.txt        # Python dependencies
│
├── frontend/                  # React Frontend
│   ├── src/
│   │   ├── App.jsx            # Main app component & routing
│   │   ├── main.jsx           # React entry point
│   │   ├── components/         # Reusable components
│   │   │   ├── NavBar.jsx
│   │   │   ├── AIAnalysis.jsx
│   │   │   ├── AnalysisResult.jsx
│   │   │   ├── AuthModal.jsx
│   │   │   ├── AuthPage.jsx
│   │   │   ├── FileUpload.jsx
│   │   │   ├── IndicatorForm.jsx
│   │   │   ├── FriendlyAnalysisSummary.jsx
│   │   │   └── SecurityVendorOverview.jsx
│   │   ├── pages/             # Page components
│   │   │   ├── Dashboard.jsx
│   │   │   ├── ScanPage.jsx
│   │   │   ├── HistoryPage.jsx
│   │   │   ├── ProfilePage.jsx
│   │   │   ├── Community.jsx
│   │   │   ├── CommunityPostDetail.jsx
│   │   │   └── RansomwareLanding.jsx
│   │   ├── utils/             # Utility functions
│   │   │   ├── auth.js
│   │   │   ├── analysisSummary.js
│   │   │   └── securityVendors.js
│   │   └── App.css            # Global styles (1955+ lines)
│   └── package.json
│
└── uploads/                   # File upload storage
```

### 2.2. Sơ Đồ Kiến Trúc Tổng Quan

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER INTERFACE                           │
│                    (React Frontend - Vite)                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │Dashboard │  │ ScanPage │  │ History  │  │Community │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │              │             │              │
│       └─────────────┴──────────────┴─────────────┘              │
│                          │                                       │
│                          ▼                                       │
│                   ┌──────────────┐                               │
│                   │   NavBar     │                               │
│                   │  (Routing)   │                               │
│                   └──────┬───────┘                               │
└──────────────────────────┼───────────────────────────────────────┘
                           │
                           │ HTTP/REST API (Axios)
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│                    FLASK BACKEND (Port 5001)                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    API Endpoints                          │   │
│  │  • /api/auth/*          (Login, Register, 2FA)          │   │
│  │  • /api/analyze         (Hash/Domain/IP lookup)          │   │
│  │  • /api/upload-file    (File upload to VT)              │   │
│  │  • /api/upload-url     (URL analysis)                    │   │
│  │  • /api/analysis/<id>  (Poll analysis status)           │   │
│  │  • /api/ai/analyze     (Gemini AI analysis)              │   │
│  │  • /api/history        (Scan history)                     │   │
│  │  • /api/user/*         (Profile, password change)         │   │
│  │  • /api/community/*    (Posts, comments)                 │   │
│  │  • /api/admin/*        (Admin operations)                 │   │
│  └──────────────────────────────────────────────────────────┘   │
│                          │                                        │
│        ┌─────────────────┼─────────────────┐                     │
│        │                 │                 │                     │
│        ▼                 ▼                 ▼                     │
│  ┌──────────┐    ┌──────────────┐   ┌──────────┐               │
│  │ Database │    │  Middleware  │   │ Services │               │
│  │(MySQL/   │    │  • Rate Limit│   │  • Email │               │
│  │ SQLite)  │    │  • Auth Check│   │  • Gemini│               │
│  └──────────┘    └──────────────┘   └────┬─────┘               │
│                                           │                      │
└───────────────────────────────────────────┼──────────────────────┘
                                             │
                    ┌────────────────────────┼────────────────────┐
                    │                        │                    │
                    ▼                        ▼                    ▼
            ┌──────────────┐        ┌──────────────┐   ┌──────────────┐
            │ VirusTotal   │        │  Gemini AI   │   │  Email SMTP  │
            │    API v3    │        │    API       │   │   Server     │
            └──────────────┘        └──────────────┘   └──────────────┘
```

---

## 3. LUỒNG HOẠT ĐỘNG

### 3.1. Luồng Quét IOC (Hash/Domain/IP)

```
User nhập Hash/Domain/IP
         │
         ▼
┌────────────────────┐
│  Dashboard/ScanPage │
│  (Frontend)         │
└─────────┬──────────┘
          │
          │ POST /api/analyze
          │ {value, type, user_email}
          ▼
┌────────────────────┐
│  Backend: app.py    │
│  • Validate input  │
│  • Check auth      │
│  • Rate limit      │
└─────────┬──────────┘
          │
          │ GET VirusTotal API
          │ /v3/{files,urls,domains,ip_addresses}/{id}
          ▼
┌────────────────────┐
│  VirusTotal API    │
│  Returns:          │
│  - stats           │
│  - detections      │
│  - file_info       │
└─────────┬──────────┘
          │
          │ Response
          ▼
┌────────────────────┐
│  Backend:          │
│  • Save to DB      │
│  • Return JSON     │
└─────────┬──────────┘
          │
          │ JSON Response
          ▼
┌────────────────────┐
│  Frontend:         │
│  • Display results │
│  • Save to history │
│  • Show AI analysis│
└────────────────────┘
```

### 3.2. Luồng Upload File

```
User chọn file
         │
         ▼
┌────────────────────┐
│  FileUpload.jsx    │
│  (Frontend)        │
└─────────┬──────────┘
          │
          │ POST /api/upload-file
          │ FormData {file, user_email}
          ▼
┌────────────────────┐
│  Backend: app.py   │
│  • Validate size   │
│  • Hash file       │
│  • Check limit     │
└─────────┬──────────┘
          │
          │ POST VirusTotal API
          │ /v3/files (multipart)
          ▼
┌────────────────────┐
│  VirusTotal API    │
│  Returns:          │
│  analysis_id       │
└─────────┬──────────┘
          │
          │ {analysis_id}
          ▼
┌────────────────────┐
│  Backend:          │
│  • Save scan_req   │
│  • Return id       │
└─────────┬──────────┘
          │
          │ {analysis_id}
          ▼
┌────────────────────┐
│  Frontend:         │
│  • Start polling   │
│  • GET /api/       │
│    analysis/{id}   │
│  • Every 6 seconds│
│  • Max 120 attempts│
└─────────┬──────────┘
          │
          │ Polling (max 120 attempts)
          ▼
┌────────────────────┐
│  Backend:          │
│  GET /api/analysis/│
│  {id}              │
│  • Query VT status  │
└─────────┬──────────┘
          │
          │ Status: queued/running/completed
          ▼
┌────────────────────┐
│  When completed:   │
│  • GET VT result   │
│  • Extract hash    │
│  • Auto-analyze    │
│    hash            │
└────────────────────┘
```

### 3.3. Luồng Phân Tích AI (Gemini)

```
User click "Run AI Analysis"
         │
         ▼
┌────────────────────┐
│  AIAnalysis.jsx    │
│  (Frontend)        │
└─────────┬──────────┘
          │
          │ POST /api/ai/analyze
          │ {vt_data, indicator_type, indicator_value}
          │ + JWT Token
          ▼
┌────────────────────┐
│  Backend: app.py   │
│  • Verify JWT      │
│  • Check rate limit│
│  • Require auth    │
└─────────┬──────────┘
          │
          │ Call gemini_service
          ▼
┌────────────────────┐
│  gemini_service.py │
│  • Build prompt    │
│  • Format VT data  │
│  • Include stats   │
│  • Include detections│
└─────────┬──────────┘
          │
          │ POST Gemini API
          │ /v1beta/models/{model}:generateContent
          │ Model: gemini-2.5-pro-exp
          ▼
┌────────────────────┐
│  Gemini AI API     │
│  Returns:          │
│  - Analysis text   │
│  - Recommendations │
│  - Risk level      │
└─────────┬──────────┘
          │
          │ JSON Response
          ▼
┌────────────────────┐
│  Backend:          │
│  • Parse response  │
│  • Extract content │
│  • Return JSON     │
└─────────┬──────────┘
          │
          │ {analysis, risk_level, recommendations}
          ▼
┌────────────────────┐
│  Frontend:         │
│  • Display AI      │
│    analysis       │
│  • Show risk badge │
│  • Show actions    │
└────────────────────┘
```

### 3.4. Luồng Xác Thực Người Dùng

```
User đăng ký/đăng nhập
         │
         ▼
┌────────────────────┐
│  AuthPage.jsx       │
│  (Frontend)         │
└─────────┬──────────┘
          │
          │ POST /api/auth/register
          │ {email, password, full_name}
          ▼
┌────────────────────┐
│  Backend: app.py    │
│  • Validate input   │
│  • Check duplicate  │
│  • Hash password    │
│  • Generate OTP    │
└─────────┬──────────┘
          │
          │ Send OTP Email
          ▼
┌────────────────────┐
│  email_service.py  │
│  • Generate 6-digit│
│  • Send via SMTP   │
│  • Expiry: 10 min  │
└─────────┬──────────┘
          │
          │ User enters OTP
          ▼
┌────────────────────┐
│  POST /api/auth/   │
│  verify-email      │
│  {email, otp_code} │
└─────────┬──────────┘
          │
          │ Verify OTP
          ▼
┌────────────────────┐
│  Backend:           │
│  • Create user      │
│  • Generate JWT     │
│  • Return token     │
└─────────┬──────────┘
          │
          │ {token, user}
          ▼
┌────────────────────┐
│  Frontend:         │
│  • Save to          │
│    localStorage     │
│  • Set auth state   │
│  • Redirect to /    │
└────────────────────┘
```

### 3.5. Luồng Đổi Mật Khẩu (OTP)

```
User click "Change Password"
         │
         ▼
┌────────────────────┐
│  ProfilePage.jsx   │
│  (Frontend)        │
└─────────┬──────────┘
          │
          │ POST /api/user/change-password/request-otp
          │ + JWT Token
          ▼
┌────────────────────┐
│  Backend: app.py    │
│  • Verify JWT       │
│  • Get user email  │
│  • Generate OTP    │
│  • Delete old OTP   │
│  • Create new OTP   │
│  • Update if exists │
└─────────┬──────────┘
          │
          │ Send OTP Email
          ▼
┌────────────────────┐
│  email_service.py  │
│  • Send 6-digit OTP│
│    (purpose:       │
│     change_password)│
└─────────┬──────────┘
          │
          │ User enters OTP + new password
          ▼
┌────────────────────┐
│  POST /api/user/   │
│  change-password   │
│  {otp_code,        │
│   newPassword}     │
└─────────┬──────────┘
          │
          │ Verify OTP
          ▼
┌────────────────────┐
│  Backend:           │
│  • Verify OTP       │
│  • Check expiry     │
│  • Validate password│
│  • Hash new password│
│  • Update user      │
│  • Delete OTP       │
└─────────┬──────────┘
          │
          │ Success
          ▼
┌────────────────────┐
│  Frontend:         │
│  • Show success msg │
│  • Close modal     │
└────────────────────┘
```

### 3.6. Luồng Community Post

```
User tạo bài viết
         │
         ▼
┌────────────────────┐
│  Community.jsx     │
│  (Frontend)        │
└─────────┬──────────┘
          │
          │ POST /api/community/posts
          │ {title, content, category, tags}
          │ + JWT Token
          ▼
┌────────────────────┐
│  Backend: app.py    │
│  • Verify JWT       │
│  • Validate input  │
│  • Sanitize content │
└─────────┬──────────┘
          │
          │ Save to database
          ▼
┌────────────────────┐
│  Database:         │
│  • Create post      │
│  • Status: draft   │
│  • Set author info │
└─────────┬──────────┘
          │
          │ Return post
          ▼
┌────────────────────┐
│  Frontend:         │
│  • Show success     │
│  • Refresh list     │
└────────────────────┘
          │
          │ Admin verify (optional)
          ▼
┌────────────────────┐
│  POST /api/admin/  │
│  posts/{id}/verify │
│  • Set verified    │
└────────────────────┘
```

---

## 4. API ENDPOINTS

### 4.1. Authentication APIs

| Method | Endpoint | Mô Tả | Auth Required |
|--------|----------|-------|---------------|
| POST | `/api/auth/register` | Đăng ký tài khoản mới | ❌ |
| GET | `/api/auth/verify-email` | Xác thực email với OTP | ❌ |
| POST | `/api/auth/resend-verification` | Gửi lại email xác thực | ❌ |
| POST | `/api/auth/login` | Đăng nhập | ❌ |
| POST | `/api/auth/2fa/setup` | Thiết lập 2FA | ✅ |
| POST | `/api/auth/2fa/verify-setup` | Xác thực thiết lập 2FA | ✅ |
| POST | `/api/auth/2fa/disable` | Tắt 2FA | ✅ |
| POST | `/api/auth/forgot-password` | Quên mật khẩu | ❌ |
| POST | `/api/auth/reset-password` | Đặt lại mật khẩu | ❌ |

### 4.2. Analysis APIs

| Method | Endpoint | Mô Tả | Auth Required |
|--------|----------|-------|---------------|
| POST | `/api/analyze` | Phân tích hash/domain/IP | ✅ |
| POST | `/api/upload-file` | Upload file để quét | ✅ |
| POST | `/api/upload-url` | Phân tích URL | ✅ |
| GET | `/api/analysis/<id>` | Lấy trạng thái phân tích | ✅ |
| POST | `/api/ai/analyze` | Phân tích AI (Gemini) | ✅ |

### 4.3. User Management APIs

| Method | Endpoint | Mô Tả | Auth Required |
|--------|----------|-------|---------------|
| GET | `/api/user/profile` | Lấy thông tin profile | ✅ |
| PUT | `/api/user/profile` | Cập nhật profile | ✅ |
| POST | `/api/user/change-password/request-otp` | Yêu cầu OTP đổi mật khẩu | ✅ |
| POST | `/api/user/change-password` | Đổi mật khẩu với OTP | ✅ |

### 4.4. History APIs

| Method | Endpoint | Mô Tả | Auth Required |
|--------|----------|-------|---------------|
| GET | `/api/history` | Lấy lịch sử quét | ✅ |
| DELETE | `/api/history` | Xóa lịch sử | ✅ |

### 4.5. Community APIs

| Method | Endpoint | Mô Tả | Auth Required |
|--------|----------|-------|---------------|
| GET | `/api/community/categories` | Lấy danh sách categories | ❌ |
| GET | `/api/community/posts` | Lấy danh sách bài viết | ❌ |
| POST | `/api/community/posts` | Tạo bài viết mới | ✅ |
| GET | `/api/community/posts/<id>` | Lấy chi tiết bài viết | ❌ |
| POST | `/api/community/posts/<id>/comments` | Thêm bình luận | ✅ |

### 4.6. Admin APIs

| Method | Endpoint | Mô Tả | Auth Required | Role |
|--------|----------|-------|---------------|------|
| GET | `/api/admin/users` | Quản lý người dùng | ✅ | admin |
| POST | `/api/admin/users` | Tạo người dùng mới | ✅ | admin |
| PUT | `/api/admin/users/<id>` | Cập nhật người dùng | ✅ | admin |
| DELETE | `/api/admin/users/<id>` | Xóa người dùng | ✅ | admin |
| POST | `/api/admin/users/<id>/reset-password` | Reset mật khẩu | ✅ | admin |
| GET | `/api/admin/posts` | Quản lý bài viết | ✅ | admin |
| POST | `/api/admin/posts` | Tạo bài viết | ✅ | admin |
| PUT | `/api/admin/posts/<id>` | Cập nhật bài viết | ✅ | admin |
| DELETE | `/api/admin/posts/<id>` | Xóa bài viết | ✅ | admin |
| POST | `/api/admin/posts/<id>/verify` | Xác thực bài viết | ✅ | admin |

---

## 5. DATABASE SCHEMA

### 5.1. Bảng `users`

Quản lý thông tin người dùng hệ thống.

| Cột | Kiểu | Mô Tả |
|-----|------|-------|
| `id` | BigInteger | Primary key, auto increment |
| `email` | String(191) | Email (unique) |
| `password_hash` | String(255) | Mật khẩu đã hash (bcrypt) |
| `full_name` | String(191) | Tên đầy đủ |
| `role` | Enum | Vai trò: admin, analyst, viewer |
| `is_active` | SmallInteger | Trạng thái hoạt động (1/0) |
| `last_login_at` | DateTime | Thời gian đăng nhập cuối |
| `two_factor_enabled` | Boolean | Bật 2FA |
| `two_factor_secret` | String(32) | Secret key cho TOTP |
| `two_factor_backup_codes` | JSON | Backup codes |
| `failed_login_attempts` | Integer | Số lần đăng nhập sai |
| `locked_until` | DateTime | Khóa tài khoản đến khi |
| `created_at` | DateTime | Thời gian tạo |
| `updated_at` | DateTime | Thời gian cập nhật |

**Relationships:**
- `profile`: One-to-one với `UserProfile`
- `scans`: One-to-many với `ScanRequest`

### 5.2. Bảng `user_profiles`

Thông tin chi tiết profile người dùng.

| Cột | Kiểu | Mô Tả |
|-----|------|-------|
| `user_id` | BigInteger | Foreign key → users.id (primary key) |
| `display_name` | String(191) | Tên hiển thị |
| `organization` | String(191) | Tổ chức |
| `job_title` | String(191) | Chức danh |
| `phone_number` | String(50) | Số điện thoại |
| `bio` | Text | Tiểu sử |
| `language` | String(10) | Ngôn ngữ (vi/en) |
| `theme` | Enum | Giao diện: dark, light, system |
| `created_at` | DateTime | Thời gian tạo |
| `updated_at` | DateTime | Thời gian cập nhật |

### 5.3. Bảng `email_otps`

Quản lý OTP gửi qua email.

| Cột | Kiểu | Mô Tả |
|-----|------|-------|
| `id` | BigInteger | Primary key |
| `email` | String(191) | Email (unique) |
| `full_name` | String(191) | Tên (cho register) |
| `password_hash` | String(255) | Hash mật khẩu (cho register) |
| `otp_code` | String(6) | Mã OTP 6 chữ số |
| `expires_at` | DateTime | Thời gian hết hạn |
| `purpose` | String(32) | Mục đích: register, change_password |
| `created_at` | DateTime | Thời gian tạo |

### 5.4. Bảng `scan_requests`

Lưu trữ các yêu cầu quét IOC.

| Cột | Kiểu | Mô Tả |
|-----|------|-------|
| `id` | BigInteger | Primary key |
| `user_id` | BigInteger | Foreign key → users.id |
| `api_client_id` | BigInteger | Foreign key → api_clients.id |
| `indicator_type` | Enum | Loại: file, url, domain, ip_address |
| `indicator_value` | String(512) | Giá trị IOC |
| `display_value` | String(512) | Giá trị hiển thị |
| `vt_analysis_id` | String(128) | ID phân tích từ VirusTotal (unique) |
| `status` | Enum | Trạng thái: queued, running, completed, error, timeout |
| `summary` | Text | Tóm tắt kết quả |
| `malicious` | SmallInteger | Số engine phát hiện malicious |
| `suspicious` | SmallInteger | Số engine phát hiện suspicious |
| `harmless` | SmallInteger | Số engine phát hiện harmless |
| `undetected` | SmallInteger | Số engine không phát hiện |
| `error_message` | Text | Thông báo lỗi |
| `created_at` | DateTime | Thời gian tạo |
| `completed_at` | DateTime | Thời gian hoàn thành |

**Relationships:**
- `user`: Many-to-one với `User`
- `vt_responses`: One-to-many với `VTResponse`
- `tags`: One-to-many với `ScanTag`
- `comments`: One-to-many với `AnalystComment`

### 5.5. Bảng `vt_responses`

Lưu trữ phản hồi thô từ VirusTotal.

| Cột | Kiểu | Mô Tả |
|-----|------|-------|
| `id` | BigInteger | Primary key |
| `scan_id` | BigInteger | Foreign key → scan_requests.id |
| `vt_status` | String(64) | Trạng thái từ VT |
| `raw_payload` | JSON | Dữ liệu thô từ API |
| `received_at` | DateTime | Thời gian nhận |

### 5.6. Bảng `community_posts`

Quản lý bài viết trong cộng đồng.

| Cột | Kiểu | Mô Tả |
|-----|------|-------|
| `id` | BigInteger | Primary key |
| `user_id` | BigInteger | Foreign key → users.id |
| `author_email` | String(191) | Email tác giả |
| `author_name` | String(191) | Tên tác giả |
| `title` | String(255) | Tiêu đề |
| `summary` | String(512) | Tóm tắt |
| `content` | Text | Nội dung |
| `category` | String(64) | Danh mục |
| `tags` | JSON | Tags (array) |
| `status` | Enum | Trạng thái: draft, published, archived |
| `is_featured` | SmallInteger | Bài viết nổi bật (1/0) |
| `views` | Integer | Số lượt xem |
| `comments_count` | Integer | Số bình luận |
| `created_at` | DateTime | Thời gian tạo |
| `updated_at` | DateTime | Thời gian cập nhật |

### 5.7. Bảng `community_comments`

Quản lý bình luận trên bài viết.

| Cột | Kiểu | Mô Tả |
|-----|------|-------|
| `id` | BigInteger | Primary key |
| `post_id` | BigInteger | Foreign key → community_posts.id |
| `user_id` | BigInteger | Foreign key → users.id |
| `author_email` | String(191) | Email tác giả |
| `author_name` | String(191) | Tên tác giả |
| `content` | Text | Nội dung bình luận |
| `created_at` | DateTime | Thời gian tạo |

### 5.8. Bảng `community_categories`

Danh mục bài viết cộng đồng.

| Cột | Kiểu | Mô Tả |
|-----|------|-------|
| `id` | BigInteger | Primary key |
| `slug` | String(128) | Slug (unique) |
| `name` | String(191) | Tên danh mục |
| `description` | Text | Mô tả |
| `display_order` | Integer | Thứ tự hiển thị |
| `is_active` | Boolean | Trạng thái hoạt động |
| `created_at` | DateTime | Thời gian tạo |
| `updated_at` | DateTime | Thời gian cập nhật |

**Default Categories:**
- `news-alerts`: News & Alerts
- `help-and-decrypt`: Help & Decrypt
- `prevention-tips`: Prevention Tips
- `incident-reports`: Incident Reports
- `tools-and-scanners`: Tools & Scanners

---

## 6. BẢO MẬT

### 6.1. Authentication & Authorization

#### **JWT Tokens:**
- **Algorithm**: HS256
- **Expiry**: 1 giờ
- **Storage**: Frontend localStorage (`vt-auth-token`)
- **Refresh**: User phải đăng nhập lại khi token hết hạn

#### **Password Security:**
- **Hashing**: bcrypt
- **Validation**: Minimum 8 characters, complexity requirements
- **Change Password**: Yêu cầu OTP qua email

#### **Role-Based Access Control (RBAC):**
- **admin**: Toàn quyền quản lý hệ thống
- **analyst**: Phân tích và quét IOC
- **viewer**: Chỉ xem kết quả

#### **Account Protection:**
- **Rate Limiting**: Giới hạn số request/giờ
- **Failed Login Tracking**: Theo dõi số lần đăng nhập sai
- **Account Lockout**: Khóa tài khoản sau nhiều lần sai
- **IP Tracking**: Ghi nhận IP đăng nhập

### 6.2. Email Verification

#### **OTP System:**
- **Length**: 6 chữ số
- **Expiry**: 10 phút
- **Purpose**: 
  - `register`: Xác thực đăng ký
  - `change_password`: Đổi mật khẩu
- **Storage**: Bảng `email_otps` (unique per email)
- **Cleanup**: Tự động xóa sau khi sử dụng hoặc hết hạn

### 6.3. Input Validation

#### **Indicators:**
- **Hash**: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)
- **Domain**: Valid domain format
- **IP Address**: IPv4/IPv6 format
- **URL**: Valid URL format

#### **File Upload:**
- **Size Limit**: 32 MB (VirusTotal API limit)
- **Type Validation**: Kiểm tra MIME type
- **Filename Sanitization**: Loại bỏ ký tự nguy hiểm

#### **SQL Injection Prevention:**
- **ORM**: SQLAlchemy (parameterized queries)
- **No Raw SQL**: Tất cả queries qua ORM

### 6.4. API Security

#### **CORS:**
- **Configuration**: Cho phép tất cả origins (development)
- **Production**: Nên giới hạn origins cụ thể

#### **Rate Limiting:**
- **Middleware**: `@rate_limit` decorator
- **Default**: 60 requests/phút
- **IP-based**: Theo địa chỉ IP

#### **Error Handling:**
- **No Sensitive Data**: Không trả về thông tin nhạy cảm trong error messages
- **Logging**: Ghi log tất cả errors để debug

---

## 7. TÍNH NĂNG NỔI BẬT

### 7.1. Phân Tích Đa Lớp

#### **VirusTotal Integration:**
- **70+ Security Engines**: Quét với nhiều engine cùng lúc
- **Real-time Analysis**: Kết quả cập nhật real-time
- **File Analysis**: Upload và phân tích file
- **URL Analysis**: Phân tích URL độc hại
- **Domain/IP Analysis**: Phân tích domain và IP address

#### **Gemini AI Analysis:**
- **Intelligent Analysis**: Phân tích thông minh dựa trên kết quả VirusTotal
- **Risk Assessment**: Đánh giá mức độ nguy hiểm
- **Recommendations**: Đưa ra khuyến nghị bảo mật
- **Human-readable**: Dịch sang tiếng Việt dễ hiểu

### 7.2. Quản Lý Lịch Sử

- **Persistent Storage**: Lưu trữ lịch sử quét trong database
- **Search & Filter**: Tìm kiếm và lọc theo type, date
- **Re-analysis**: Phân tích lại từ lịch sử
- **Export**: Có thể export dữ liệu (future feature)

### 7.3. Community Platform

- **Post Management**: Tạo, chỉnh sửa, xóa bài viết
- **Categories**: Phân loại bài viết theo categories
- **Tags**: Gắn tags cho bài viết
- **Comments**: Bình luận và thảo luận
- **Verification**: Admin có thể verify bài viết
- **Views Tracking**: Theo dõi số lượt xem

### 7.4. User Experience

#### **Dark Theme:**
- **Consistent Design**: Giao diện tối đồng nhất
- **Glassmorphism**: Hiệu ứng glass cho cards
- **Aurora Effects**: Hiệu ứng ánh sáng nền
- **Responsive**: Tương thích mobile và desktop

#### **Loading States:**
- **Progress Bars**: Hiển thị tiến trình quét
- **Spinners**: Loading indicators
- **Skeleton Screens**: Placeholder khi load

#### **Error Handling:**
- **User-friendly Messages**: Thông báo lỗi dễ hiểu
- **Retry Mechanisms**: Cho phép thử lại
- **Fallback UI**: Giao diện dự phòng khi lỗi

### 7.5. Admin Features

- **User Management**: Quản lý người dùng (CRUD)
- **Post Moderation**: Kiểm duyệt bài viết
- **System Monitoring**: Theo dõi hệ thống (future)
- **Analytics**: Thống kê sử dụng (future)

---

## 8. CẤU HÌNH MÔI TRƯỜNG

### 8.1. Backend Environment Variables (.env)

```env
# Database Configuration
DATABASE_URL=mysql+pymysql://user:password@host:port/database
# OR
DB_DRIVER=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=ransomware_portal
ALLOW_SQLITE_FALLBACK=1

# VirusTotal API
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Gemini AI Configuration
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-pro-exp
GEMINI_ENDPOINT=https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent

# JWT Secret
JWT_SECRET_KEY=your_secret_key_change_in_production

# Email Configuration (SMTP)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password

# Community Moderation
COMMUNITY_MODERATOR_TOKEN=your_moderator_token

# Logging
LOG_LEVEL=INFO

# Rate Limiting
RATE_LIMIT_REQUESTS=60
RATE_LIMIT_WINDOW=3600
```

### 8.2. Frontend Environment Variables (.env)

```env
# Backend API URL
VITE_BACKEND_URL=http://localhost:5001
```

### 8.3. Installation & Setup

#### **Backend Setup:**

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env với thông tin của bạn
python app.py
```

#### **Frontend Setup:**

```bash
cd frontend
npm install
cp .env.example .env
# Edit .env với VITE_BACKEND_URL
npm run dev
```

### 8.4. Database Initialization

Database sẽ tự động được khởi tạo khi chạy backend lần đầu. SQLAlchemy sẽ tạo các bảng dựa trên models.

```python
# Tự động chạy trong app.py
init_database()
ensure_default_community_categories()
```

---

## 9. KẾT LUẬN

### 9.1. Tổng Kết

Dự án **Ransomware Analysis Portal** là một hệ thống hoàn chỉnh tích hợp:

✅ **VirusTotal API** - Quét và phân tích IOC với 70+ security engines  
✅ **Google Gemini AI** - Phân tích thông minh và đưa ra khuyến nghị  
✅ **User Management** - Quản lý người dùng với JWT, OTP, 2FA  
✅ **Community Platform** - Chia sẻ threat intelligence  
✅ **Modern UI/UX** - Dark theme, glassmorphism, responsive  

### 9.2. Kiến Trúc

- **Frontend**: React SPA với React Router
- **Backend**: Flask REST API
- **Database**: MySQL/SQLite với SQLAlchemy ORM
- **External Services**: VirusTotal, Gemini AI, SMTP

### 9.3. Ứng Dụng Thực Tế

Hệ thống phù hợp cho:

- **SOC Teams**: Phân tích nhanh IOC trong incident response
- **Security Analysts**: Nghiên cứu và phân tích malware
- **Threat Intelligence Sharing**: Chia sẻ thông tin về threats
- **Ransomware Analysis**: Workflow phân tích ransomware chuyên nghiệp

### 9.4. Hướng Phát Triển

- [ ] Export reports (PDF, CSV)
- [ ] Real-time notifications
- [ ] Advanced analytics dashboard
- [ ] API key management cho external integrations
- [ ] Webhook support
- [ ] Multi-language support (i18n)
- [ ] Mobile app (React Native)

---

## 📝 GHI CHÚ

- File này được tạo tự động từ phân tích codebase
- Cập nhật lần cuối: 2025-11-30
- Phiên bản: 1.0.0

---

**Tác giả**: System Analysis  
**Dự án**: Ransomware Analysis Portal  
**License**: [Specify license]













