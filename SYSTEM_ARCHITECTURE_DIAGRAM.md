# SYSTEM ARCHITECTURE DIAGRAMS
## Ransomware Analysis Portal

Tài liệu này chứa các sơ đồ kiến trúc hệ thống được tạo bằng Mermaid. Bạn có thể xem các diagram này trong:
- GitHub (tự động render)
- VS Code với extension Mermaid Preview
- Mermaid Live Editor: https://mermaid.live
- Các công cụ hỗ trợ Mermaid khác

---

## 1. OVERALL SYSTEM ARCHITECTURE

Sơ đồ tổng quan về kiến trúc hệ thống với 6 lớp chính.

```mermaid
graph TB
    subgraph "Client Layer"
        Browser[Web Browser<br/>Chrome/Firefox/Edge]
    end
    
    subgraph "Frontend Layer"
        React[React SPA<br/>Vite + React Router]
        Pages[Pages<br/>Dashboard/Scan/History/Profile/Community]
        Components[Components<br/>NavBar/AIAnalysis/AnalysisResult]
    end
    
    subgraph "API Gateway"
        CORS[CORS Middleware]
        RateLimit[Rate Limiting<br/>60 req/min]
    end
    
    subgraph "Backend Layer"
        Flask[Flask Application]
        Auth[Authentication<br/>JWT + OTP]
        API[REST API Endpoints]
        Security[Security Middleware]
        Services[Services<br/>Email/Gemini/Validator]
    end
    
    subgraph "Data Layer"
        DB[(MySQL/SQLite<br/>SQLAlchemy ORM)]
        Models[Models<br/>User/ScanRequest/CommunityPost/EmailOtp]
    end
    
    subgraph "External Services"
        VT[VirusTotal API v3<br/>70+ Security Engines]
        Gemini[Google Gemini AI<br/>gemini-2.5-pro-exp]
        SMTP[SMTP Server<br/>Email OTP]
    end
    
    Browser -->|HTTP/HTTPS| React
    React --> Pages
    Pages --> Components
    Components -->|API Calls| CORS
    CORS --> RateLimit
    RateLimit --> Flask
    Flask --> Auth
    Flask --> API
    Flask --> Security
    Flask --> Services
    Services --> DB
    Services --> Models
    Services -->|API Calls| VT
    Services -->|API Calls| Gemini
    Services -->|SMTP| SMTP
    Models --> DB
    
    style Browser fill:#e1f5ff
    style React fill:#c8e6ff
    style Flask fill:#90caf9
    style DB fill:#64b5f6
    style VT fill:#42a5f5
    style Gemini fill:#42a5f5
    style SMTP fill:#42a5f5
```

---

## 2. DETAILED COMPONENT ARCHITECTURE

Sơ đồ chi tiết về các component và tương tác giữa chúng.

```mermaid
graph LR
    subgraph "Frontend Components"
        A[App.jsx<br/>Main Router]
        B[Dashboard.jsx]
        C[ScanPage.jsx]
        D[HistoryPage.jsx]
        E[ProfilePage.jsx]
        F[Community.jsx]
        G[AuthPage.jsx]
        
        A --> B
        A --> C
        A --> D
        A --> E
        A --> F
        A --> G
    end
    
    subgraph "Backend Services"
        H[app.py<br/>Flask Routes]
        I[auth_utils.py<br/>JWT Management]
        J[email_service.py<br/>OTP Emails]
        K[gemini_service.py<br/>AI Analysis]
        L[validators.py<br/>Input Validation]
        M[middleware.py<br/>Rate Limiting]
        
        H --> I
        H --> J
        H --> K
        H --> L
        H --> M
    end
    
    subgraph "Database Models"
        N[User Model]
        O[ScanRequest Model]
        P[CommunityPost Model]
        Q[EmailOtp Model]
        R[UserProfile Model]
    end
    
    B -->|API Calls| H
    C -->|API Calls| H
    D -->|API Calls| H
    E -->|API Calls| H
    F -->|API Calls| H
    G -->|API Calls| H
    
    H --> N
    H --> O
    H --> P
    H --> Q
    H --> R
    
    style A fill:#c8e6ff
    style H fill:#90caf9
    style N fill:#64b5f6
    style O fill:#64b5f6
    style P fill:#64b5f6
```

---

## 3. DATA FLOW DIAGRAM

Sơ đồ luồng dữ liệu từ người dùng đến các dịch vụ bên ngoài.

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant Backend
    participant Database
    participant VirusTotal
    participant Gemini
    participant SMTP
    
    User->>Frontend: Upload File/Enter IOC
    Frontend->>Backend: POST /api/upload-file or /api/analyze
    Backend->>Backend: Validate Input & Authenticate
    Backend->>Database: Save Scan Request
    Backend->>VirusTotal: Submit for Analysis
    VirusTotal-->>Backend: Return analysis_id
    Backend-->>Frontend: Return analysis_id
    Frontend->>Backend: Poll /api/analysis/{id}
    Backend->>VirusTotal: Get Analysis Results
    VirusTotal-->>Backend: Return Results
    Backend->>Database: Update Scan Request
    Backend->>Gemini: Request AI Analysis
    Gemini-->>Backend: Return AI Analysis
    Backend-->>Frontend: Return Complete Results
    Frontend-->>User: Display Results
    
    Note over User,SMTP: Registration/Login Flow
    User->>Frontend: Register/Login
    Frontend->>Backend: POST /api/auth/register or /login
    Backend->>Database: Check/Create User
    Backend->>SMTP: Send OTP Email
    SMTP-->>User: OTP Code
    User->>Frontend: Enter OTP
    Frontend->>Backend: POST with OTP
    Backend->>Database: Verify & Create User
    Backend-->>Frontend: Return JWT Token
```

---

## 4. SECURITY ARCHITECTURE

Sơ đồ về các lớp bảo mật và xác thực.

```mermaid
graph TB
    subgraph "Authentication Flow"
        A[User Request] -->|1. Login| B[Auth Endpoint]
        B -->|2. Verify Credentials| C[Database]
        C -->|3. Check Password| D{Valid?}
        D -->|Yes| E[Generate JWT]
        D -->|No| F[Return 401]
        E -->|4. Send OTP| G[Email Service]
        G -->|5. Email OTP| H[User Email]
        H -->|6. Enter OTP| I[Verify OTP]
        I -->|7. Valid OTP| J[Return JWT Token]
        I -->|8. Invalid OTP| F
    end
    
    subgraph "Authorization Flow"
        K[API Request] -->|1. Include JWT| L[Security Middleware]
        L -->|2. Verify Token| M{Token Valid?}
        M -->|No| N[Return 401]
        M -->|Yes| O[Extract User Info]
        O -->|3. Check Role| P{Role Allowed?}
        P -->|No| Q[Return 403]
        P -->|Yes| R[Process Request]
    end
    
    subgraph "Security Layers"
        S[Rate Limiting<br/>60 req/min]
        T[CORS Protection]
        U[Input Validation]
        V[SQL Injection Prevention<br/>SQLAlchemy ORM]
        W[Password Hashing<br/>bcrypt]
        X[CAPTCHA Verification<br/>reCAPTCHA v2]
    end
    
    style E fill:#4caf50
    style J fill:#4caf50
    style F fill:#f44336
    style N fill:#f44336
    style Q fill:#f44336
```

---

## 5. DATABASE SCHEMA RELATIONSHIP

Sơ đồ quan hệ giữa các bảng trong database.

```mermaid
erDiagram
    User ||--o{ ScanRequest : "has many"
    User ||--|| UserProfile : "has one"
    User ||--o{ EmailOtp : "has many"
    User ||--o{ CommunityPost : "creates"
    User ||--o{ CommunityComment : "comments"
    CommunityPost ||--o{ CommunityComment : "has many"
    CommunityPost }o--|| CommunityCategory : "belongs to"
    
    User {
        int id PK
        string email UK
        string full_name
        string password_hash
        string role
        int is_active
        datetime created_at
    }
    
    UserProfile {
        int id PK
        int user_id FK
        string display_name
        string organization
        string bio
        datetime updated_at
    }
    
    ScanRequest {
        int id PK
        int user_id FK
        string indicator_type
        string indicator_value
        string display_value
        string vt_analysis_id
        json vt_response
        string status
        datetime created_at
        datetime updated_at
    }
    
    EmailOtp {
        int id PK
        string email
        string otp_code
        string password_hash
        string full_name
        datetime expires_at
        string purpose
    }
    
    CommunityPost {
        int id PK
        int author_id FK
        int category_id FK
        string title
        text content
        string tags
        string contact_email
        int is_verified
        int views_count
        datetime created_at
        datetime updated_at
    }
    
    CommunityComment {
        int id PK
        int post_id FK
        int author_id FK
        text content
        datetime created_at
    }
    
    CommunityCategory {
        int id PK
        string name
        string description
    }
```

---

## 6. DEPLOYMENT ARCHITECTURE

Sơ đồ triển khai hệ thống.

```mermaid
graph TB
    subgraph "Production Environment"
        subgraph "Load Balancer"
            LB[Nginx/HAProxy]
        end
        
        subgraph "Application Servers"
            App1[Flask App 1<br/>Port 5001]
            App2[Flask App 2<br/>Port 5001]
        end
        
        subgraph "Frontend Servers"
            Frontend1[React Build<br/>Nginx]
            Frontend2[React Build<br/>Nginx]
        end
        
        subgraph "Database Cluster"
            DB1[(MySQL Primary)]
            DB2[(MySQL Replica)]
        end
        
        subgraph "External Services"
            VT[VirusTotal API]
            Gemini[Gemini API]
            SMTP[SMTP Server]
        end
    end
    
    Internet --> LB
    LB --> App1
    LB --> App2
    LB --> Frontend1
    LB --> Frontend2
    App1 --> DB1
    App2 --> DB1
    DB1 -->|Replication| DB2
    App1 --> VT
    App1 --> Gemini
    App1 --> SMTP
    App2 --> VT
    App2 --> Gemini
    App2 --> SMTP
    
    style LB fill:#ff9800
    style App1 fill:#2196f3
    style App2 fill:#2196f3
    style DB1 fill:#4caf50
    style DB2 fill:#4caf50
```

---

## 7. API ENDPOINTS ARCHITECTURE

Sơ đồ các API endpoints và nhóm chức năng.

```mermaid
graph LR
    subgraph "Authentication APIs"
        A1[POST /api/auth/register]
        A2[POST /api/auth/login]
        A3[POST /api/auth/logout]
        A4[POST /api/auth/forgot-password]
        A5[POST /api/auth/reset-password]
        A6[POST /api/auth/verify-email]
    end
    
    subgraph "Analysis APIs"
        B1[POST /api/analyze]
        B2[POST /api/upload-file]
        B3[POST /api/upload-url]
        B4[GET /api/analysis/:id]
        B5[POST /api/ai/analyze]
    end
    
    subgraph "User Management APIs"
        C1[GET /api/user/profile]
        C2[PUT /api/user/profile]
        C3[POST /api/user/change-password/request-otp]
        C4[POST /api/user/change-password]
    end
    
    subgraph "History APIs"
        D1[GET /api/history]
        D2[DELETE /api/history/:id]
    end
    
    subgraph "Community APIs"
        E1[GET /api/community/posts]
        E2[POST /api/community/posts]
        E3[GET /api/community/posts/:id]
        E4[PUT /api/community/posts/:id]
        E5[DELETE /api/community/posts/:id]
        E6[POST /api/community/posts/:id/comments]
    end
    
    subgraph "Admin APIs"
        F1[GET /api/admin/users]
        F2[POST /api/admin/users]
        F3[PUT /api/admin/users/:id]
        F4[DELETE /api/admin/users/:id]
    end
    
    style A1 fill:#e3f2fd
    style A2 fill:#e3f2fd
    style B1 fill:#f3e5f5
    style B2 fill:#f3e5f5
    style C1 fill:#e8f5e9
    style E1 fill:#fff3e0
    style F1 fill:#fce4ec
```

---

## 8. SIMPLIFIED SYSTEM OVERVIEW

Sơ đồ đơn giản hóa về hệ thống.

```mermaid
graph TB
    User[👤 User] -->|1. Request| Frontend[🖥️ React Frontend<br/>localhost:5173]
    Frontend -->|2. API Call| Backend[⚙️ Flask Backend<br/>localhost:5001]
    Backend -->|3. Query| Database[(💾 MySQL/SQLite)]
    Backend -->|4. Analyze| VirusTotal[🔍 VirusTotal API<br/>70+ Engines]
    Backend -->|5. AI Analysis| Gemini[🤖 Google Gemini AI]
    Backend -->|6. Send OTP| SMTP[📧 SMTP Server]
    Backend -->|7. Response| Frontend
    Frontend -->|8. Display| User
    
    style User fill:#e1f5ff
    style Frontend fill:#c8e6ff
    style Backend fill:#90caf9
    style Database fill:#64b5f6
    style VirusTotal fill:#42a5f5
    style Gemini fill:#42a5f5
    style SMTP fill:#42a5f5
```

---

## 9. USER REGISTRATION & AUTHENTICATION FLOW

Sơ đồ chi tiết về luồng đăng ký và xác thực người dùng.

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant Backend
    participant Database
    participant CAPTCHA
    participant SMTP
    
    Note over User,SMTP: Registration Flow with CAPTCHA
    User->>Frontend: Fill Registration Form
    Frontend->>CAPTCHA: Load reCAPTCHA Widget
    CAPTCHA-->>Frontend: Display CAPTCHA
    User->>CAPTCHA: Verify "I'm not a robot"
    CAPTCHA-->>Frontend: Return CAPTCHA Token
    User->>Frontend: Submit Form (with CAPTCHA token)
    Frontend->>Backend: POST /api/auth/register<br/>(email, password, fullName, captcha_token)
    Backend->>CAPTCHA: Verify CAPTCHA Token
    CAPTCHA-->>Backend: Verification Result
    alt CAPTCHA Invalid
        Backend-->>Frontend: 400 - CAPTCHA verification failed
    else CAPTCHA Valid
        Backend->>Database: Check if email exists
        Database-->>Backend: Email not found
        Backend->>Backend: Hash Password
        Backend->>Backend: Generate 6-digit OTP
        Backend->>Database: Save EmailOtp (pending)
        Backend->>SMTP: Send OTP Email
        SMTP-->>User: OTP Code via Email
        Backend-->>Frontend: 202 - OTP sent
        Frontend-->>User: Display OTP Input
        User->>Frontend: Enter OTP
        Frontend->>Backend: POST /api/auth/register<br/>(email, password, fullName, otp)
        Backend->>Database: Verify OTP
        Database-->>Backend: OTP Valid
        Backend->>Database: Create User & UserProfile
        Database-->>Backend: User Created
        Backend-->>Frontend: 201 - Registration successful
        Frontend-->>User: Redirect to Login
    end
    
    Note over User,SMTP: Login Flow
    User->>Frontend: Enter Email & Password
    Frontend->>Backend: POST /api/auth/login
    Backend->>Database: Verify Credentials
    Database-->>Backend: Password Correct
    Backend->>Backend: Generate JWT Token
    Backend-->>Frontend: Return JWT Token
    Frontend->>Frontend: Store Token in localStorage
    Frontend-->>User: Redirect to Dashboard
```

---

## 10. FILE UPLOAD & ANALYSIS FLOW

Sơ đồ chi tiết về luồng upload file và phân tích.

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant Backend
    participant Database
    participant VirusTotal
    participant Gemini
    
    User->>Frontend: Upload File
    Frontend->>Frontend: Create FormData
    Frontend->>Backend: POST /api/upload-file<br/>(file, user_email, Authorization header)
    Backend->>Backend: Verify JWT Token
    Backend->>Backend: Check User Role (block admin)
    Backend->>Backend: Validate File Size
    Backend->>Backend: Calculate SHA256 Hash
    Backend->>Database: Save Pending ScanRequest
    Backend->>VirusTotal: POST /files<br/>(file, API key)
    VirusTotal-->>Backend: Return analysis_id
    Backend->>Database: Update ScanRequest with analysis_id
    Backend-->>Frontend: Return analysis_id
    Frontend->>Frontend: Start Polling
    
    loop Poll Every 6 Seconds
        Frontend->>Backend: GET /api/analysis/:id
        Backend->>VirusTotal: GET /analyses/:id
        VirusTotal-->>Backend: Return Status
        alt Analysis Complete
            Backend->>Database: Update ScanRequest with results
            Backend->>Gemini: Request AI Analysis
            Gemini-->>Backend: Return AI Analysis
            Backend-->>Frontend: Return Complete Results
            Frontend->>Frontend: Stop Polling
            Frontend-->>User: Display Results
        else Analysis Pending
            Backend-->>Frontend: Return Status: "pending"
        end
    end
```

---

## CÁCH SỬ DỤNG

### 1. Xem trong GitHub
- File này sẽ tự động render các diagram Mermaid trong GitHub
- Chỉ cần commit và push lên repository

### 2. Xem trong VS Code
- Cài đặt extension: "Markdown Preview Mermaid Support"
- Mở file và nhấn `Ctrl+Shift+V` (Windows) hoặc `Cmd+Shift+V` (Mac)

### 3. Xem trong Mermaid Live Editor
- Copy code Mermaid từ file này
- Paste vào: https://mermaid.live
- Diagram sẽ được render ngay lập tức

### 4. Export sang hình ảnh
- Sử dụng Mermaid CLI: `mmdc -i input.mmd -o output.png`
- Hoặc dùng Mermaid Live Editor để export PNG/SVG

---

## GHI CHÚ

- Tất cả các diagram được tạo bằng Mermaid syntax
- Có thể chỉnh sửa và tùy chỉnh theo nhu cầu
- Đảm bảo cài đặt extension hoặc công cụ hỗ trợ Mermaid để xem
- Các diagram này phản ánh kiến trúc hệ thống tại thời điểm phân tích

---

**Cập nhật lần cuối**: 2025-12-03  
**Phiên bản**: 1.0.0  
**Dự án**: Ransomware Analysis Portal

