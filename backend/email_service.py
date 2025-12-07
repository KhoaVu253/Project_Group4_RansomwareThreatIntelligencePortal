"""
Email service for sending verification and notification emails
"""
import os
import secrets
from flask import Flask
from flask_mail import Mail, Message
from typing import Optional

# Initialize Flask app for mail
mail_app = Flask(__name__)
mail_app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
mail_app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
mail_app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
mail_app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
mail_app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail_app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', mail_app.config.get('MAIL_USERNAME'))

mail = Mail(mail_app)


def generate_verification_token() -> str:
    """Generate secure verification token"""
    return secrets.token_urlsafe(32)


def send_verification_email(user_email: str, user_name: str, token: str, base_url: str) -> bool:
    """Send email verification link"""
    verification_url = f"{base_url}/verify-email?token={token}"

    try:
        with mail_app.app_context():
            msg = Message(
                subject="Xác nhận email đăng ký - VirusTotal Intelligence",
                recipients=[user_email],
                sender=mail_app.config.get("MAIL_DEFAULT_SENDER") or mail_app.config.get("MAIL_USERNAME"),
                html=f"""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #4CAF50;">Xác nhận địa chỉ email</h2>
                        <p>Xin chào {user_name},</p>
                        <p>Cảm ơn bạn đã đăng ký tài khoản. Vui lòng click vào link sau để xác nhận email:</p>
                        <p style="text-align: center; margin: 30px 0;">
                            <a href="{verification_url}" 
                               style="background-color: #4CAF50; color: white; padding: 12px 24px; 
                                      text-decoration: none; border-radius: 5px; display: inline-block;">
                                Xác nhận email
                            </a>
                        </p>
                        <p>Hoặc copy link sau vào trình duyệt:</p>
                        <p style="word-break: break-all; color: #666;">{verification_url}</p>
                        <p><small>Link này sẽ hết hạn sau 24 giờ.</small></p>
                        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                        <p style="font-size: 12px; color: #999;">
                            Nếu bạn không đăng ký tài khoản này, vui lòng bỏ qua email này.
                        </p>
                    </div>
                </body>
                </html>
                """
            )
            mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


def send_otp_email(user_email: str, user_name: str, otp_code: str, purpose: str = "register") -> bool:
    """Send a short-lived OTP code for registration verification or password change."""
    try:
        # Check email configuration
        mail_username = mail_app.config.get("MAIL_USERNAME")
        mail_password = mail_app.config.get("MAIL_PASSWORD")
        mail_server = mail_app.config.get("MAIL_SERVER")
        mail_port = mail_app.config.get("MAIL_PORT")
        
        if not mail_username or not mail_password:
            error_msg = f"Email configuration missing. MAIL_USERNAME: {bool(mail_username)}, MAIL_PASSWORD: {bool(mail_password)}, MAIL_SERVER: {mail_server}, MAIL_PORT: {mail_port}"
            print(f"ERROR: {error_msg}")
            return False
        
        with mail_app.app_context():
            # Customize subject and content based on purpose
            if purpose == "change_password":
                subject = "Password Change Verification (OTP)"
                title = "Password Change Verification"
                description = "You have requested to change your password. Your OTP code is:"
                action_text = "Please enter the OTP to complete the password change."
                warning_text = "If you did not request this, please ignore this email and check your account."
            else:
                subject = "Registration Verification (OTP)"
                title = "Registration Verification"
                description = "Your OTP code is:"
                action_text = "Please enter the OTP to complete your registration."
                warning_text = "If you did not make this request, please ignore this email."
            
            sender = mail_app.config.get("MAIL_DEFAULT_SENDER") or mail_username
            print(f"Attempting to send OTP email to {user_email} from {sender} via {mail_server}:{mail_port}")
            
            msg = Message(
                subject=subject,
                recipients=[user_email],
                sender=sender,
                html=f"""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #1E90FF;">{title}</h2>
                        <p>Hello {user_name},</p>
                        <p>{description}</p>
                        <p style="font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #1E90FF;">{otp_code}</p>
                        <p>The OTP is valid for 10 minutes. {action_text}</p>
                        <p><strong>{warning_text}</strong></p>
                    </div>
                </body>
                </html>
                """,
            )
            mail.send(msg)
            print(f"OTP email sent successfully to {user_email}")
        return True
    except Exception as e:
        error_msg = f"Failed to send OTP email to {user_email}: {str(e)}"
        print(f"ERROR: {error_msg}")
        import traceback
        traceback.print_exc()
        return False


def send_login_warning_email(user_email: str, user_name: str) -> bool:
    """Send security alert email when too many failed login attempts occur."""
    msg = Message(
        subject="Security alert: Too many failed login attempts",
        recipients=[user_email],
        sender=mail_app.config.get("MAIL_DEFAULT_SENDER") or mail_app.config.get("MAIL_USERNAME"),
        html=f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #D9534F;">Security Alert</h2>
                <p>Hi {user_name},</p>
                <p>We detected multiple failed login attempts to your account. For your security, please reset your password using the "Forgot password" option.</p>
                <p>If this wasn't you, we recommend changing your password immediately after regaining access.</p>
            </div>
        </body>
        </html>
        """,
    )
    try:
        with mail_app.app_context():
            mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send login warning email: {e}")
        return False
