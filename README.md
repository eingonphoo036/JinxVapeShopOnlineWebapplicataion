# Jinx Vape Shop - Secure E-Commerce Web Application

## Overview
**Jinx Vape Shop** is a prototype e-commerce website developed with a strong emphasis on cybersecurity best practices. This project showcases a user-centric shopping platform where safety, privacy, and data integrity are key priorities.

The application includes key modules like product browsing, user authentication, OTP verification, product reviews, account management, and secure purchase history tracking.

## Technology Stack
- **Frontend:** HTML, CSS (Jinja2 templating via Flask)
- **Backend:** Python (Flask Framework)
- **Security Focus Areas:** CSRF protection, input validation, session handling, HTTPS enforcement, and secure authentication practices.

## Key Security Features

### 🔐 Authentication & Authorization
- Secure login and registration system with password masking
- OTP-based 2FA verification for added account security (`otp.html`)
- Change password feature with CSRF token and input validation (`change_password.html`)

### 🧼 Input Validation & Sanitization
- CSRF protection tokens embedded in all forms
- Safe rendering of user input in reviews and settings
- Parameterized forms to prevent injection vulnerabilities

### 🔒 Session and Data Protection
- Cookies configured with `HttpOnly`, `Secure`, and `SameSite` policies (assumed in Flask session handling)
- Session expiration and logout flow implemented
- CSP (`Content-Security-Policy`) headers defined in all pages for XSS protection

### 🧾 Secure User Interaction
- Secure review submission with form checks and flash messaging
- Purchase history and user settings are accessible only to authenticated users
- Account deletion and password update mechanisms for user data control

## Main HTML Templates
- `homepage.html` – Main landing and search interface
- `login.html`, `register.html`, `otp.html` – Authentication and verification flow
- `product.html`, `productreview.html` – Product detail and review features
- `user_setting.html` – Secure user account controls
- `change_password.html`, `purchase_history.html`, `search_results.html` – Functional tools with security-enhanced UX

## Deployment Notes
To deploy this application securely:
1. Use HTTPS in production (via TLS certificate).
2. Set `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `SESSION_COOKIE_SAMESITE` in Flask config.
3. Store secrets and credentials using environment variables or secure vaults.
4. Disable Flask debug mode in production.

## Future Enhancements
- Role-Based Access Control (RBAC)
- Integration with secure payment gateways
- Biometric MFA or hardware token support
- Penetration testing and continuous security audits

## License
&copy; 2024 Jinx Vape Shop. All rights reserved.

---

This README is suitable for showcasing in your professional portfolio or repository. Let me know if you want it saved as a file or tailored further for platforms like GitHub or LinkedIn.
