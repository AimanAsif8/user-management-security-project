# 🔐 Node.js User Management System – Cybersecurity Internship Project

## 📌 Overview

This project is a mock User Management System built with Node.js, Express, and MongoDB. It was used as a practical project during my 3-week **Cybersecurity Internship** to identify, test, and fix web application vulnerabilities using **manual testing** and **OWASP ZAP**, while implementing best security practices.

---

## Week 1: Security Assessment

### 🔧 Application Setup
- Cloned the app from GitHub.
- Installed dependencies using:
  ```bash
  npm install
  npm start
Explored routes: /signup, /login, /profile.

Vulnerability Testing
1. Cross-Site Scripting (XSS)
Injected payload <script>alert('XSS');</script> in signup form.

❗ Input was accepted (no sanitization).

🔒 Fix: Apply input/output sanitization.

2. SQL Injection
Tried: admin' OR '1'='1 in login.

⚠ App showed partial protection.

🔒 Fix: Use parameterized queries or ORM.

3. Password Storage
Verified usage of bcrypt in package.json.

✅ Passwords are hashed securely.

4. OWASP ZAP Scan
Ran ZAP scan on http://localhost:3000.

Found low to medium risks.

Saved report in internship-report/.

Week 2: Implementing Security Measures
Input Validation
Used validator package.

Blocked invalid email, name, and password:

js
Copy
Edit
if (!validator.isEmail(email)) {
  return res.status(400).send('Invalid email');
}
Password Hashing (Confirmed)
bcrypt.hash() used during signup.

bcrypt.compare() used for login.

JWT Authentication
Installed jsonwebtoken.

Implemented token creation and session handling:

js
Copy
Edit
const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });
req.session.token = token;
Securing HTTP Headers
Installed helmet for HTTP security:

js
Copy
Edit
const helmet = require('helmet');
app.use(helmet());
Summary
Security Feature	Status
Input Validation	✅ Done
Password Hashing	✅ Done
JWT Authentication	✅ Done
HTTP Headers (Helmet)	✅ Done

Week 3: Advanced Security & Reporting
Manual Penetration Testing
Retested XSS and SQLi → Inputs blocked ✅

Tried session hijacking → Tampering redirected to login ✅

 Logging with Winston
Installed and configured winston:

js
Copy
Edit
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});
Logged app events like:

Server start

404 errors

Admin route access

✅ Final Security Checklist
#	Security Area	Status	Notes
1	Input Validation	✅ Done	validator package used
2	Password Hashing	✅ Done	bcrypt used
3	Secure Headers	✅ Done	helmet middleware added
4	Session Handling	✅ Secure	JWT & session protection
5	Logging	✅ Done	Winston implemented
6	Penetration Testing	✅ Done	XSS, SQLi, session checked
7	Nmap Scan	❌ Skipped	Optional

 Conclusion
During this 3-week internship, I successfully identified and secured a Node.js-based user management system by applying real-world cybersecurity practices:

Manual and Automated Testing (OWASP ZAP)

Fixed vulnerabilities like XSS, SQLi

Added secure authentication with JWT

Implemented logging with Winston

Followed OWASP security guidelines

All reports, code, and logs are stored in the internship-report/ folder.

Tools & Technologies Used
Node.js + Express

MongoDB

bcrypt

JWT (jsonwebtoken)

Helmet

Validator

Winston (logging)

OWASP ZAP (vulnerability scanner)
