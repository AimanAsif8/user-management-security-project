# Cybersecurity Internship – Web Application Security Project

## Overview
This repository documents the work completed during my cybersecurity internship. The goal was to identify and mitigate security vulnerabilities in a sample Node.js-based user management web application through manual testing, automated tools, and secure coding practices.

---

## Project Objective
Secure a vulnerable web application by:
- Identifying security flaws (XSS, SQL Injection, weak password storage)
- Implementing defensive coding techniques
- Performing manual and automated penetration testing
- Logging key security events for auditing
- Applying OWASP Top 10 principles

---

## Tools & Technologies Used
- Node.js, Express.js
- MongoDB
- bcrypt, jsonwebtoken, validator, helmet
- OWASP ZAP
- Winston (logging)
- Browser Developer Tools

---

## Weekly Breakdown

### Week 1: Security Assessment

#### 1. Application Setup
- Cloned a mock User Management System from GitHub.
- Set up project using:
  ```bash
  cd user-management-nodejs-mongodb-MVC
  npm install
  npm start
Explored key app routes:

Signup

Login

Profile

2. Vulnerability Testing
Cross-Site Scripting (XSS)
Injected payload <script>alert('XSS');</script> in signup form.
➤ Input was accepted, no sanitization.
Risk: High
Fix: Add input/output sanitization.

SQL Injection
Tried admin' OR '1'='1 during login.
➤ App showed partial protection but may still be vulnerable.
Risk: Medium
Fix: Use parameterized queries or ORM.

Password Storage
Verified usage of bcrypt in package.json.
➤ Passwords are hashed.
Risk: Low
Status: ✅ Secure

3. OWASP ZAP Scan
Ran an automated scan at http://localhost:3000

Found low/medium risks and informational alerts.

Saved ZAP report for analysis.

Week 2: Implementing Security Measures
1. Input Validation
Used validator package to validate email, name, and password.

Blocked invalid inputs with:

js
Copy
Edit
const validator = require('validator');
if (!validator.isEmail(email)) {
  return res.status(400).send('Invalid email');
}
2. Password Hashing (Confirmed)
bcrypt.hash() used during signup.

bcrypt.compare() used during login.

3. JWT-based Authentication
Installed jsonwebtoken.

Added session token handling:

js
Copy
Edit
const token = jwt.sign({ id: user._id }, 'your-secret-key', { expiresIn: '1h' });
req.session.token = token;
4. Securing HTTP Headers
Installed and used helmet:

js
Copy
Edit
const helmet = require('helmet');
app.use(helmet());
✅ Impact Summary
Security Feature	Status
Input Validation	✅ Implemented
Password Hashing	✅ Verified
JWT Authentication	✅ Added
HTTP Headers (Helmet.js)	✅ Secured

Week 3: Advanced Security and Final Reporting
1. Manual Penetration Testing
XSS and SQLi re-tested with sanitized inputs → App blocked them ✅

Session Hijacking Test: Edited session cookies in DevTools → App redirected to login ✅

2. Logging with Winston
Installed winston and configured logger:

js
Copy
Edit
const winston = require('winston');
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});
Logged:

App start

404 errors

Custom events for route access

3. Security Checklist
#	Security Area	Status	Notes
1	Input Validation	✅ Done	Using validator
2	Password Hashing	✅ Done	bcrypt implemented in Week 1
3	Secure Headers	✅ Done	Using helmet
4	Session Handling	✅ Secure	Session tampering protection works
5	Logging	✅ Done	Winston logs saved to file
6	Penetration Testing	✅ Done	Manual simulations successful
7	Nmap Scan	❌ Skipped	Optional task

Conclusion
Over the 3-week internship, I identified and mitigated common web vulnerabilities in a Node.js application. The project applied OWASP principles through both automated scanning and manual testing. The app now includes:

Secure password handling

Input validation

Token-based authentication

Logging of security events

Mitigation against XSS, SQLi, and session tampering

📁 Detailed reports are available in the internship-report/ folder.








