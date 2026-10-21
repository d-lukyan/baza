# 🛡️ Project: Baza
**Full-stack web application with a focus on Application Security (AppSec).**

The "Baza" project is a training ground for practicing secure web development skills. It implements 
strict data validation, session protection, and an architecture resistant to common vulnerabilities.

## 🚀 Key Features
* **Strict Validation:** Custom `utils-server.js` module for deep validation of all incoming data (username, email, password, messages).
* **Secure Auth:** Password hashing with `bcryptjs` and session management via `express-session`.
* **Zero-Leak Policy:** Sensitive data is moved to `.env` (environment variables are used).
* **Search System:** Search for users in PostgreSQL database.

## 🛠️ Tech Stack
* **Backend:** Node.js, Express
* **Database:** PostgreSQL
* **Security:** Bcryptjs, Dotenv, Express-session
* **Frontend:** HTML5, CSS3, JavaScript

## Install docker compose 
```bash
sudo apt install docker-compose
```

## 📦 Installation & Setup

```bash
  git clone https://github.com/d-lukyan/baza.git && cd baza && cp .env.example .env && sudo docker compose up --build
```
## Credentials 
```text
username: admin_1
email: admin_1@baza.xyz
password: p-SSw0RD

(The password is stored in the database in hashed form)
```

