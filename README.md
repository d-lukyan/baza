# 🛡️ Project: Baza
**Full-stack web application with a focus on Application Security (AppSec).**

The "Baza" project is a training ground for practicing secure web development skills. It implements 
strict data validation, session protection, and an architecture resistant to common vulnerabilities.

## 🚀 Key Features
* **Strict Validation:** Custom `utils-server.js` module for deep validation of all incoming data (username, email, password, messages).
* **Secure Auth:** Password hashing with `bcryptjs` and session management via `express-session`.
* **Zero-Leak Policy:** Sensitive data is moved to `.env` (environment variables are used).
* **Search System:** Search for users in SQLite database.

## 🛠️ Tech Stack
* **Backend:** Node.js, Express
* **Database:** SQLite3
* **Security:** Bcryptjs, Dotenv, Express-session
* **Frontend:** HTML5, CSS3, JavaScript (Vanilla)

## 📦 Installation & Setup

1. **Clone the repository:**
  ```bash
  git clone https://github.com/d-lukyan/baza.git
  cd baza
  ```
2. **Install dependencies:**
  ```bash
  npm install
  ```

3. **Set up environment variables:**
Create a .env file in the root of your project based on .env.example and add your keys:
  ```
PORT=3000
SESSION_SECRET=session_secret
DATABASE_URL=postgresql://username:password@127.0.0.1:3000/baza_db
  ```
4. **Start the server:**
  ```bash
npm run dev
  ```
  

