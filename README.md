# OTP Auth App (Register + Login with Email OTP)

## Requirements
- Node.js 18+
- MongoDB running locally or a MongoDB connection string

## Setup
1. Copy the project files into a folder `otp-auth-app`.
2. In `backend` folder run `npm install`.
3. Create an `.env` file (use `.env.example`) and fill values.
4. Start backend: `npm run dev` (if using nodemon) or `npm start`.
5. Serve `frontend` files using a simple static server or open `frontend/register.html` and `frontend/login.html` in your browser. (For CORS safety use a local server like `live-server` or `npx http-server -p 5500 frontend`.)

## Notes
- This is a simple demo. For production, add proper input validation, rate-limiting, stronger session handling (JWT or cookies), HTTPS, and secure email credentials handling.