# Blog Platform: Express + MongoDB

Features: register/login (bcrypt + JWT), create/edit/delete posts, comments, search, pagination.

## Run locally
1. `npm install`
2. Copy `.env.example` to `.env`; set `MONGODB_URI` (MongoDB Atlas free tier) and `JWT_SECRET`.
3. `npm run dev`, open http://localhost:3000.

## Permissions
- Anyone can read posts and comments.
- Logged-in users can write posts and comment.
- Only a post's author can edit or delete it (its comments are deleted with it).
- A comment can be deleted by its own author or by the author of the post it is on.

## REST API
| Method | Route | Access |
|---|---|---|
| POST | /api/auth/register, /api/auth/login | public |
| GET | /api/auth/me | user |
| GET | /api/posts?page=1&q=search | public |
| GET | /api/posts/:id | public |
| POST | /api/posts | user |
| PUT / DELETE | /api/posts/:id | post author |
| GET | /api/posts/:id/comments | public |
| POST | /api/posts/:id/comments | user |
| DELETE | /api/comments/:id | comment author or post author |

Content is stored as plain text and escaped on display, so users cannot inject HTML or scripts.

## Deploy
Render or Railway: build `npm install`, start `npm start`, set `MONGODB_URI` and `JWT_SECRET`.
Create a MongoDB Atlas cluster and allow access from anywhere (0.0.0.0/0).
