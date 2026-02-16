# Real-Time Poll Rooms

Full-stack assignment submission for Applyo/Skite: create polls, share links, collect votes, and view real-time results.

## Tech Stack

- Backend: Node.js, Express, Socket.IO
- Database: SQLite (`data/applyo.db`)
- Frontend: HTML/CSS/vanilla JavaScript

## Features Implemented

- Poll creation with question + 2 to 8 options
- Shareable poll URL (`/poll/:slug`)
- Single-choice voting
- Real-time result updates using Socket.IO rooms
- Persistent polls and votes in SQLite

## Fairness / Anti-Abuse Mechanisms

1. Device-level single vote lock
- Mechanism: Every visitor gets a persistent device cookie (`did`), and the `votes` table enforces `UNIQUE (poll_id, device_id)`.
- Prevents: repeat voting from the same browser/device for the same poll.
- Limitation: can be bypassed by clearing cookies or changing browser/device.

2. IP-based rate limiting
- Mechanism: all create/vote attempts are logged in `rate_limits`, and API checks enforce thresholds:
- Poll creation: max 10 per IP per hour
- Vote attempts: max 30 per IP per minute per poll
- Prevents: high-frequency spam/automation from a single IP.
- Limitation: shared networks (office/campus) may hit limits earlier; attackers can rotate IPs.

## Edge Cases Handled

- Invalid poll input:
- Question length constrained (5 to 200 chars)
- Option count constrained (2 to 8)
- Empty options removed
- Duplicate options rejected (case-insensitive)
- Invalid share link returns 404 response from API
- Voting with option not belonging to poll is rejected
- Double voting from same device returns conflict (`409`)
- Real-time updates continue to work while users are on results page
- Poll/votes persist across page refreshes and server restarts

## Known Limitations / Next Improvements

- No authentication; fairness is best-effort for anonymous users
- No CAPTCHA/challenge flow for bot resistance
- No vote-edit feature (intentionally one-time vote)
- Rate limit storage cleanup is simple; can be moved to scheduled job in production
- Basic UI only; could improve accessibility and visual polish

## Local Run

```bash
npm install
npm start
```

Open:
- `http://localhost:3000` to create a poll
- Generated share URL for voting

## Deployment Notes

The app can be deployed on services like Render/Railway/Fly.io.
- Ensure persistent disk for SQLite file (`data/applyo.db`) or switch to managed DB for production.
