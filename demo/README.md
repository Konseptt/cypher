# Cypher browser demo

Send a file across an air gap as a looping QR video: one window renders it,
another films it with a webcam and rebuilds the file. Nothing is uploaded.

## Run

```sh
npm install
npm run dev
```

Open the printed URL in two windows (ideally two devices, or a screen + a phone
with a camera). Toggle **Send** / **Receive** at the top.

- **Send:** pick a file, optionally set a phrase (blank = public broadcast), then
  **Start Loop** - or **Save video** to record and share later.
- **Receive:** enter the same phrase (or leave blank), then **Start Camera** and aim
  at the QR - or load a saved video. The file downloads when complete.

Chrome/Edge work best; the camera needs a secure context (`localhost`, or HTTPS
over LAN).

Social / SEO preview image: `public/og-card.png`.
