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
  **Play live** to loop the QR for a camera - or **Save as video** to record it
  to a file to share or replay.
- **Receive:** enter the phrase (or leave blank), then **Start camera** and aim
  it at the QR - or load a saved video to decode offline. The file downloads
  automatically when complete.

Chrome/Edge work best; the camera needs a secure context (`localhost`, or HTTPS
over LAN).
