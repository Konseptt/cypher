// Web app for sending files through flashing QR code loops. Pretty sick.
// The test suite says this works without losing bytes, so don't touch the math.

import { Sender, Receiver, generate_phrase } from "@konsept/cypher";
import jsQR from "jsqr";
import { bytesToQR, drawQRToBytes } from "./qr_stuff";

// Lazy shortcut because document.getElementById is way too much typing.
const getEl = <T extends HTMLElement = HTMLElement>(id: string) =>
  document.getElementById(id) as T;

// ---------------- PAGE SWITCHER THINGY ----------------
// Toggle between TX and RX. Shut down everything that is running so it doesn't crash.
function togglePages(activePage: string) {
  const isSend = activePage === "send";
  getEl("send-panel").hidden = !isSend;
  getEl("recv-panel").hidden = isSend;
  getEl("mode-send").setAttribute("aria-selected", String(isSend));
  getEl("mode-recv").setAttribute("aria-selected", String(!isSend));
  if (isSend) stopRxMode();
  else stopTxMode();
}
getEl("mode-send").addEventListener("click", () => togglePages("send"));
getEl("mode-recv").addEventListener("click", () => togglePages("recv"));

// Generates a random pass-phrase from the wordlist so we don't have to think of one.
getEl("send-randomize").addEventListener("click", () => {
  getEl<HTMLInputElement>("send-phrase").value = generate_phrase();
});

// ---------------- SENDER GUY (TX) ----------------

const canvas1 = getEl<HTMLCanvasElement>("send-canvas");
const ctx1 = canvas1.getContext("2d") as CanvasRenderingContext2D;
const statusText1 = getEl("send-status");
let loopTimer: ReturnType<typeof setInterval> | null = null;

const sleepMs = (ms: number) => new Promise((r) => setTimeout(r, ms));

const getClampedFps = () =>
  Math.max(1, Math.min(30, Number(getEl<HTMLInputElement>("send-fps").value) || 20));

// If they are on a phone, make the QR codes way bigger and simpler so the camera can read them.
function getMaxBytesPerFrame(): number {
  return matchMedia("(pointer: coarse)").matches ? 250 : 600;
}

function updateTxStatus(message: string) {
  statusText1.textContent = message;
}

async function grabFileBytes() {
  const fileBlob = getEl<HTMLInputElement>("send-file").files![0];
  if (!fileBlob) return null;
  const buffer = await fileBlob.arrayBuffer();
  return { bytes: new Uint8Array(buffer), name: fileBlob.name };
}

let externalWindow: Window | null = null; 
let externalCtx: CanvasRenderingContext2D | null = null; 

function drawOnCanvas(bytes: Uint8Array) {
  const qrCode = bytesToQR(bytes);
  const { data: d, width: w, height: h } = drawQRToBytes(qrCode, 8, 4);
  canvas1.width = w;
  canvas1.height = h;
  ctx1.putImageData(new ImageData(d, w, h), 0, 0);
  canvas1.style.display = "block";
  
  // If they have a popup window open, clone the screen frames to it.
  if (externalCtx) {
    const c = externalCtx.canvas;
    if (c.width !== w || c.height !== h) {
      c.width = w;
      c.height = h;
    }
    externalCtx.drawImage(canvas1, 0, 0);
  }
}

// Call the library to build the array of frames we are going to flash.
async function generatePayloadFrames() {
  const fileData = await grabFileBytes();
  if (!fileData) {
    updateTxStatus("Pick a file first.");
    return null;
  }
  const phraseStr = getEl<HTMLInputElement>("send-phrase").value.trim();
  try {
    const payloadFrames = new Sender(phraseStr, phraseStr === "").frames(
      fileData.bytes,
      fileData.name,
      getMaxBytesPerFrame(),
    );
    if (!payloadFrames.length) {
      updateTxStatus("Sender produced no frames.");
      return null;
    }
    return { frames: payloadFrames, fileInfo: fileData };
  } catch (e) {
    updateTxStatus("Sender error: " + e);
    return null;
  }
}

// Turn buttons on/off based on what we are doing, so the user doesn't break stuff.
function updateTxButtons(currentState: string) {
  const hasFile = getEl<HTMLInputElement>("send-file").files!.length > 0;
  const isPlaying = currentState === "playing";
  getEl<HTMLButtonElement>("send-start").disabled = !hasFile || currentState !== "idle";
  getEl<HTMLButtonElement>("send-clear").disabled = !hasFile;
  getEl<HTMLButtonElement>("send-stop").disabled = !isPlaying;
  getEl<HTMLButtonElement>("send-popout").disabled = !isPlaying;
  getEl<HTMLButtonElement>("send-record").disabled = !isPlaying;
}

function stopTxMode() {
  if (loopTimer) clearInterval(loopTimer);
  loopTimer = null;
  updateTxButtons("idle");
  canvas1.style.display = "none";
  if (externalWindow) externalWindow.close();
  externalWindow = null;
  externalCtx = null;
}

async function startTxMode() {
  const setup = await generatePayloadFrames();
  if (!setup) return;
  const { frames: payloadFrames, fileInfo: fileData } = setup;
  const speed = getClampedFps();
  stopTxMode();
  updateTxButtons("playing");
  let frameIndex = 0;
  
  const nextFrame = () => {
    drawOnCanvas(payloadFrames[frameIndex]);
    updateTxStatus(
      `Sending "${fileData.name}" (${fileData.bytes.length} B) - frame ${frameIndex + 1}/${payloadFrames.length} @ ${speed} fps`,
    );
    frameIndex = (frameIndex + 1) % payloadFrames.length;
  };
  nextFrame();
  loopTimer = setInterval(nextFrame, 1000 / speed);
}

// Record the blinking canvas to a video file using the browser's recording API.
async function saveVideoFile() {
  const setup = await generatePayloadFrames();
  if (!setup) return;
  const { frames: payloadFrames, fileInfo: fileData } = setup;
  const speed = getClampedFps();

  const videoFormat = [
    "video/mp4;codecs=avc1",
    "video/mp4",
    "video/webm;codecs=vp9",
    "video/webm",
  ].find((m) => MediaRecorder.isTypeSupported(m));
  if (!videoFormat) {
    updateTxStatus("This browser can't record video (no MediaRecorder codec).");
    return;
  }
  const fileExt = videoFormat.startsWith("video/mp4") ? "mp4" : "webm";

  stopTxMode();
  updateTxButtons("recording");

  drawOnCanvas(payloadFrames[0]);
  const videoStream = canvas1.captureStream(speed);
  const savedChunks: Blob[] = [];
  const recorder = new MediaRecorder(videoStream, {
    mimeType: videoFormat,
    videoBitsPerSecond: 12_000_000,
  });
  recorder.ondataavailable = (e) => e.data.size && savedChunks.push(e.data);
  const recordingDone = new Promise<void>((res) => (recorder.onstop = () => res()));
  recorder.start();

  for (let idx = 0; idx < payloadFrames.length; idx++) {
    drawOnCanvas(payloadFrames[idx]);
    updateTxStatus(
      `Recording ${fileExt.toUpperCase()} - frame ${idx + 1}/${payloadFrames.length} @ ${speed} fps`,
    );
    await sleepMs(1000 / speed);
  }
  await sleepMs(1000 / speed); 
  recorder.stop();
  videoStream.getTracks().forEach((t) => t.stop());
  await recordingDone;

  const baseName = (fileData.name || "cypher").replace(/\.[^.]+$/, "");
  downloadBlobData(new Blob(savedChunks, { type: videoFormat }), `${baseName}.cypher.${fileExt}`);
  updateTxStatus(`Saved ${payloadFrames.length}-frame ${fileExt.toUpperCase()} video.`);
  canvas1.style.display = "none";
  updateTxButtons("idle");
}

getEl("send-file").addEventListener("change", (e) => {
  const fileInput = e.target as HTMLInputElement;
  const label = getEl("send-file-label");
  if (fileInput.files && fileInput.files[0]) {
    label.textContent = "📂 " + fileInput.files[0].name;
  } else {
    label.textContent = "📂 SELECT A FILE...";
  }
  updateTxButtons("idle");
});
getEl("send-fps").addEventListener("input", () => {
  const element = getEl<HTMLInputElement>("send-fps");
  if (Number(element.value) > 30) element.value = "30";
});
getEl("send-fps").addEventListener("change", () => {
  getEl<HTMLInputElement>("send-fps").value = String(getClampedFps());
});
getEl("send-start").addEventListener("click", startTxMode);
getEl("send-record").addEventListener("click", saveVideoFile);
getEl("send-clear").addEventListener("click", () => {
  stopTxMode();
  getEl<HTMLInputElement>("send-file").value = "";
  getEl("send-file-label").textContent = "📂 SELECT A FILE...";
  updateTxButtons("idle");
  updateTxStatus("Idle.");
});

// Open a popout window so we can drag the QR code to another monitor.
getEl("send-popout").addEventListener("click", () => {
  const poppedWin = window.open("", "cypher-live", "width=640,height=680");
  if (!poppedWin) {
    updateTxStatus("Pop-out blocked - allow pop-ups for this page.");
    return;
  }
  poppedWin.document.title = "Cypher - live QR";
  poppedWin.document.head.innerHTML =
    "<style>html,body{margin:0;height:100%;background:#fff;display:flex;" +
    "align-items:center;justify-content:center}" +
    "canvas{width:100vmin;height:100vmin;image-rendering:pixelated}</style>";
  const popCanvas = poppedWin.document.createElement("canvas");
  popCanvas.width = canvas1.width;
  popCanvas.height = canvas1.height;
  poppedWin.document.body.appendChild(popCanvas);
  externalWindow = poppedWin;
  externalCtx = popCanvas.getContext("2d");
  externalCtx!.drawImage(canvas1, 0, 0); 
  
  poppedWin.addEventListener("beforeunload", () => {
    externalWindow = null;
    externalCtx = null;
  });
});
getEl("send-stop").addEventListener("click", () => {
  stopTxMode();
  updateTxStatus("Stopped.");
});
updateTxButtons("idle");

// ---------------- RECEIVER GUY (RX) ----------------

const myVideo = getEl<HTMLVideoElement>("recv-video");
const canvas2 = getEl<HTMLCanvasElement>("recv-canvas");
const ctx2 = canvas2.getContext("2d", {
  willReadFrequently: true,
}) as CanvasRenderingContext2D;
const statusText2 = getEl("recv-status");
let cameraStream: MediaStream | null = null;
let videoUrl: string | null = null;
let animationId: number | null = null;
let listenerGuys: Receiver[] = [];
let countOfFrames = 0;

function updateRxStatus(message: string) {
  statusText2.textContent = message;
}

function drawBoundingBox(loc: NonNullable<ReturnType<typeof jsQR>>["location"]) {
  ctx2.lineWidth = 4;
  ctx2.strokeStyle = "#4f4";
  ctx2.beginPath();
  ctx2.moveTo(loc.topLeftCorner.x, loc.topLeftCorner.y);
  ctx2.lineTo(loc.topRightCorner.x, loc.topRightCorner.y);
  ctx2.lineTo(loc.bottomRightCorner.x, loc.bottomRightCorner.y);
  ctx2.lineTo(loc.bottomLeftCorner.x, loc.bottomLeftCorner.y);
  ctx2.closePath();
  ctx2.stroke();
}

function downloadBlobData(blob: Blob, fileName: string) {
  const tempUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = tempUrl;
  anchor.download = fileName || "download";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(tempUrl);
}

function triggerDownload(bytes: Uint8Array<ArrayBuffer>, name: string) {
  downloadBlobData(
    new Blob([bytes], { type: "application/octet-stream" }),
    name || "received.bin",
  );
}

function cameraLoop() {
  if (myVideo.readyState === myVideo.HAVE_ENOUGH_DATA) {
    const w = myVideo.videoWidth;
    const h = myVideo.videoHeight;
    if (w && h) {
      canvas2.width = w;
      canvas2.height = h;
      ctx2.drawImage(myVideo, 0, 0, w, h);
      const imgData = ctx2.getImageData(0, 0, w, h);
      const qrData = jsQR(imgData.data, w, h);
      
      if (qrData && qrData.binaryData && qrData.binaryData.length) {
        drawBoundingBox(qrData.location);
        countOfFrames++;
        
        const wireBytes = new Uint8Array(qrData.binaryData);
        let solvedListener: Receiver | null = null;
        for (const listener of listenerGuys) {
          try {
            listener.push_frame(wireBytes);
          } catch (_) {
            // Decrypt failed on this listener, which is normal. Keep checking the next listener.
          }
          if (listener.is_complete()) {
            solvedListener = listener;
            break;
          }
        }
        updateRxStatus(`frames seen: ${countOfFrames}\ncomplete: ${!!solvedListener}`);
        if (solvedListener) {
          const rxName = solvedListener.name();
          triggerDownload(new Uint8Array(solvedListener.data()), rxName);
          updateRxStatus(
            `COMPLETE - downloaded "${rxName}" after ${countOfFrames} frames.`,
          );
          stopRxMode();
          return;
        }
      }
    }
  }
  animationId = requestAnimationFrame(cameraLoop);
}

function stopRxMode() {
  if (animationId) cancelAnimationFrame(animationId);
  animationId = null;
  if (cameraStream) cameraStream.getTracks().forEach((t) => t.stop());
  cameraStream = null;
  if (videoUrl) URL.revokeObjectURL(videoUrl);
  videoUrl = null;
  myVideo.srcObject = null;
  myVideo.removeAttribute("src");
  myVideo.load();
  canvas2.style.display = "none";
  getEl<HTMLButtonElement>("recv-start").disabled = false;
  getEl<HTMLInputElement>("recv-file").disabled = false;
  getEl<HTMLButtonElement>("recv-stop").disabled = true;
  getEl("recv-file-label").textContent = "🎞 LOAD RECORDING...";
}

async function startRxMode(source: "camera" | File) {
  const phraseVal = getEl<HTMLInputElement>("recv-phrase").value.trim();
  try {
    listenerGuys = [new Receiver("", true)];
    if (phraseVal) listenerGuys.push(new Receiver(phraseVal, false));
  } catch (e) {
    updateRxStatus("Receiver error: " + e);
    return;
  }
  countOfFrames = 0;

  if (source === "camera") {
    try {
      cameraStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
      });
    } catch (e) {
      updateRxStatus("Camera error: " + e);
      return;
    }
    myVideo.srcObject = cameraStream;
    myVideo.loop = false;
    updateRxStatus("Camera on - point it at the sender's QR video.");
  } else {
    videoUrl = URL.createObjectURL(source);
    myVideo.srcObject = null;
    myVideo.src = videoUrl;
    myVideo.muted = true; 
    myVideo.loop = true; 
    updateRxStatus(`Decoding "${source.name}" - replaying until complete.`);
  }

  try {
    await myVideo.play();
  } catch (e) {
    updateRxStatus("Playback error: " + e);
    stopRxMode();
    return;
  }
  canvas2.style.display = "block";
  getEl<HTMLButtonElement>("recv-start").disabled = true;
  getEl<HTMLInputElement>("recv-file").disabled = true;
  getEl<HTMLButtonElement>("recv-stop").disabled = false;
  cameraLoop();
}

getEl("recv-start").addEventListener("click", () => startRxMode("camera"));
getEl("recv-file").addEventListener("change", (e) => {
  const fileInput = e.target as HTMLInputElement;
  const label = getEl("recv-file-label");
  const fileSelected = fileInput.files![0];
  if (fileSelected) {
    label.textContent = "🎞 " + fileSelected.name;
    startRxMode(fileSelected);
  }
  fileInput.value = ""; 
});
getEl("recv-stop").addEventListener("click", () => {
  stopRxMode();
  updateRxStatus("Stopped.");
});

// ---------------- INSTRUCTIONS MODAL (POPUP) ----------------
const instructionsModal = getEl("instructions-modal");
const openInstructionsBtn = getEl("open-instructions");
const closeModalTop = getEl("close-modal-top");
const closeModalBtn = getEl("close-modal-btn");
const dontShowAgainCheckbox = getEl<HTMLInputElement>("dont-show-again");

function showInstructions() {
  instructionsModal.classList.add("show");
}

function hideInstructions() {
  instructionsModal.classList.remove("show");
  if (dontShowAgainCheckbox.checked) {
    localStorage.setItem("cypher_dismiss_instructions", "true");
  } else {
    localStorage.setItem("cypher_dismiss_instructions", "false");
  }
}

// Open modal on click
openInstructionsBtn.addEventListener("click", () => {
  dontShowAgainCheckbox.checked = localStorage.getItem("cypher_dismiss_instructions") === "true";
  showInstructions();
});

// Close modal handlers
closeModalTop.addEventListener("click", hideInstructions);
closeModalBtn.addEventListener("click", hideInstructions);
instructionsModal.addEventListener("click", (e) => {
  if (e.target === instructionsModal) {
    hideInstructions();
  }
});

// Show automatically on page load if not dismissed
const isDismissed = localStorage.getItem("cypher_dismiss_instructions") === "true";
dontShowAgainCheckbox.checked = isDismissed;
if (!isDismissed) {
  showInstructions();
}

