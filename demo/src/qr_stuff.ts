// Helper for converting raw bytes into QR codes.
//
// Since we are dealing with raw binary bytes, normal text QR libraries will mangle them.
// So we use Nayuki's qrcodegen helper to preserve our binary bytes exactly.
// This single file is shared between the browser GUI (main_code.ts) and the test script (test_stuff.test.ts).

import qrcodegen from "nayuki-qr-code-generator";

const errorLevel = qrcodegen.QrCode.Ecc;

// Converts a bunch of bytes into a QR code.
// Uses Medium error correction (level M) so it's readable but not too dense.
export function bytesToQR(inputData: Uint8Array) {
  const segment = qrcodegen.QrSegment.makeBytes(Array.from(inputData));
  return qrcodegen.QrCode.encodeSegments([segment], errorLevel.MEDIUM);
}

export type QrCode = ReturnType<typeof bytesToQR>;

// Renders the QR code modules into a flat RGBA pixel array (like ImageData).
// pixelScale = size of each QR block in pixels.
// borderSize = white boundary size around the QR code.
export function drawQRToBytes(
  myQR: QrCode,
  pixelScale = 8,
  borderSize = 4,
): { data: Uint8ClampedArray<ArrayBuffer>; width: number; height: number } {
  const gridDim = myQR.size + borderSize * 2;
  const totalPixels = gridDim * pixelScale;
  const pixelArray = new Uint8ClampedArray(totalPixels * totalPixels * 4);
  
  for (let yIndex = 0; yIndex < totalPixels; yIndex++) {
    const yModule = Math.floor(yIndex / pixelScale) - borderSize;
    for (let xIndex = 0; xIndex < totalPixels; xIndex++) {
      const xModule = Math.floor(xIndex / pixelScale) - borderSize;
      const isBlack = myQR.getModule(xModule, yModule); // light outside the QR area
      const colorVal = isBlack ? 0 : 255;
      const arrayIndex = (yIndex * totalPixels + xIndex) * 4;
      pixelArray[arrayIndex] = colorVal;
      pixelArray[arrayIndex + 1] = colorVal;
      pixelArray[arrayIndex + 2] = colorVal;
      pixelArray[arrayIndex + 3] = 255;
    }
  }
  return { data: pixelArray, width: totalPixels, height: totalPixels };
}
