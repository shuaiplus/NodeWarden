/// <reference types="vite/client" />

declare module 'qrcode-generator' {
  interface QrCode {
    addData(data: string): void;
    make(): void;
    createSvgTag(options?: { scalable?: boolean; margin?: number }): string;
  }
  export default function qrcode(typeNumber: number, errorCorrectionLevel: 'L' | 'M' | 'Q' | 'H'): QrCode;
}
