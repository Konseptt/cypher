/* tslint:disable */
/* eslint-disable */

export class Receiver {
    free(): void;
    [Symbol.dispose](): void;
    data(): Uint8Array;
    is_complete(): boolean;
    name(): string;
    constructor(phrase: string, is_public: boolean);
    push_frame(wire: Uint8Array): string;
}

export class Sender {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Render `file` (named `name`) to the wire frames the host loops as QR
     * codes. Random session_id (OsRng via getrandom's js backend).
     *
     * `max_wire` = QR density (per-frame wire budget); `max_loss` = tolerable
     * frame-loss percent. `None` for either keeps today's broadcast defaults.
     */
    frames(file: Uint8Array, name: string, max_wire?: number | null, max_loss?: number | null): Uint8Array[];
    constructor(phrase: string, is_public: boolean);
}

/**
 * A fresh random code phrase drawn from the protocol wordlist.
 */
export function generate_phrase(): string;
