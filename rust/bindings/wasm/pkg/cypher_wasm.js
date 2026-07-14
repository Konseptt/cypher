/* @ts-self-types="./cypher_wasm.d.ts" */
import * as wasm from "./cypher_wasm_bg.wasm";
import { __wbg_set_wasm } from "./cypher_wasm_bg.js";

__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
export {
    Receiver, Sender, generate_phrase
} from "./cypher_wasm_bg.js";
