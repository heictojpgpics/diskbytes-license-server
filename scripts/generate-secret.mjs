#!/usr/bin/env node
/** Generate a strong random secret (ADMIN_API_KEY or CLIENT_REQUEST_SECRET). */
import { randomBytes } from "node:crypto";

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
console.log(hex(randomBytes(32)));
