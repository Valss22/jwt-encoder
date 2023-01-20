import { Buffer } from "buffer";
import { Payload, Header } from "./types";

const crypto = require("crypto");

export const defaultHeader: Header = {
  alg: "HS256",
  typ: "JWT",
};

export class JWTEncoder {
  encodeHeader(header: Header = defaultHeader): string {
    const headerJSON = JSON.stringify(header);
    return Buffer.from(headerJSON).toString("base64");
  }

  encodePayload(payload: Payload): string {
    const payloadJSON = JSON.stringify(payload);
    return Buffer.from(payloadJSON).toString("base64");
  }

  getUnsignedToken(header = defaultHeader, payload): string {
    return this.encodeHeader(header) + "." + this.encodePayload(payload);
  }

  getSignature(
    header: Header = defaultHeader,
    payload: Payload,
    secretKey: string
  ) {
    return crypto
      .createHmac("SHA256", secretKey)
      .update(this.getUnsignedToken(header, payload))
      .digest("base64");
  }
}
