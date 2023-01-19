import { Buffer } from "buffer";
import { Payload, Header, DefaultHeader } from "./types";

const crypto = require("crypto");

export const encodeHeader = (header: Header = DefaultHeader): string => {
  const headerJSON = JSON.stringify(header);
  return Buffer.from(headerJSON).toString("base64");
};

export const encodePayload = (payload: Payload): string => {
  const payloadJSON = JSON.stringify(payload);
  return Buffer.from(payloadJSON).toString("base64");
};

export const getUnsignedToken = (header = DefaultHeader, payload): string => {
  return encodeHeader(header) + "." + encodePayload(payload);
};

export const getSignature = (
  header: Header = DefaultHeader,
  payload: Payload,
  secretKey: string
) => {
  return crypto
    .createHmac("SHA256", secretKey)
    .update(getUnsignedToken(header, payload))
    .digest("base64");
};
