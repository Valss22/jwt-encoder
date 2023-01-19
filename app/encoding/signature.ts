import { encodeHeader, headerDefault, Header } from "./header";
import { encodePayload, Payload } from "./payload";

const crypto = require("crypto");

export const getUnsignedToken = (header = headerDefault, payload): string => {
  return encodeHeader(header) + "." + encodePayload(payload);
};

export const getSignature = (
  header: Header = headerDefault,
  payload: Payload,
  secretKey: string
) => {
  return crypto
    .createHmac("SHA256", secretKey)
    .update(getUnsignedToken(header, payload))
    .digest("base64");
};
