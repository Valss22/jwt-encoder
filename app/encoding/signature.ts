import {encodeHeader, HEADER_DEFAULT, IHeader} from "./header";
import {encodePayload, Payload} from "./payload";

const crypto = require('crypto')


export const getUnsignedToken = (
  header = HEADER_DEFAULT, payload
): string => {
  return encodeHeader(header)
    + '.' + encodePayload(payload)
}


export const getSignature = (
  header: IHeader = HEADER_DEFAULT,
  payload: Payload, secretKey: string
) => {
  return crypto
    .createHmac('SHA256', secretKey)
    .update(getUnsignedToken(header, payload))
    .digest('base64')
}


