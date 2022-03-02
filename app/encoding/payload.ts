import {Buffer} from "buffer";

export type Payload = {
  [key: string]: any,
  exp?: number | undefined
}

export const encodePayload = (payload: Payload): string => {
  const payloadJSON = JSON.stringify(payload)
  return Buffer.from(payloadJSON).toString('base64')
}