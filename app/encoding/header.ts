import { Buffer } from "buffer";

export const HEADER_DEFAULT: IHeader = {
  alg: "HS256",
  typ: "JWT",
};

type Algorithms = "HS256";

export interface IHeader {
  alg: Algorithms;
  typ: "JWT";
}

export const encodeHeader = (header: IHeader = HEADER_DEFAULT): string => {
  const headerJSON = JSON.stringify(header);
  return Buffer.from(headerJSON).toString("base64");
};
