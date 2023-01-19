import { Buffer } from "buffer";

export const headerDefault: Header = {
  alg: "HS256",
  typ: "JWT",
};

type Algorithms = "HS256";

export interface Header {
  alg: Algorithms;
  typ: "JWT";
}

export const encodeHeader = (header: Header = headerDefault): string => {
  const headerJSON = JSON.stringify(header);
  return Buffer.from(headerJSON).toString("base64");
};
