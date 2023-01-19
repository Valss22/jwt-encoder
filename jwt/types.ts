export type Payload = {
  [key: string]: any;
  exp?: number | undefined;
};

type Algorithms = "HS256";

export interface Header {
  alg: Algorithms;
  typ: "JWT";
}

export const DefaultHeader: Header = {
  alg: "HS256",
  typ: "JWT",
};
