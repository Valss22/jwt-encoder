import { Buffer } from "buffer";
import { Payload, DefaultHeader, Header } from "./types";
import { JWTEncoder } from "./encoder";

export class JWT {
  private expirationDate: number;

  constructor(
    private readonly encoder: JWTEncoder,
    private readonly payload: Payload,
    private readonly secretKey: string,
    private readonly header: Header = DefaultHeader
  ) {}

  verifyJWT(jwtLifetime: number | undefined, expirationDate: number): boolean {
    if (jwtLifetime) {
      const currentDate = Math.floor(Date.now() / 1000);
      return expirationDate > currentDate;
    }
    return true;
  }

  getJWT(): string {
    const unsignedToken = this.encoder.getUnsignedToken(
      this.header,
      this.payload
    );
    const signature = this.encoder.getSignature(
      this.header,
      this.payload,
      this.secretKey
    );
    const extraSeconds = this.payload["exp"] ? this.payload["exp"] : 0;
    this.expirationDate = Math.floor(Date.now() / 1000) + extraSeconds;

    return unsignedToken + "." + signature;
  }

  getPayload(jwt: string): Payload | never {
    if (this.verifyJWT(this.payload["exp"], this.expirationDate)) {
      const encodedPayload = jwt.split(".")[1];
      const strPayload = Buffer.from(encodedPayload, "base64").toString(
        "ascii"
      );
      return JSON.parse(strPayload);
    }
    throw new Error("jwt validation error!");
  }
}
