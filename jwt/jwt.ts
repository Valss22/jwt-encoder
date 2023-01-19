import { Buffer } from "buffer";
import { Payload, DefaultHeader, Header } from "./types";
import { getUnsignedToken, getSignature } from "./encoding";

class JWT {
  private expirationDate: number;

  constructor(
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
    const unsignedToken = getUnsignedToken(this.header, this.payload);
    const signature = getSignature(this.header, this.payload, this.secretKey);
    const extraSeconds = this.payload["exp"] ? this.payload["exp"] : 0;
    this.expirationDate = Math.floor(Date.now() / 1000) + extraSeconds;

    return unsignedToken + "." + signature;
  }

  getPayloadFromJWT(jwt: string): Payload {
    if (this.verifyJWT(this.payload["exp"], this.expirationDate)) {
      const encodedPayload = jwt.split(".")[1];
      const strPayload = Buffer.from(encodedPayload, "base64").toString(
        "ascii"
      );
      return JSON.parse(strPayload);
    } else {
      console.error("jwt expired");
    }
  }
}
