import {HEADER_DEFAULT, IHeader} from "./encoding/header";
import {Payload} from "./encoding/payload";
import {getSignature, getUnsignedToken} from "./encoding/signature";
import {Buffer} from "buffer";
import {verifyJWT} from "./verification";


class JWT {
  private expirationDate: number

  constructor(
    private readonly payload: Payload,
    private readonly secretKey: string,
    private readonly header: IHeader = HEADER_DEFAULT
  ) {
  }

  getJWT(): string {
    const unsignedToken = getUnsignedToken(this.header, this.payload)
    const signature = getSignature(this.header, this.payload, this.secretKey)
    const extraSeconds = this.payload['exp'] ? this.payload['exp'] : 0
    this.expirationDate = Math.floor(Date.now() / 1000) + extraSeconds
    return unsignedToken + '.' + signature
  }

  getPayloadFromJWT(jwt: string): Payload {
    if (verifyJWT(this.payload['exp'], this.expirationDate)) {
      const encodedPayload = jwt.split('.')[1]
      const strPayload = Buffer.from(encodedPayload, 'base64').toString('ascii')
      return JSON.parse(strPayload)
    } else {
      console.error('jwt expired')
    }
  }
}

//const jwt = new JWT({user: 'tsts'}, 'fs')
