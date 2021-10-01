import bippath from "bip32-path";
import { crypto } from "bitcoinjs-lib";
import { Merkle } from "./merkle";
import { createVarint } from "../varint";

export type DefaultDescriptorTemplate = "pkh(@0)" | "sh(pkh(@0))" | "wpkh(@0)" | "tr(@0)";

export class WalletPolicy {
  descriptorTemplate: string;
  keys: string[];
  /**
   * For now, we only support default descriptor templates.
   */
  constructor(descriptorTemplate: DefaultDescriptorTemplate, key: string) {
    this.descriptorTemplate = descriptorTemplate;
    this.keys = [key];
  }

  getWalletId(): Buffer {
    // wallet_id (sha256 of the wallet serialization),     
    return crypto.sha256(this.serialize());
  }

  serialize(): Buffer {
    const keyBuffers = this.keys.map(k => {
      return Buffer.from(k, 'ascii');
    });
    const m = new Merkle(keyBuffers);

    return Buffer.concat([
      Buffer.of(0),
      createVarint(this.descriptorTemplate.length),
      Buffer.from(this.descriptorTemplate, 'ascii'),
      m.getRoot(),
    ]);
  }
}

export function createKey(masterFingerprint: Buffer, path: number[], xpub: string) {
  // Limitation: bippath can't handle and empty path. It shouldn't affect us
  // right now, but might in the future.
  // TODO: Fix support for empty path.
  const accountPath = bippath.fromPathArray(path).toString(true);
  return `[${masterFingerprint.toString('hex')}/${accountPath}]${xpub}/**`;
}