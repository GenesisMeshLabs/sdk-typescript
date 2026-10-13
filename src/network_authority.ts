import type { HttpTransport } from './client.js';
import { GenesisMeshError } from './errors.js';
import { verifyKeyHistoryView, type KeyHistoryVerification, type KeyHistoryView, type NAKeyHistory } from './key-history.js';

/** The NA's key history was refused: the first failure's reason is the code (v1.5.0). */
export class KeyHistoryError extends GenesisMeshError {
  constructor(readonly verification: KeyHistoryVerification) {
    const first = verification.failures[0];
    super(`the NA key history is refused: ${first?.reason ?? 'key_history_invalid'} (key ${first?.key_sequence ?? '?'})`,
      first?.reason ?? 'key_history_invalid', 0);
    this.name = 'KeyHistoryError';
  }
}

/** The Network Authority's own keys (v1.5.0). */
export class NetworkAuthorityClient {
  constructor(private readonly http: HttpTransport) {}

  /**
   * The NA's key history (`GET /na/key-history`, public): the signed genesis
   * block, every succession and each key's validity. It proves nothing alone:
   * verify it from the root key you hold (`verifiedKeyHistory`).
   */
  getKeyHistory(): Promise<KeyHistoryView> {
    return this.http.publicGet<KeyHistoryView>('/na/key-history');
  }

  /**
   * The NA's key history, verified from the root public key held out of band
   * (the served keys are ignored and the history rebuilt from the genesis
   * block down). Pass it as `naPublicKeys` or `operatorPublicKeys` to verify
   * records signed before and after a succession, each with the key valid at
   * its time. Throws `KeyHistoryError` when the history is refused.
   */
  async verifiedKeyHistory(rootPublicKey: string): Promise<NAKeyHistory> {
    const verification = verifyKeyHistoryView(await this.getKeyHistory(), rootPublicKey);
    if (!verification.verified || verification.history === null) throw new KeyHistoryError(verification);
    return verification.history;
  }
}
