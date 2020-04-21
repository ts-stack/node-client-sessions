import { CookieOptions, NodeRequest, NodeResponse } from '@ts-stack/cookies';

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

export interface SessionOptions {
  /**
   * Cookie name dictates the key name added to the request object.
   */
  cookieName?: string;
  /**
   * Should be a large unguessable string or Buffer.
   */
  secret?: string;
  /**
   * How long the session will stay valid in ms.
   */
  duration?: number;
  /**
   * If expiresIn < activeDuration, the session will be extended
   * by activeDuration milliseconds.
   */
  activeDuration?: string | number;
  encryptionKey?: Buffer;
  signatureKey?: Buffer | string;
  /**
   * Supported HMAC `signatureAlgorithm`s (and key length requirements):
   * 
| HMAC           | Minimum Key Length | Maximum Key Length |
| -------------- | ------------------ | ------------------ |
| sha256         | 32 bytes           | 64 bytes           |
| sha256-drop128 | 32 bytes           | 64 bytes           |
| sha384         | 48 bytes           | 128 bytes          |
| sha384-drop192 | 48 bytes           | 128 bytes          |
| sha512         | 64 bytes           | 128 bytes          |
| sha512-drop256 | 64 bytes           | 128 bytes          |
   * 
   */
  signatureAlgorithm?: string;
  /**
   * 
   * Supported CBC-mode `encryptionAlgorithm`s (and key length requirements):

| Cipher | Key length |
| ------ | ---------- |
| aes128 | 16 bytes   |
| aes192 | 24 bytes   |
| aes256 | 32 bytes   |
   * 
   */
  encryptionAlgorithm?: string;
  /**
   * Overrides cookieName for the key name added to the request object.
   */
  requestKey?: string;
  cookie?: SessionCookieOptions;
}

export interface SessionCookieOptions extends CookieOptions {
  /**
   * Cookie will only be sent to requests under '/api'.
   */
  path?: string;
  /**
   * Duration of the cookie in milliseconds, defaults to duration above.
   */
  maxAge?: number;
  /**
   * When true, cookie expires when the browser closes.
   */
  ephemeral?: boolean;
  /**
   * When true, cookie is not accessible from javascript.
   */
  httpOnly?: boolean;
  /**
   * When true, cookie will only be sent over SSL. use key 'secureProxy'
   * instead if you handle SSL not in your node process.
   */
  secure?: boolean;
}

export interface ObjectAny {
  [key: string]: any;
}

export type SessionCallback = (req: NodeRequest, res: NodeResponse, next?: (...arg: any) => void) => void;
