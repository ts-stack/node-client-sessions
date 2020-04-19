/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

export interface Opts {
  /**
   * Cookie name dictates the key name added to the request object.
   */
  cookieName?: string;
  /**
   * Should be a large unguessable string.
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
  signatureAlgorithm?: string;
  encryptionAlgorithm?: string;
  requestKey?: string;
  cookie?: Cookie;
}

export interface Cookie {
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
  expires?: Date;
}

export interface ObjectAny {
  [key: string]: any;
}
