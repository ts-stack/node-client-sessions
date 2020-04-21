/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { Cookies, NodeRequest, NodeResponse } from '@ts-stack/cookies';

import { SessionOptions } from './types';
import { encode, decode } from './util';

/**
 * Session object
 *
 * this should be implemented with proxies at some point
 */
export class Session {
  protected _content: any;
  protected json: string;
  protected loaded: boolean;
  protected dirty: boolean;
  protected createdAt: number;
  protected duration: number;
  protected activeDuration: number | string;
  protected expires: Date;

  constructor(req: NodeRequest, res: NodeResponse, protected cookies: Cookies, protected opts: SessionOptions) {
    if (opts.cookie.ephemeral && opts.cookie.maxAge) {
      throw new Error('you cannot have an ephemeral cookie with a maxAge.');
    }

    this.content = {};
    this.json = JSON.stringify(this._content);
    this.loaded = false;
    this.dirty = false;

    // no need to initialize it, loadFromCookie will do
    // via reset() or unbox()
    this.createdAt = null;
    this.duration = opts.duration;
    this.activeDuration = opts.activeDuration;

    // support for maxAge
    if (opts.cookie.maxAge) {
      this.expires = new Date(new Date().getTime() + opts.cookie.maxAge);
    } else {
      this.updateDefaultExpires();
    }

    // here, we check that the security bits are set correctly
    const secure =
      (res.socket && (res.socket as any).encrypted) || ((req as any).connection && (req as any).connection.proxySecure);
    if (opts.cookie.secure && !secure) {
      throw new Error(
        'you cannot have a secure cookie unless the socket is ' +
          ' secure or you declare req.connection.proxySecure to be true.'
      );
    }
  }

  get content() {
    if (!this.loaded) {
      this.loadFromCookie();
    }
    return this._content;
  }

  set content(value: any) {
    Object.defineProperty(value, 'reset', {
      enumerable: false,
      value: this.reset.bind(this),
    });
    Object.defineProperty(value, 'destroy', {
      enumerable: false,
      value: this.destroy.bind(this),
    });
    Object.defineProperty(value, 'setDuration', {
      enumerable: false,
      value: this.setDuration.bind(this),
    });
    this._content = value;
  }

  updateCookie() {
    if (this.isDirty()) {
      // support for adding/removing cookie expires
      this.opts.cookie.expires = this.expires;

      try {
        this.cookies.set(this.opts.cookieName, this.box(), this.opts.cookie);
      } catch (x) {
        // this really shouldn't happen. Right now it happens if secure is set
        // but cookies can't determine that the connection is secure.
      }
    }
  }

  protected updateDefaultExpires() {
    if (this.opts.cookie.maxAge) {
      return;
    }

    if (this.opts.cookie.ephemeral) {
      this.expires = null;
    } else {
      const time = this.createdAt || new Date().getTime();
      // the cookie should expire when it becomes invalid
      // we add an extra second because the conversion to a date
      // truncates the milliseconds
      this.expires = new Date(time + this.duration + 1000);
    }
  }

  protected clearContent(keysToPreserve?: string) {
    const self = this;
    Object.keys(this._content).forEach((k) => {
      // exclude this key if it's meant to be preserved
      if (keysToPreserve && keysToPreserve.indexOf(k) > -1) {
        return;
      }

      delete self._content[k];
    });
  }

  protected reset(keysToPreserve?: string) {
    this.clearContent(keysToPreserve);
    this.createdAt = new Date().getTime();
    this.duration = this.opts.duration;
    this.updateDefaultExpires();
    this.dirty = true;
    this.loaded = true;
  }

  // alias for `reset` function for compatibility
  protected destroy() {
    this.reset();
  }

  protected setDuration(newDuration: number, ephemeral: boolean) {
    if (ephemeral && this.opts.cookie.maxAge) {
      throw new Error('you cannot have an ephemeral cookie with a maxAge.');
    }
    if (!this.loaded) {
      this.loadFromCookie(true);
    }
    this.dirty = true;
    this.duration = newDuration;
    this.createdAt = new Date().getTime();
    this.opts.cookie.ephemeral = ephemeral;
    this.updateDefaultExpires();
  }

  // take the content and do the encrypt-and-sign
  // boxing builds in the concept of createdAt
  protected box() {
    return encode(this.opts, this._content, this.duration, this.createdAt);
  }

  protected unbox(content: string) {
    this.clearContent();

    const unboxed = decode(this.opts, content);
    if (!unboxed) {
      return;
    }

    Object.assign(this._content, unboxed.content);
    this.createdAt = unboxed.createdAt;
    this.duration = unboxed.duration;
    this.updateDefaultExpires();
  }

  protected loadFromCookie(forceReset?: boolean) {
    const cookie = this.cookies.get(this.opts.cookieName);
    if (cookie) {
      this.unbox(cookie);

      const expiresAt = this.createdAt + this.duration;
      const now = Date.now();
      // should we reset this session?
      if (expiresAt < now) {
        this.reset();
        // if expiration is soon, push back a few minutes to not interrupt user
      } else if (expiresAt - now < this.activeDuration) {
        this.createdAt += +this.activeDuration;
        this.dirty = true;
        this.updateDefaultExpires();
      }
    } else {
      if (forceReset) {
        this.reset();
      } else {
        return false; // didn't actually load the cookie
      }
    }

    this.loaded = true;
    this.json = JSON.stringify(this._content);
    return true;
  }

  protected isDirty() {
    return this.dirty || this.json !== JSON.stringify(this._content);
  }
}
