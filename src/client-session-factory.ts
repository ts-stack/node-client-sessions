import Cookies = require('cookies');
import { Request, Response, NextFunction } from 'express';

import { Opts } from './types';
import {
  ACTIVE_DURATION,
  DEFAULT_ENCRYPTION_ALGO,
  ENCRYPTION_ALGORITHMS,
  DEFAULT_SIGNATURE_ALGO,
  SIGNATURE_ALGORITHMS,
  setupKeys,
  keyConstraints,
  isObject,
} from './util';
import { Session } from './session';

export function clientSessionFactory(opts: Opts) {
  if (!opts) {
    throw new Error('no options provided, some are required');
  }

  if (!(opts.secret || (opts.encryptionKey && opts.signatureKey))) {
    throw new Error('cannot set up sessions without a secret ' + 'or encryptionKey/signatureKey pair');
  }

  // defaults
  opts.cookieName = opts.cookieName || 'session_state';
  opts.duration = opts.duration || 24 * 60 * 60 * 1000;
  opts.activeDuration = 'activeDuration' in opts ? opts.activeDuration : ACTIVE_DURATION;

  let encAlg = opts.encryptionAlgorithm || DEFAULT_ENCRYPTION_ALGO;
  encAlg = encAlg.toLowerCase();
  if (!ENCRYPTION_ALGORITHMS[encAlg]) {
    throw new Error('invalid encryptionAlgorithm, supported are: ' + Object.keys(ENCRYPTION_ALGORITHMS).join(', '));
  }
  opts.encryptionAlgorithm = encAlg;

  let sigAlg = opts.signatureAlgorithm || DEFAULT_SIGNATURE_ALGO;
  sigAlg = sigAlg.toLowerCase();
  if (!SIGNATURE_ALGORITHMS[sigAlg]) {
    throw new Error('invalid signatureAlgorithm, supported are: ' + Object.keys(SIGNATURE_ALGORITHMS).join(', '));
  }
  opts.signatureAlgorithm = sigAlg;

  // set up cookie defaults
  opts.cookie = opts.cookie || {};
  if (typeof opts.cookie.httpOnly === 'undefined') {
    opts.cookie.httpOnly = true;
  }

  // let's not default to secure just yet,
  // as this depends on the socket being secure,
  // which is tricky to determine if proxied.
  /*
   if (typeof(opts.cookie.secure) == 'undefined')
     opts.cookie.secure = true;
     */

  setupKeys(opts);
  keyConstraints(opts);

  const propertyName = opts.requestKey || opts.cookieName;

  return function clientSession(req: Request, res: Response, next: NextFunction) {
    if (propertyName in req) {
      return next(); // self aware
    }

    const cookies = new Cookies(req, res);
    let rawSession: Session;
    try {
      rawSession = new Session(req, res, cookies, opts);
    } catch (x) {
      // this happens only if there's a big problem
      process.nextTick(function () {
        next(new Error('client-sessions error: ' + x.toString()));
      });
      return;
    }

    Object.defineProperty(req, propertyName, {
      get: function getSession() {
        return rawSession.content;
      },
      set: function setSession(value) {
        if (isObject(value)) {
          rawSession.content = value;
        } else {
          throw new TypeError('cannot set client-session to non-object');
        }
      },
    });

    const writeHead = res.writeHead;
    res.writeHead = function () {
      rawSession.updateCookie();
      return writeHead.apply(res, arguments);
    };

    next();
  };
}