import querystring from 'querystring';
import crypto from 'crypto';
import nonce from 'nonce';

import { OAuthStartOptions /* , AccessMode */ /* , NextFunction */ } from '../types';
import { Context, Next as NextFunction } from 'koa';
import getCookieOptions from './cookie-options';

const createNonce = nonce();

export function genShopifyAuthLink({
  apiKey,
  // secret,
  accessMode,
  scopes,
  shop,
  host,
  state,
}: any) {

  // const nonce = config.app.nonce;

  const params = {
    client_id: apiKey,
    scope: scopes.join(','), // per-user
    redirect_uri: `https://${host}/auth/callback`,
    state,
    'grant_options[]': accessMode,
  };

  return `https://${shop}/admin/oauth/authorize?` + querystring.stringify(params);

}

export function verifyShopifyQueryString(ctx: Context, secret: string) {
  const s = Object.keys(ctx.query)
    .filter((key) => key !== 'hmac')
    .map((key) => key + '=' + ctx.query[key])
    .sort()
    .join('&');

  const digest = crypto.createHmac('SHA256', secret)
          .update(s)
          .digest('hex');

  return digest === ctx.query.hmac;

}

export async function processCallback(ctx: Context, apiKey: string, secret: string) {
  const shopifyNonce = ctx.cookies.get('shopifyNonce');
  if (!shopifyNonce || shopifyNonce !== ctx.query.state) {
    throw new Error('Request origin could not be verified');
  }

  if (
    typeof ctx.query.shop === 'string'
    // && ctx.query.shop.match(/(https|http)\:\/\/[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com[\/]?/)
    && ctx.query.shop.match(/[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com[\/]?/)
    && verifyShopifyQueryString(ctx, secret)
  ) { 
    try {
      const response = await fetch(
        `https://${ctx.query.shop}/admin/oauth/access_token`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            client_id: apiKey,
            client_secret: secret,
            code: ctx.query.code,
          })
        }
      );
      
      if (response.ok) {
        return await response.json();
      } else {
        throw new Error('Bad request');
      }
    } catch (err) {
      throw new Error(err.message);
    }
  } else {
    throw new Error('Bad request');
  }
}

export default function createShopifyAuth({
  apiKey,
  secret,
  accessMode = 'offline',
  scopes = [],
  // tunnelUrl,
  afterAuth,
  stateName = 'session',
 }: OAuthStartOptions) {
   console.log('here 2')
  return async (ctx: Context, next: NextFunction) => {
    if (ctx.path === '/auth' || ctx.path === '/auth/') {
      if (!ctx.query.shop) {
        ctx.status = 400;
        ctx.body = 'Bad request';
        return;
      }
      const { host, cookies } = ctx;
      const state = createNonce();
      cookies.set('shopifyNonce', state, getCookieOptions(ctx));
    
      ctx.redirect(exports.genShopifyAuthLink({
        apiKey,
        secret,
        accessMode,
        scopes,
        host,
        shop: ctx.query.shop,
        state,
      }));
      return;
    }
    if (ctx.path === '/auth/callback') {
      try {
        const accessTokenData = await exports.processCallback(ctx, apiKey, secret);
        if (!ctx[stateName]) {
          ctx[stateName] = {};
        }
        ctx[stateName] = {
          ...ctx[stateName],
          shop: ctx.query.shop,
          accessToken: accessTokenData.access_token,
        }
        if (typeof afterAuth === 'function') {
          await afterAuth(ctx);
        }
      } catch (err) {
        ctx.status = 400;
        ctx.body = 'Bad request';
      }
      return;
    }
    await next();
  }
}
