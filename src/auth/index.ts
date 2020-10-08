import querystring from 'querystring';
import crypto from 'crypto';
const nonce = 'test';
import { OAuthStartOptions /* , AccessMode */ /* , NextFunction */ } from '../types';
import { Context, Next as NextFunction } from 'koa';

export function genShopifyAuthLink({
  apiKey,
  // secret,
  accessMode,
  scopes,
  shop,
  host,
}: any) {

  // const nonce = config.app.nonce;

  const params = {
    client_id: apiKey,
    scope: scopes.join(','), // per-user
    redirect_uri: `https://${host}/auth/callback`,
    state: nonce,
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
  if (
    ctx.query.state === nonce
    && typeof ctx.query.shop === 'string'
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
  return async (ctx: Context, next: NextFunction) => {
    if (ctx.path === '/auth' || ctx.path === '/auth/') {
      if (!ctx.query.shop) {
        ctx.status = 400;
        ctx.body = 'Bad request';
        return;
      }
      const { host } = ctx;
      ctx.redirect(exports.genShopifyAuthLink({
        apiKey,
        secret,
        accessMode,
        scopes,
        host,
        shop: ctx.query.shop,
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
