import { Context, Next as NextFunction } from 'koa';
import jwt from 'jsonwebtoken';

function verifyToken(token: string, secret: string) {
  try {
    const decoded = jwt.verify(token, secret);
    if (decoded.exp > Date.now() / 1000 && decoded.nbf < Date.now() / 1000) {
      const m = decoded.dest.match(/^https:\/\/(.*?)\.myshopify\.com$/);
      if (m) {
        const shop = `${m[1]}.myshopify.com`;
        return {
          shop,
          // accessToken: '!';
        }
      }
    } ;
    return null;
  } catch(err) {
    return null;
  }
}

export default function verifyRequest({
  stateName = 'session',
  secret,
  getOfflineToken
} : {
  stateName?: 'session' | string,
  secret: string,
  getOfflineToken: (shop: string) => Promise<string>,
}) {
  return async (ctx: Context, next: NextFunction) => {
    if (ctx.path === '/verify_token') {
      const token = ctx.query && ctx.query.token || null;
      if (token) {
        const tokenData = verifyToken(token, secret);
        if (tokenData && tokenData.shop && tokenData.shop=== ctx.query.shop) {
          const offlineToken = await getOfflineToken(tokenData.shop);
          if (offlineToken) {
            ctx.body = { status: 'ok' };
            return;
          }
        }
      }
      ctx.body = { status: 'error' };
      return;
    } 
    if (ctx.headers['authorization']) {
      const [, token] = ctx.headers['authorization'].split(' ');
      if (token) {
        const tokenData = verifyToken(token, secret);
        if (tokenData) {
          const offlineToken = await getOfflineToken(tokenData.shop);
          if (offlineToken) {
            ctx[stateName] = {
              shop: tokenData.shop || null,
              accessToken: offlineToken || null,
            };
            return next();
          }
        }
      }
    }
    ctx.status = 401;
    ctx.body = { message: 'Unauthorized' };
  }
}