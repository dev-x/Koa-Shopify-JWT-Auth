import { Context } from 'koa';

export default function getCookieOptions(ctx: Context) {
  const { headers } = ctx;
  const userAgent = headers['user-agent'];
  const isChrome = userAgent && userAgent.match(/chrome|crios/i);
  let cookieOptions = {};
  if (isChrome) {
    cookieOptions = {
      sameSite: 'none',
      secure: true,
    };
  }
  return cookieOptions;
}
