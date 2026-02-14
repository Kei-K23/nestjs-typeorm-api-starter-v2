import { Request } from 'express';
import { UAParser } from 'ua-parser-js';

export interface ParsedUserAgent {
  device: string;
  browser: string;
  os: string;
}

export function parseUserAgent(request: Request): ParsedUserAgent {
  if (!request) {
    return {
      device: 'Unknown',
      browser: 'Unknown',
      os: 'Unknown',
    };
  }

  const userAgent = request.get('User-Agent') || '';

  const parser = new UAParser(userAgent);
  const result = parser.getResult();

  return {
    device: result.device.model || result.device.type || 'Desktop',
    browser:
      `${result.browser.name || 'Unknown'} ${result.browser.version || ''}`.trim(),
    os: `${result.os.name || 'Unknown'} ${result.os.version || ''}`.trim(),
  };
}
