// Mock DOMParser
class MockDOMParser {
  parseFromString(html: string, _mimeType: string) {
    const parser = new DOMParser();
    return parser.parseFromString(html, 'text/html');
  }
}

// Mock browser APIs if not in browser environment
if (typeof window === 'undefined') {
  global.DOMParser = MockDOMParser as any;
  global.HTMLElement = class {} as any;
  global.HTMLScriptElement = class {} as any;
  global.HTMLStyleElement = class {} as any;
  global.HTMLLinkElement = class {} as any;
  global.HTMLImageElement = class {} as any;
  global.HTMLIFrameElement = class {} as any;
  global.HTMLFormElement = class {} as any;
  global.HTMLBaseElement = class {} as any;
} 