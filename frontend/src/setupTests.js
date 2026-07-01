// jest-dom matchers : toBeInTheDocument, toHaveTextContent, etc.
import '@testing-library/jest-dom';
import { vi } from 'vitest';

// matchMedia mock — react-hot-toast uses window.matchMedia, jsdom doesn't implement it
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});
