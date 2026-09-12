import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

// Vitest does not unmount between cases, so without this a getByText
// that should match once matches every copy left behind by earlier
// cases -- which fails as "multiple elements" rather than as the thing
// actually being tested.
afterEach(cleanup);
