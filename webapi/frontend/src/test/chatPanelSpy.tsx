// A spy on ChatPanel for page tests: renders the real panel, and keeps the
// props the page last gave it so a test can call the page's client-side
// hooks the way the panel would when the assistant invokes a tool.
//
// Usage, at the top of a test file:
//   vi.mock('@/components/ChatPanel', async () => (await import('@/test/chatPanelSpy')).chatPanelMock());
// then chatPanelProps() after render.

import type { ComponentProps } from 'react';
import { vi } from 'vitest';

type Props = ComponentProps<typeof import('@/components/ChatPanel').ChatPanel>;

let last: Props | null = null;

export function chatPanelProps(): Props {
  if (!last) throw new Error('the page has not rendered a ChatPanel');
  return last;
}

export function resetChatPanelSpy() {
  last = null;
}

export async function chatPanelMock() {
  const actual = await vi.importActual<typeof import('@/components/ChatPanel')>('@/components/ChatPanel');
  return {
    ...actual,
    ChatPanel: (props: Props) => {
      last = props;
      return <actual.ChatPanel {...props} />;
    },
  };
}

// callHook runs a client-side tool the way the panel does.
export function callHook(name: string, input: Record<string, unknown>): unknown {
  const hook = chatPanelProps().hooks?.[name];
  if (!hook) throw new Error(`the page has no ${name} hook`);
  return hook(input);
}
