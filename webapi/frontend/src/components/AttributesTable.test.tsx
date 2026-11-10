import { fireEvent, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AttributeValue, AttributesTable, BOUNDED_CHARS, CLAMP_CHARS, looksLong } from './AttributesTable';
import type { ClassAd } from '@/lib/api';

// A controlled AttributeValue, the way the table holds it.
function Value({ name, value }: { name: string; value: string }) {
  const [expanded, setExpanded] = useState(false);
  return <AttributeValue name={name} value={value} expanded={expanded} onToggle={() => setExpanded((v) => !v)} />;
}

const long = 'a'.repeat(CLAMP_CHARS + 1);

describe('looksLong', () => {
  it('is false for a short value and true past the character or line limit', () => {
    expect(looksLong('short')).toBe(false);
    expect(looksLong(long)).toBe(true);
    expect(looksLong('1\n2\n3')).toBe(false);
    expect(looksLong('1\n2\n3\n4')).toBe(true);
  });
});

describe('AttributeValue', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('has no toggle for a short value', () => {
    render(<Value name="Owner" value="alice" />);
    expect(screen.getByText('alice')).toBeInTheDocument();
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('clamps a long value behind a Show more toggle', () => {
    render(<Value name="Args" value={long} />);
    const more = screen.getByRole('button', { name: 'Show more' });
    expect(more).toHaveAttribute('aria-expanded', 'false');
    const text = screen.getByText(long);
    expect(text).toHaveClass('line-clamp-3');
    expect(more).toHaveAttribute('aria-controls', text.id);

    fireEvent.click(more);
    const less = screen.getByRole('button', { name: 'Show less' });
    expect(less).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText(long)).not.toHaveClass('line-clamp-3');

    fireEvent.click(less);
    expect(screen.getByRole('button', { name: 'Show more' })).toHaveAttribute('aria-expanded', 'false');
  });

  it('bounds a very long value in a scrolling box when expanded', () => {
    const huge = 'b'.repeat(BOUNDED_CHARS + 1);
    render(<Value name="Blob" value={huge} />);
    fireEvent.click(screen.getByRole('button', { name: 'Show more' }));
    const box = screen.getByRole('region', { name: 'Blob value' });
    expect(box).toHaveClass('max-h-72', 'overflow-y-auto');
    expect(box).toHaveAttribute('tabindex', '0');
  });

  it('a measured value decides over its length', () => {
    // A layout in which the long value fits in three lines.
    vi.stubGlobal(
      'ResizeObserver',
      class {
        constructor(private cb: () => void) {}
        observe() {
          this.cb();
        }
        disconnect() {}
      },
    );
    const spies = [
      vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(48),
      vi.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockReturnValue(48),
    ];
    try {
      render(<Value name="Args" value={long} />);
      expect(screen.queryByRole('button')).toBeNull();
    } finally {
      spies.forEach((s) => s.mockRestore());
    }
  });

  it('opens an environment to one variable per line', () => {
    const env = `GREETING='hello world' Q='it''s' ${Array.from({ length: 8 }, (_, i) => `VAR_${i}=${'x'.repeat(20)}`).join(' ')}`;
    render(<Value name="Environment" value={env} />);
    expect(screen.getByText('10 variables')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Show more' }));
    const items = within(screen.getByTestId('environment-list')).getAllByRole('listitem');
    expect(items).toHaveLength(10);
    expect(items[0]).toHaveTextContent('GREETING=hello world');
    expect(items[1]).toHaveTextContent("Q=it's");
  });

  it('opens a V1 Env the same way', () => {
    const env = Array.from({ length: 8 }, (_, i) => `VAR_${i}=${'y'.repeat(20)}`).join(';');
    render(<Value name="Env" value={env} />);
    fireEvent.click(screen.getByRole('button', { name: 'Show more' }));
    expect(within(screen.getByTestId('environment-list')).getAllByRole('listitem')).toHaveLength(8);
  });
});

const ad: ClassAd = {
  Owner: 'alice',
  ClusterId: 7,
  Args: long,
};

function table(editable = false) {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <AttributesTable jobID="7.0" job={ad} editable={editable} />
    </QueryClientProvider>,
  );
}

describe('AttributesTable', () => {
  afterEach(() => vi.unstubAllGlobals());

  it("does not list the server's evaluated requests as an attribute", () => {
    const client = new QueryClient();
    render(
      <QueryClientProvider client={client}>
        <AttributesTable jobID="7.0" job={{ ...ad, evaluated: { RequestMemory: 2048 } }} editable />
      </QueryClientProvider>,
    );
    expect(screen.queryByText('evaluated')).toBeNull();
    expect(screen.queryByText('{"RequestMemory":2048}')).toBeNull();
    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('is a table on a wide screen', () => {
    table();
    expect(screen.getAllByRole('table').length).toBeGreaterThan(0);
    expect(screen.queryAllByTestId('attribute-card')).toHaveLength(0);
    expect(screen.getAllByRole('button', { name: 'Show more' })).toHaveLength(1);
  });

  describe('on a phone', () => {
    // jsdom has no matchMedia: give it one that says the screen is narrow.
    const narrow = () =>
      vi.stubGlobal('matchMedia', (q: string) => ({
        matches: q.includes('max-width'),
        media: q,
        addEventListener: () => {},
        removeEventListener: () => {},
      }));

    it('lists cards, name over value, in name order', () => {
      narrow();
      table();
      expect(screen.queryByRole('table')).toBeNull();
      const cards = screen.getAllByTestId('attribute-card');
      expect(cards).toHaveLength(3);
      expect(cards[0]).toHaveTextContent(/^Args/);
      expect(cards[1]).toHaveTextContent(/^ClusterId/);
      expect(cards[2]).toHaveTextContent(/^Owner/);
      const owner = cards[2];
      expect(within(owner).getByText('Owner')).toBeInTheDocument();
      expect(within(owner).getByText('alice')).toBeInTheDocument();
      expect(within(owner).queryByRole('button')).toBeNull();
      expect(within(cards[0]).getByRole('button', { name: 'Show more' })).toBeInTheDocument();
    });

    it('filters cards', () => {
      narrow();
      table();
      fireEvent.change(screen.getByRole('textbox', { name: 'Filter ClassAd attributes' }), {
        target: { value: 'ali' },
      });
      expect(screen.getAllByTestId('attribute-card')).toHaveLength(1);
      expect(screen.getByText('1 / 3')).toBeInTheDocument();
    });

    it('edits from a card', () => {
      narrow();
      table(true);
      fireEvent.click(screen.getByRole('button', { name: 'Edit Owner' }));
      expect(screen.getByRole('combobox', { name: 'Attribute type' })).toHaveValue('string');
      expect(screen.getByDisplayValue('alice')).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'cancel' }));
      expect(screen.getByText('alice')).toBeInTheDocument();
    });
  });
});
