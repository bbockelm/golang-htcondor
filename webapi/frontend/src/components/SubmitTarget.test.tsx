import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { SubmitTarget } from './SubmitTarget';

describe('SubmitTarget', () => {
  it('renders nothing outside multi-AP mode', () => {
    const { container } = render(
      <SubmitTarget multiAP={false} assignment={{ schedd: 'ap2' }} value="" onChange={() => {}} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('names the home access point when there is no choice', () => {
    render(<SubmitTarget multiAP assignment={{ schedd: 'ap2.example.org' }} value="" onChange={() => {}} />);
    expect(screen.getByText('Will submit to')).toBeInTheDocument();
    expect(screen.getByText('ap2.example.org')).toBeInTheDocument();
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
  });

  it('offers only the home access point and its alternates', () => {
    const onChange = vi.fn();
    render(
      <SubmitTarget
        multiAP
        assignment={{ schedd: 'ap2.example.org', alternates: ['ap3.example.org'] }}
        value=""
        onChange={onChange}
      />,
    );
    const select = screen.getByRole('combobox', { name: 'Access point' });
    const options = Array.from((select as HTMLSelectElement).options).map((o) => o.value);
    expect(options).toEqual(['ap2.example.org', 'ap3.example.org']);
    expect((select as HTMLSelectElement).value).toBe('ap2.example.org');
    fireEvent.change(select, { target: { value: 'ap3.example.org' } });
    expect(onChange).toHaveBeenCalledWith('ap3.example.org');
  });

  it('says why submission is unavailable', () => {
    render(
      <SubmitTarget
        multiAP
        assignment={{ error: 'no access point is assigned to you', reason: 'no_access_point_assigned' }}
        value=""
        onChange={() => {}}
      />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent('You cannot submit here: no access point is assigned to you.');
  });
});
