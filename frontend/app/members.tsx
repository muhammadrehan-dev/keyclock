'use client';

import { useEffect, useState } from 'react';

type Member = { id: number; name: string; email: string; can_message: boolean; is_you: boolean };
type Directory = { users: Member[]; total: number; next_cursor: number | null };

async function getMembers(after = 0): Promise<Directory> {
  const response = await fetch(`/api/auth/users?after=${after}`, { cache: 'no-store' });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'Could not load registered users. Please try again.');
  return data;
}

export default function Members({ onMessage, disabled }: { onMessage: (email: string) => void; disabled: boolean }) {
  const [directory, setDirectory] = useState<Directory | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    getMembers().then(data => { if (active) setDirectory(data); })
      .catch(e => { if (active) setError(e.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  async function load(more = false) {
    setLoading(true); setError('');
    try {
      const data = await getMembers(more ? directory?.next_cursor ?? 0 : 0);
      setDirectory(previous => more && previous ? { ...data, users: [...previous.users, ...data.users] } : data);
    } catch (e) { setError(e instanceof Error ? e.message : 'Please try again.'); }
    finally { setLoading(false); }
  }

  return <section className="dashboard-panel members-panel" aria-labelledby="members-title" aria-busy={loading}>
    <div className="panel-heading"><h2 id="members-title">Registered users{directory ? ` (${directory.total})` : ''}</h2><button className="outline-button" disabled={loading} onClick={() => load()}>Refresh users</button></div>
    <p className="description">Find someone on Keyclock and start a conversation.</p>
    {error && <p className="error" role="alert">{error}</p>}
    {!directory && loading && <p role="status" className="mailbox-note">Loading registered users…</p>}
    {directory?.users.length === 0 && <p className="mailbox-note">No registered users yet.</p>}
    <ul className="members-list">{directory?.users.map(member => <li key={member.id}>
      <span className="avatar" aria-hidden="true">{(member.name || member.email).slice(0, 1).toUpperCase()}</span>
      <div className="member-details"><strong>{member.name || 'Member'}{member.is_you && <span className="member-you">You</span>}</strong><span>{member.email}</span></div>
      {member.can_message ? <button className="outline-button" disabled={disabled} aria-label={`Message ${member.name || member.email}`} onClick={() => onMessage(member.email)}>Message ↗</button> : !member.is_you && <span className="member-pending">Setup pending</span>}
    </li>)}</ul>
    {directory?.next_cursor != null && <button className="outline-button" disabled={loading} onClick={() => load(true)}>{loading ? 'Loading…' : 'Load more users'}</button>}
  </section>;
}
