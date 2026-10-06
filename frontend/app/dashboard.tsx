'use client';

import { FormEvent, useEffect, useRef, useState } from 'react';
import Members from './members';

type Message = { id: number; body: string; created_at: number; contact: { name: string; email: string } };
type Mailbox = { inbox: Message[]; sent: Message[]; inbox_count: number; sent_count: number };
type Props = { name: string; email: string; onLogout: () => Promise<void>; busy: boolean; error: string };

async function mailboxRequest(body?: { recipient: string; body: string }): Promise<Mailbox> {
  const response = await fetch('/api/auth/messages', {
    method: body ? 'POST' : 'GET', cache: 'no-store',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'Could not load your messages. Please try again.');
  return data;
}

export default function Dashboard({ name, email, onLogout, busy, error }: Props) {
  const [mailbox, setMailbox] = useState<Mailbox | null>(null);
  const [folder, setFolder] = useState<'inbox' | 'sent'>('inbox');
  const [recipient, setRecipient] = useState('');
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [sendError, setSendError] = useState('');
  const [notice, setNotice] = useState('');
  const composer = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    let active = true;
    mailboxRequest().then(data => { if (active) setMailbox(data); })
      .catch(e => { if (active) setLoadError(e.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  async function refresh() {
    setLoading(true); setLoadError('');
    try { setMailbox(await mailboxRequest()); }
    catch (e) { setLoadError(e instanceof Error ? e.message : 'Please try again.'); }
    finally { setLoading(false); }
  }

  async function send(event: FormEvent) {
    event.preventDefault(); setSendError(''); setNotice('');
    if (!body.trim()) { setSendError('Write a message before sending.'); return; }
    setSending(true);
    try {
      await mailboxRequest({ recipient: recipient.trim(), body: body.trim() });
      setBody(''); setRecipient(''); setNotice('Message sent. You can find it in Sent.');
      await refresh();
    } catch (e) { setSendError(e instanceof Error ? e.message : 'Could not send your message.'); }
    finally { setSending(false); }
  }

  return <main className="dashboard">
    <header><a className="brand" href="/" aria-label="Keyclock home"><span className="brandmark">k</span>keyclock<span className="branddot">®</span></a><div className="dashboard-user"><span className="avatar">{(name || email).slice(0, 1).toUpperCase()}</span><span>{name || email}</span><button className="outline-button" disabled={busy || sending} onClick={onLogout}>{busy ? 'Signing out…' : 'Sign out'}</button></div></header>
    <section className="dashboard-welcome"><div><p className="eyebrow">YOUR PERSONAL SPACE</p><h1>Hello, {name || 'there'}.</h1><p>A little space to connect. Send a note, keep in touch.</p></div><span className="security-badge">✓ Authenticator protected</span></section>
    {error && <p className="error" role="alert">{error}</p>}
    <section className="dashboard-stats" aria-label="Account overview">
      <div><span>Messages received</span><strong>{mailbox?.inbox_count ?? '—'}</strong><small>Your personal inbox</small></div>
      <div><span>Messages sent</span><strong>{mailbox?.sent_count ?? '—'}</strong><small>Conversations started</small></div>
      <div className="profile-stat"><span>Your account</span><strong>{name || 'Member'}</strong><small>{email}</small></div>
    </section>
    <div className="dashboard-grid">
      <section className="dashboard-panel" aria-labelledby="mailbox-title">
        <div className="panel-heading"><h2 id="mailbox-title">Your messages</h2><button className="outline-button" disabled={loading || sending} onClick={refresh}>{loading ? 'Loading…' : 'Refresh'}</button></div>
        <div className="tabs mailbox-tabs" role="group" aria-label="Message folders"><button aria-pressed={folder === 'inbox'} className={folder === 'inbox' ? 'active' : ''} onClick={() => setFolder('inbox')}>Inbox</button><button aria-pressed={folder === 'sent'} className={folder === 'sent' ? 'active' : ''} onClick={() => setFolder('sent')}>Sent</button></div>
        {loadError && <p className="error" role="alert">{loadError}</p>}
        <div aria-busy={loading}>
          {!mailbox && loading ? <p className="empty-mailbox" role="status">Loading your messages…</p> : mailbox && mailbox[folder].length === 0 ? <div className="empty-mailbox"><span aria-hidden="true">✉</span><h3>{folder === 'inbox' ? 'A fresh start.' : 'Your first hello starts here.'}</h3><p>{folder === 'inbox' ? 'Messages from other members will appear here. Share your account email so they can reach you.' : 'Send a message to another member using the form beside your inbox.'}</p></div> : <div className="message-list">{mailbox?.[folder].map(message => <article className="message-item" key={message.id}><div className="message-meta"><div><strong>{folder === 'sent' ? 'To: ' : ''}{message.contact.name || message.contact.email}</strong><small>{message.contact.email}</small></div><time dateTime={new Date(message.created_at * 1000).toISOString()}>{new Date(message.created_at * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</time></div><p>{message.body}</p>{folder === 'inbox' && <button className="text-button" disabled={sending} onClick={() => { setRecipient(message.contact.email); setNotice(''); setSendError(''); composer.current?.focus(); }}>Reply ↗</button>}</article>)}</div>}
        </div>
        {mailbox && mailbox[folder].length > 0 && <p className="mailbox-note">Showing the latest {mailbox[folder].length} messages. Refresh to check for new ones.</p>}
      </section>
      <section className="dashboard-panel compose-panel" aria-labelledby="compose-title">
        <div className="eyebrow">SAY HELLO</div><h2 id="compose-title">Send a message.</h2><p className="description">Reach another Keyclock member using their registered email address.</p>
        <form onSubmit={send}><fieldset disabled={sending || busy}><label htmlFor="recipient">Recipient email</label><input id="recipient" type="email" required maxLength={254} placeholder="friend@example.com" value={recipient} onChange={e => setRecipient(e.target.value)} /><label htmlFor="message-body">Your message</label><textarea ref={composer} id="message-body" required maxLength={2000} rows={7} placeholder="Start with a hello…" value={body} onChange={e => setBody(e.target.value)} /><div className="character-count">{body.length.toLocaleString()} / 2,000</div>{sendError && <p className="error" role="alert">{sendError}</p>}{notice && <p className="send-success" role="status">✓ {notice}</p>}<button type="submit" className="primary" disabled={!body.trim() || !recipient.trim()}>{sending ? 'Sending…' : 'Send message'}<span aria-hidden="true">↗</span></button></fieldset></form>
        <p className="mailbox-note">Delivered to their inbox on Keyclock.</p>
      </section>
    </div>
    <Members disabled={sending || busy} onMessage={address => { setRecipient(address); setNotice(''); setSendError(''); composer.current?.focus(); composer.current?.scrollIntoView({ block: 'center', behavior: 'auto' }); }} />
    <footer><span>SMALL STEP. STRONGER CONNECTIONS.</span><span>Your space, a little more connected.</span></footer>
  </main>;
}
