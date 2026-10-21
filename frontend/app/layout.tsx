import type { Metadata } from 'next';
import './globals.css';
import './password.css';
import './dashboard.css';
import './members.css';

export const metadata: Metadata = {
  title: 'DUETCLOCK · Secure Student E2EE Chat',
  description: 'Exclusively for DUET students with end-to-end encryption and time-based authenticator codes.',
  robots: { index: false, follow: false },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
