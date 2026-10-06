import type { Metadata } from 'next';
import './globals.css';
import './password.css';
import './dashboard.css';
import './members.css';

export const metadata: Metadata = {
  title: 'Keyclock · Your second layer',
  description: 'Secure your account with time-based authenticator codes.',
  robots: { index: false, follow: false },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
