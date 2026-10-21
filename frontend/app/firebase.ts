import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';

const firebaseConfig = {
  apiKey: "AIzaSyC1cALBUxV1ZfmKW3yZkqPeIH_EDqvDF6c",
  authDomain: "duet-e2e-chat.firebaseapp.com",
  databaseURL: "https://duet-e2e-chat-default-rtdb.asia-southeast1.firebasedatabase.app",
  projectId: "duet-e2e-chat",
  storageBucket: "duet-e2e-chat.firebasestorage.app",
  messagingSenderId: "239054230046",
  appId: "1:239054230046:web:0a2656506d1b983cc8d40f",
  measurementId: "G-K8GNLHE6XN"
};

const app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);
export const auth = getAuth(app);
export default app;
