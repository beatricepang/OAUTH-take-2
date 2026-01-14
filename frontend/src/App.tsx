import { useEffect, useState } from "react";

type Me = { email: string; name: string };

export default function App() {
  const [me, setMe] = useState<Me | null>(null);

  async function loadMe() {
    const res = await fetch("/api/me", { credentials: "include" });
    if (!res.ok) {
      setMe(null);
      return;
    }
    setMe(await res.json());
  }

  useEffect(() => {
    loadMe();
  }, []);

  return (
    <div style={{ padding: 24 }}>
      <h1>Google OAuth (React + Gin + Goth)</h1>

      {!me ? (
        <button
          onClick={() => {
            // Since Vite proxies /auth -> backend, this works nicely in dev
            window.location.assign("/auth/google?redirect=http://localhost:5173/");
          }}
        >
          Sign in with Google
        </button>
      ) : (
        <>
          <p>
            Signed in as <b>{me.name}</b> ({me.email})
          </p>
          <button
            onClick={async () => {
              await fetch("/logout", { method: "GET", credentials: "include" });
              await loadMe();
            }}
          >
            Logout
          </button>
        </>
      )}
    </div>
  );
}
