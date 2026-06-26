"use client";

// src/next/client.tsx
import {
  createContext,
  useContext,
  useEffect,
  useState
} from "react";
import { jsx } from "react/jsx-runtime";
var UserContext = createContext({ user: null, isLoading: false });
function UserProvider({ user, children }) {
  return /* @__PURE__ */ jsx(UserContext.Provider, { value: { user, isLoading: false }, children });
}
function useUser() {
  return useContext(UserContext);
}
function UserFetchProvider({
  children,
  mePath = "/auth/me"
}) {
  const [user, setUser] = useState(null);
  const [isLoading, setLoading] = useState(true);
  useEffect(() => {
    fetch(mePath, { credentials: "same-origin" }).then((r) => r.ok ? r.json() : null).then((data) => setUser(data)).catch(() => setUser(null)).finally(() => setLoading(false));
  }, [mePath]);
  return /* @__PURE__ */ jsx(UserContext.Provider, { value: { user, isLoading }, children });
}
export {
  UserFetchProvider,
  UserProvider,
  useUser
};
