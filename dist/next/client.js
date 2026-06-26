"use strict";
"use client";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/next/client.tsx
var client_exports = {};
__export(client_exports, {
  UserFetchProvider: () => UserFetchProvider,
  UserProvider: () => UserProvider,
  useUser: () => useUser
});
module.exports = __toCommonJS(client_exports);
var import_react = require("react");
var import_jsx_runtime = require("react/jsx-runtime");
var UserContext = (0, import_react.createContext)({ user: null, isLoading: false });
function UserProvider({ user, children }) {
  return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(UserContext.Provider, { value: { user, isLoading: false }, children });
}
function useUser() {
  return (0, import_react.useContext)(UserContext);
}
function UserFetchProvider({
  children,
  mePath = "/auth/me"
}) {
  const [user, setUser] = (0, import_react.useState)(null);
  const [isLoading, setLoading] = (0, import_react.useState)(true);
  (0, import_react.useEffect)(() => {
    fetch(mePath, { credentials: "same-origin" }).then((r) => r.ok ? r.json() : null).then((data) => setUser(data)).catch(() => setUser(null)).finally(() => setLoading(false));
  }, [mePath]);
  return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(UserContext.Provider, { value: { user, isLoading }, children });
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  UserFetchProvider,
  UserProvider,
  useUser
});
