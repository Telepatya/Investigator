import React, { lazy } from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createBrowserRouter, Navigate } from "react-router-dom";
import "./index.css";
import App from "./App";
import CasesPage from "./pages/CasesPage";
import SettingsPage from "./pages/SettingsPage";
import CaseLayout from "./pages/CaseLayout";
import OverviewPage from "./pages/OverviewPage";
import EvidencePage from "./pages/EvidencePage";
import MemoryPage from "./pages/MemoryPage";
import FindingsPage from "./pages/FindingsPage";
import EventsPage from "./pages/EventsPage";
import ChatPage from "./pages/ChatPage";
import ReportPage from "./pages/ReportPage";
import { ThemeProvider } from "./lib/theme";

// Split the two heaviest routes into on-demand chunks: TimelinePage pulls in
// vis-timeline and EntityMapPage pulls in reactflow, so neither weighs down the
// initial load of the case list, dashboard, or settings.
const TimelinePage = lazy(() => import("./pages/TimelinePage"));
const EntityMapPage = lazy(() => import("./pages/EntityMapPage"));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 10_000,
      gcTime: 5 * 60_000,
    },
    mutations: { retry: 0 },
  },
});

const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
    children: [
      { index: true, element: <CasesPage /> },
      { path: "settings", element: <SettingsPage /> },
      {
        path: "cases/:caseId",
        element: <CaseLayout />,
        children: [
          { index: true, element: <Navigate to="overview" replace /> },
          { path: "overview", element: <OverviewPage /> },
          { path: "evidence", element: <EvidencePage /> },
          { path: "timeline", element: <TimelinePage /> },
          { path: "entities", element: <EntityMapPage /> },
          { path: "memory", element: <MemoryPage /> },
          { path: "findings", element: <FindingsPage /> },
          { path: "events", element: <EventsPage /> },
          { path: "report", element: <ReportPage /> },
          { path: "chat", element: <ChatPage /> },
        ],
      },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
