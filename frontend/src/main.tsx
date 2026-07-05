import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createBrowserRouter, Navigate } from "react-router-dom";
import "./index.css";
import "reactflow/dist/style.css";
import App from "./App";
import CasesPage from "./pages/CasesPage";
import SettingsPage from "./pages/SettingsPage";
import CaseLayout from "./pages/CaseLayout";
import OverviewPage from "./pages/OverviewPage";
import TimelinePage from "./pages/TimelinePage";
import EntityMapPage from "./pages/EntityMapPage";
import EvidencePage from "./pages/EvidencePage";
import MemoryPage from "./pages/MemoryPage";
import FindingsPage from "./pages/FindingsPage";
import EventsPage from "./pages/EventsPage";
import ChatPage from "./pages/ChatPage";
import ReportPage from "./pages/ReportPage";

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 1 } },
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
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>,
);
