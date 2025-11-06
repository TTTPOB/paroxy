import React from 'react';
import ReactDOM from 'react-dom/client';
import { AdminPage } from './pages/AdminPage';
import './index.css';

const root = document.getElementById('root')!;

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <AdminPage />
  </React.StrictMode>
);
