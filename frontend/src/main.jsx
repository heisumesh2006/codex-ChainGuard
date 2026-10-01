import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './styles/theme.css'
import './styles/dashboard.css'
import './styles/identity.css'
import './styles/governance.css'
import './styles/analysis.css'
import './styles/final.css'

createRoot(document.getElementById('root')).render(
  <React.StrictMode><App /></React.StrictMode>,
)
