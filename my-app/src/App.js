import React, { useState, useEffect } from 'react';
import Dashboard from './components/Dashboard';
import Alerts from './components/Alerts';
import DataStructure from './components/DataStructure';
import './App.css'; // Import global styles

function App() {
  const [trafficData, setTrafficData] = useState([]);
  const [floatingAlert, setFloatingAlert] = useState(null); // State for floating alert

  useEffect(() => {
    const loadTrafficData = async () => {
      const response = await fetch('http://localhost:8888/api/traffic');
      const data = await response.json();
      setTrafficData(data);
    };
    loadTrafficData();
  }, []);

  const showAlert = (message) => {
    setFloatingAlert(message);
    setTimeout(() => setFloatingAlert(null), 5000); // Hide after 5 seconds
  };

  return (
    <div className="App">
      <div className="sidebar">
        <Alerts showAlert={showAlert} />
        <DataStructure showAlert={showAlert} />
      </div>
      <div className="main-content">
        <Dashboard trafficData={trafficData} setTrafficData={setTrafficData} showAlert={showAlert} />
      </div>
      {floatingAlert && (
        <div className="floating-alert show">
          {floatingAlert}
        </div>
      )}
    </div>
  );
}

export default App;

