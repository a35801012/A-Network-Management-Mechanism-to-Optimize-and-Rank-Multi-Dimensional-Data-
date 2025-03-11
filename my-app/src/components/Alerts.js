//Alerts.js

import React, { useState, useEffect } from 'react';
import { useTable, useSortBy, usePagination } from 'react-table';
import './Alerts.css';

const Alerts = ({ showAlert }) => {
  const [networkInfo, setNetworkInfo] = useState({ nicName: '', ipAddress: '' });
  const [showThresholdsForm, setShowThresholdsForm] = useState(true);
  const [selectedThresholdKey, setSelectedThresholdKey] = useState('DATA_SIZE');
  const [selectedThresholdValue, setSelectedThresholdValue] = useState('');
  const [isRendered, setIsRendered] = useState(false);
  const [thresholds, setThresholds] = useState({
    DATA_SIZE: '',
    FLOW_COUNT: '',
    SRC_IP: '',
    DST_IP: '',
    SRC_PORT: '',
    DST_PORT: '',
    PROTOCOL: ''
  });
  const [logs, setLogs] = useState([]); // State to store log data
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refreshInterval, setRefreshInterval] = useState(5000);
  const [lastAlertTimestamp, setLastAlertTimestamp] = useState(null);


  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const networkResponse = await fetch('http://localhost:8888/');
        const [nicName, ipAddress] = await networkResponse.text().then(text => text.trim().split('\n'));
        const logsResponse = await fetch('http://localhost:8888/api/logs');
        const logsData = await logsResponse.json();
        
        const alertsResponse = await fetch('http://localhost:8888/api/alerts');
        const alertsData = await alertsResponse.json();
        
        setNetworkInfo({ nicName, ipAddress });
        setLogs(logsData.map(entry => ({
          date: entry.timestamp,
          systemName: entry.systemName,
          alertMessage: entry.message.split(", ")[0],
          alertContent: entry.message.split(", ")[1],
          alertValue: entry.message.split(", ")[2]
        })));
      // Filter out duplicate alerts based on the latest timestamp
        const filteredAlerts = alertsData.filter(alert => {
          return lastAlertTimestamp ? new Date(alert.timestamp) > new Date(lastAlertTimestamp) : true;
        });

        if (filteredAlerts.length > 0) {
          setLastAlertTimestamp(filteredAlerts[0].timestamp); // Update the latest alert timestamp
          setAlerts(prevAlerts => [...filteredAlerts, ...prevAlerts]); // Add new alerts to the state
          
          // Show floating alert
          showAlert(filteredAlerts[0].message);
        }
        
        console.log('Filtered Alerts data:', filteredAlerts); // Log filtered alerts data to console
      } catch (error) {
        console.error('Error fetching data:', error);
        setError('Failed to fetch data');
      } finally {
        setLoading(false);
      }
    };


    fetchData();
    const intervalId = setInterval(fetchData, refreshInterval);

    return () => clearInterval(intervalId); // Cleanup interval on component unmount
  },[refreshInterval, showAlert, lastAlertTimestamp]);

  const columns = React.useMemo(() => [
    { Header: 'Date/Time', accessor: 'date' },
    { Header: 'System Name', accessor: 'systemName' },
    { Header: 'Alert Message', accessor: 'alertMessage' },
    { Header: 'Alert Content', accessor: 'alertContent' },
    { Header: 'Alert Value', accessor: 'alertValue' }
  ], []);

  const tableInstance = useTable({ columns, data: logs }, useSortBy, usePagination);
  const initialState = { sortBy: [{ id: 'date', desc: true }] };

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    prepareRow,
    page,
    canPreviousPage,
    canNextPage,
    nextPage,
    previousPage,
    gotoPage,
    pageCount,
    state: { pageIndex }
  } = useTable({ columns, data: logs , initialState }, useSortBy, usePagination);
  
  const fetchThresholds = async () => {
    try {
      const response = await fetch('http://localhost:8888/api/thresholds');
      const data = await response.json();
      setThresholds({
        DATA_SIZE: data.DATA_SIZE,
        FLOW_COUNT: data.FLOW_COUNT,
        SRC_IP: data.SRC_IP,
        DST_IP: data.DST_IP,
        SRC_PORT: data.SRC_PORT,
        DST_PORT: data.DST_PORT,
        PROTOCOL: data.PROTOCOL
      });
      setSelectedThresholdValue(data[selectedThresholdKey]);
    } catch (error) {
      console.error('Error fetching thresholds:', error);
      setError('Failed to fetch thresholds');
    }
  };
  
  useEffect(() => {
    if (!isRendered) {
      fetchThresholds().then(() => setIsRendered(true));
    }
  }, [isRendered]);
  
   useEffect(() => {
    fetchThresholds();
  }, [selectedThresholdKey]);

  useEffect(() => {
    setSelectedThresholdValue(thresholds[selectedThresholdKey]);
  }, [selectedThresholdKey, thresholds]);
  
 
   const handleSelectChange = (event) => {
    setSelectedThresholdKey(event.target.value);
  };

  const handleThresholdValueChange = (event) => {
    setSelectedThresholdValue(event.target.value);
  };

   const handleSubmit = async (event) => {
  event.preventDefault();
  const singleThresholdUpdate = { [selectedThresholdKey]: selectedThresholdValue };

  const url = 'http://localhost:8888/api/thresholds';
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(singleThresholdUpdate),
      credentials: 'include'
    });

    if (!response.ok) {
      const errorMessage = await response.text();
      throw new Error(`Network response was not ok: ${errorMessage}`);
    }

    alert('Threshold updated successfully');
    await fetchThresholds(); // Fetch the updated thresholds after submitting
  } catch (error) {
  }
};

  const handleRefreshIntervalChange = (event) => {
    const value = event.target.value;
    if (!isNaN(value) && value > 0) {
      setRefreshInterval(Number(value) * 1000);
    }
  };
  
  const handlePageChange = (event) => {
    const pageNumber = event.target.value ? Number(event.target.value) - 1 : 0;
    if (!isNaN(pageNumber) && pageNumber >= 0 && pageNumber < pageCount) {
      gotoPage(pageNumber);
    }
  };
  




  return (
    <div className="alerts-page">
      <div className="top-panel">
        <div className="network-info">
          <div className="input-group">
            <label htmlFor="nic">NIC :</label>
            <input type="text" id="nic" value={networkInfo.nicName} readOnly />
            <label htmlFor="ip">Host IP:</label>
            <input type="text" id="ip" value={networkInfo.ipAddress} readOnly />
          </div>
        </div>
         <div className="center-panel">
        <div className="thresholds-form">
          <form onSubmit={handleSubmit}>
            <label htmlFor="threshold-select">Choose a threshold:</label>
            <select id="threshold-select" value={selectedThresholdKey} onChange={handleSelectChange}>
              {Object.keys(thresholds).map(key => (
                <option key={key} value={key}>{key}</option>
              ))}
            </select>
            <input type="text" value={selectedThresholdValue} onChange={handleThresholdValueChange} />
            <button type="submit">Update Threshold</button>
          </form>
        </div>
        <div className="refresh-interval">
          <label htmlFor="refresh-interval-input">Enter refresh interval (seconds):</label>
          <input
            type="number"
            id="refresh-interval-input"
            value={refreshInterval / 1000}
            onChange={handleRefreshIntervalChange}
            min="1"
          />
        </div>
      </div>
      </div>
      <div className="log-table-area">
        <table {...getTableProps()}>
          <thead>
            {headerGroups.map(headerGroup => (
              <tr {...headerGroup.getHeaderGroupProps()}>
                {headerGroup.headers.map(column => (
                  <th {...column.getHeaderProps(column.getSortByToggleProps())}>
                    {column.render('Header')}
                    <span>{column.isSorted ? (column.isSortedDesc ? ' 🔽' : ' 🔼') : ''}</span>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody {...getTableBodyProps()}>
            {page.map((row, i) => {
              prepareRow(row);
              return (
                <tr {...row.getRowProps()}>
                  {row.cells.map(cell => (
                    <td {...cell.getCellProps()}>{cell.render('Cell')}</td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
        <div className="pagination">
          <button onClick={() => previousPage()} disabled={!canPreviousPage}> {'<'} </button>
          <button onClick={() => nextPage()} disabled={!canNextPage}> {'>'} </button>
          <span> Page {pageIndex + 1} of {pageCount} </span>
          <input type="number" min="1" max={pageCount} defaultValue={pageIndex + 1} onChange={handlePageChange} />
        </div>
      </div>
    </div>
  );
};

export default Alerts;
