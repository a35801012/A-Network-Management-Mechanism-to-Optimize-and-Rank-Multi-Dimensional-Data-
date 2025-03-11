//4
//Dashboard.js
import React, { useState, useEffect, useRef } from 'react';
import Highcharts from 'highcharts';
import HighchartsReact from 'highcharts-react-official';
import RankingBarChart from './RankingBarChart';

import { BrowserRouter as Router, Route, Routes, Link } from 'react-router-dom';
import Alerts from './Alerts'; // Import the alerts component
import DataStructure from './DataStructure'; // Import the data structure component


import './Dashboard.css';

// This should be placed before any charts are initialized.
Highcharts.setOptions({
  time: {
    useUTC: false // Use local time
  }
});


const formatTimestamp = (timestamp) => {
  const date = new Date(timestamp);
  // Combine date and time in the format 'YYYY-MM-DD HH:MM:SS'
  return date.toLocaleDateString('en-CA') + ' ' + date.toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
};




const TrafficChart = ({ trafficData, setTrafficData, intervalSeconds, setStartTime, setEndTime, chartComponentRef}) => {

  const [totalTrafficSize, setTotalTrafficSize] = useState(0);
  
  const handleZoomReset = () => {
    setStartTime(null);
    setEndTime(null);
    // Other state updates might be necessary depending on how your components are structured
  };

  useEffect(() => {
    const interval = setInterval(() => {

        fetch('http://localhost:8888/api/traffic')
          .then((res) => res.json())
          .then((data) => {
            const currentTime = new Date();
            const point = [currentTime.getTime(), data.trafficSize];
            setTrafficData((prevData) => [...prevData, point]);
            setTotalTrafficSize(data.totalTrafficSize);
       
          })
          .catch((error) => console.error('Error fetching traffic data:', error));
      
    }, intervalSeconds * 1000);
    return () => clearInterval(interval);
  }, [intervalSeconds,  setTotalTrafficSize]);


  useEffect(() => {
    if (chartComponentRef.current && chartComponentRef.current.chart) {
      chartComponentRef.current.chart.reflow();
    }
  }, [setStartTime, setEndTime]);
  
  
  const options = {
    chart: {
    type: 'area',
    zoomType: 'x',
    resetZoomButton: {
      position: {
        align: 'right', // Align button to the right
        verticalAlign: 'top', // Position at the top
        x: -10,
        y: 10
      }
    }
},
    theme: {
          fill: 'white',
          stroke: 'silver',
          r: 0,
          states: {
            hover: {
              fill: '#41739D',
              style: {
                color: 'white',
              },
            },
          },
        },
    title: { text: 'Network Traffic' },
    xAxis: {
    events: {
            setExtremes: function (e) {
                if(typeof e.min == 'undefined' && typeof e.max == 'undefined'){
                     handleZoomReset(); 
                } 
            }
    },
      type: 'datetime',
      dateTimeLabelFormats: {
        millisecond: '%H:%M:%S.%L',
        second: '%H:%M:%S',
        minute: '%H:%M',
        hour: '%H:%M',
        day: '%e. %b',
        week: '%e. %b',
        month: '%b \'%y',
        year: '%Y'
      }
    },
    yAxis: {
      title: { text: 'Traffic Size' }
    },
    series: [{
      name: 'Traffic Size',
      data: trafficData,
      tooltip: { valueDecimals: 2 }
    }],
    rangeSelector: {
      buttonTheme: {
        fill: 'green',
        style: { color: 'white' },
        states: {
          hover: {
            fill: 'darkgreen',
            style: { color: 'white' }
          },
          select: {
            fill: 'darkgreen',
            style: { color: 'white' }
          }
        }
      },
      buttons: [
        { type: 'hour', count: 1, text: '1h' },
        { type: 'day', count: 1, text: '1D' },
        { type: 'all', text: 'All' }
      ],
      inputEnabled: false,
      selected: 1
    },
    plotOptions: {
      area: {
        fillColor: {
          linearGradient: { x1: 0, y1: 0, x2: 0, y2: 1 },
          stops: [
            [0, Highcharts.getOptions().colors[0]],
            [1, Highcharts.color(Highcharts.getOptions().colors[0]).setOpacity(0).get('rgba')]
          ]
        },
        marker: { radius: 2 },
        lineWidth: 1,
        states: { hover: { lineWidth: 1 } },
        threshold: null
      }
    }
  };
  
  options.chart.events = {
    selection: function (event) {
      if (event.xAxis) {
        const xAxis = event.xAxis[0];
        // Call the passed in setStartTime and setEndTime with the selected range
        setStartTime(xAxis.min);
        setEndTime(xAxis.max);
      }
      return true; // Return true to zoom the chart
    }
  };
  
  options.chart.events.selection = function (event) {
    if (event.xAxis) {
      const xAxis = event.xAxis[0];
      const formattedStartTime = formatTimestamp(xAxis.min);
      const formattedEndTime = formatTimestamp(xAxis.max);
      setStartTime(formattedStartTime);
      setEndTime(formattedEndTime);
    }
    return true;
  };
  
  

  return (
    <HighchartsReact
      highcharts={Highcharts}
      options={options}
      ref={chartComponentRef}
    />
  );
};

const Dashboard = () => {
  const [networkInfo, setNetworkInfo] = useState({ nicName: '', ipAddress: '' });
  const [intervalSeconds, setIntervalSeconds] = useState(10); // Default interval
  
  const [trafficData, setTrafficData] = useState([]);  // 提升 trafficData 狀態至此
  const [totalTrafficSize, setTotalTrafficSize] = useState(0);
  
  const [startTime, setStartTime] = useState(null);
  const [endTime, setEndTime] = useState(null);
  
  const [userStartTime, setUserStartTime] = useState('');
  const [userEndTime, setUserEndTime] = useState('');
  
   const chartComponentRef = useRef(null);
   
   const [rankAttribute, setRankAttribute] = useState('flow');  // 默认按照源IP排序
   const [rankingResults, setRankingResults] = useState([]);
  const [topN, setTopN] = useState(5);  // 默认显示前5名
   const [externalFlow, setExternalFlow] = useState(null);
    const [isBarClicked, setIsBarClicked] = useState(false);

  const handleBarClick = async (clickedData, barStartTime, barEndTime) => {
  try {
    const params = new URLSearchParams({
      src_ip: clickedData.srcIP,
      dst_ip: clickedData.dstIP,
      src_port: clickedData.srcPort,
      dst_port: clickedData.dstPort,
      protocol: clickedData.protocol,
      start_time: barStartTime, // 将 RankingBarChart 的 start_time 传递给查询
      end_time: barEndTime // 将 RankingBarChart 的 end_time 传递给查询
    }).toString();
    console.log('Query params:', params); // 调试信息

    const response = await fetch(`http://localhost:8888/api/query?${params}`);
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    const queryResult = await response.json();
    console.log('Query result:', queryResult); // 调试信息
    setExternalFlow(queryResult.flows[0]); // 将第一个流的数据设置为 externalFlow
    setIsBarClicked(true);
  } catch (error) {
    console.error('Failed to fetch flow details:', error);
  }
};





  // Function to handle the change in interval
  const handleIntervalChange = (event) => {
  const newInterval = parseInt(event.target.value, 10);
  if (!isNaN(newInterval) && newInterval > 0) {
    setIntervalSeconds(newInterval);
    
    // Send the new interval to the backend
    fetch('http://localhost:8888/api/setInterval', {
      method: 'POST',
      body: newInterval.toString()
    })
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      console.log('Interval updated on backend');
    })
    .catch(error => {
      console.error('Failed to update interval:', error);
    });
  } else {
    console.error('Invalid input for interval. Please enter a positive number.');
  }
};

  
  const formatTimestampForApi = (timestamp) => {
  const date = new Date(timestamp);
  // Format the date and time as 'YYYY-MM-DD-HH:mm:ss'
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}-${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
};

const handleZoom = () => {
  // Parse user input times
  const parsedStart = Date.parse(userStartTime);
  const parsedEnd = Date.parse(userEndTime);
  
  const chart = chartComponentRef.current.chart;
    chart.xAxis[0].setExtremes(parsedStart, parsedEnd);

  // Check if times are valid
  if (!isNaN(parsedStart) && !isNaN(parsedEnd) && parsedStart < parsedEnd) {
    // Format times in "YYYY-MM-DD-HH:mm:ss" format for the API
    const formattedStartTime = formatTimestampForApi(parsedStart);
    const formattedEndTime = formatTimestampForApi(parsedEnd);
    setStartTime(userStartTime);
    setEndTime(userEndTime);

    // Construct the URL for the API request
    const startTimeEncoded = encodeURIComponent(formattedStartTime);
    const endTimeEncoded = encodeURIComponent(formattedEndTime);
    const rankUrl = `http://localhost:8888/api/time-range-ranking?attribute=${rankAttribute}&topN=${topN}&startTime=${startTimeEncoded}&endTime=${endTimeEncoded}`;

    // Fetch the ranking data for the given time range
    fetch(rankUrl)
      .then((res) => {
        if (!res.ok) {
          throw new Error(`HTTP error! Status: ${res.status}`);
        }
        return res.json();
      })
      .then((data) => {
        // Handle the received ranking data here
        console.log('Time Range Ranking Data:', data);
        setRankingResults(data); // Update the state with the received data
      })
      .catch((error) => {
        // Handle errors in fetching data here
        console.error('Error fetching time range ranking data:', error);
      });
  } else {
    // Handle invalid input
    console.error('Invalid input for start/end time. Please enter times in the format "YYYY-MM-DD HH:MM:SS".');
  }
};
  
  useEffect(() => {
    if (startTime && endTime) {
      setUserStartTime(formatTimestamp(startTime));
      setUserEndTime(formatTimestamp(endTime));
      const startTimeEncoded = encodeURIComponent(startTime);
    const endTimeEncoded = encodeURIComponent(endTime);
    const rankUrl = `http://localhost:8888/api/time-range-ranking?attribute=${rankAttribute}&topN=${topN}&startTime=${startTimeEncoded}&endTime=${endTimeEncoded}`;

    // Fetch the ranking data for the given time range
    fetch(rankUrl)
      .then((res) => {
        if (!res.ok) {
          throw new Error(`HTTP error! Status: ${res.status}`);
        }
        return res.json();
      })
      .then((data) => {
        // Handle the received ranking data here
        console.log('Time Range Ranking Data:', data);
        setRankingResults(data); // Update the state with the received data
      })
      .catch((error) => {
        // Handle errors in fetching data here
        console.error('Error fetching time range ranking data:', error);
      });
  }
}, [rankAttribute, topN, startTime, endTime]);

  useEffect(() => {
    // Fetch network info
    fetch('http://localhost:8888/')
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.text();
      })
      .then((data) => {
        const [nicName, ipAddress] = data.trim().split('\n');
        setNetworkInfo({ nicName, ipAddress });
      })
      .catch((error) => {
        console.error('Error fetching data from C server:', error);
      });

    // Fetch intervalSeconds value
    fetch('http://localhost:8888/api/traffic')
      .then((response) => response.json())
      .then((data) => {
        setIntervalSeconds(data.intervalSeconds);
      })
      .catch((error) => {
        console.error('Error fetching interval seconds from server:', error);
      });
  }, []);
  
  useEffect(() => {
    // Moved fetch call for total traffic size into this useEffect
    const interval = setInterval(() => {
      fetch('http://localhost:8888/api/traffic')
        .then((res) => res.json())
        .then((data) => {
          const newPoint = [new Date().getTime(), data.trafficSize];
          setTrafficData(prevData => [...prevData, newPoint]);
          setTotalTrafficSize(data.totalTrafficSize);
        })
        .catch((error) => console.error('Error fetching total traffic size:', error));
    }, 1000);
    return () => clearInterval(interval);
    // Removed intervalSeconds from dependency array since it's not used in this effect
  }, [intervalSeconds, setTrafficData]);
  
  useEffect(() => {
    if (rankAttribute && topN > 0) {
      fetch(`http://localhost:8888/api/rank?attribute=${rankAttribute}&topN=${topN}`)
        .then(res => res.json())
        .then(data => {
          // 假设返回数据是排名列表，你可以存储这些数据或直接使用
          console.log('Ranking Data:', data);
        })
        .catch(error => console.error('Error fetching ranking data:', error));
    }
  }, [rankAttribute, topN]);
  
  useEffect(() => {
  const fetchRankingData = async () => {
    try {
      const response = await fetch(`http://localhost:8888/api/rank?attribute=${rankAttribute}&topN=${topN}`);
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      const json = await response.json();
      console.log("Received ranking data:", json); // Add this to log the actual received data
      setRankingResults(json.ranking); // Assuming the JSON has a "ranking" key that contains an array of rank data
    } catch (error) {
      console.error('Error fetching ranking data:', error);
    }
  };

  fetchRankingData();
}, [rankAttribute, topN]);// Dependencies array ensures this effect runs when rankAttribute or topN changes




useEffect(() => {
    if (rankAttribute && topN > 0) {
    const startTimeEncoded = encodeURIComponent(startTime);
    const endTimeEncoded = encodeURIComponent(endTime);
      fetch(`http://localhost:8888/api/time-range-ranking?attribute=${rankAttribute}&topN=${topN}&startTime=${startTimeEncoded}&endTime=${endTimeEncoded}`)
        .then(res => res.json())
        .then(data => {
          // 假设返回数据是排名列表，你可以存储这些数据或直接使用
          console.log('Ranking Data:', data);
        })
        .catch(error => console.error('Error fetching ranking data:', error));
    }
  }, [rankAttribute, topN, startTime, endTime]);

useEffect(() => {
    if (rankAttribute && topN > 0 && startTime && endTime) {
      const startTimeFormatted = formatTimestampForApi(new Date(startTime));
      const endTimeFormatted = formatTimestampForApi(new Date(endTime));
      const rankUrl = `http://localhost:8888/api/time-range-ranking?attribute=${rankAttribute}&topN=${topN}&startTime=${startTimeFormatted}&endTime=${endTimeFormatted}`;
      fetch(rankUrl)
        .then((res) => res.json())
        .then((data) => {
          // Transform the data here if needed to fit the Highcharts series format
          setRankingResults(data); // assuming `data` is an array of the expected objects
        })
        .catch((error) => console.error('Error fetching time range ranking data:', error));
    }
  }, [rankAttribute, topN, startTime, endTime]); // Run the effect when any dependency changes
 
  useEffect(() => {
    if (isBarClicked) {
      setTimeout(() => {
        setIsBarClicked(false);
        setExternalFlow(null);
      }, 8000); // Set timeout to reset the state after 1 second
    }
  }, [isBarClicked]);
 
  return (
  <Router>
    <div className="dashboard">
      <div className="sidebar">
        <Link to="/"><img src="Logo.png" alt="Home" id="home" /></Link>
        <Link to="/alerts"><img src="Logo2.png" alt="Alerts" id="alerts" /></Link>
        <Link to="/data-structure"><img src="Logo3.png" alt="Data Structure" id="data-structure" /></Link>
      </div>
      <div className="main-content">
        <Routes>
          <Route path="/" element={
          <React.Fragment>
            <div className="network-info">
              <div className="input-group">
                <label htmlFor="nic">NIC :</label>
                <input type="text" id="nic" value={networkInfo.nicName} readOnly />
                <label htmlFor="ip">Host IP:</label>
                <input type="text" id="ip" value={networkInfo.ipAddress} readOnly />
                {intervalSeconds !== null && (
                  <div className="interval-display">
                    <label htmlFor="intervalSeconds">Interval Seconds:</label>
                    <input
                      type="number" // Change type to number for proper validation
                      id="intervalSeconds"
                      value={intervalSeconds}
                      onChange={handleIntervalChange} // Set the onChange handler
                      min="1" // Optional: Ensure only positive numbers can be entered
                    />
                  </div>
                )}
                <div id="totalTrafficSize">Total Traffic Size: {totalTrafficSize} bytes</div>
                <div className="time-range-container">
                  <label>Start Time:</label>
                  <input
                    type="text"
                    value={userStartTime}
                    onChange={(e) => setUserStartTime(e.target.value)}
                    placeholder="YYYY-MM-DD HH:MM:SS"
                  />
                  
                  <label>End Time:</label>
                  <input
                    type="text"
                    value={userEndTime}
                    onChange={(e) => setUserEndTime(e.target.value)}
                    placeholder="YYYY-MM-DD HH:MM:SS"
                  />
                  <button onClick={handleZoom}>Zoom</button>
                </div>
                
                 <div className="ranking-section">
        <label htmlFor="rankAttribute">Rank By:</label>
        <select id="rankAttribute" value={rankAttribute} onChange={e => setRankAttribute(e.target.value)}>
          <option value="src_ip">Source IP</option>
          <option value="dst_ip">Destination IP</option>
          <option value="src_port">Source Port</option>
          <option value="dst_port">Destination Port</option>
          <option value="protocol">Protocol</option>
          <option value="flow">Flow</option>
          <option value="flowcount">Flow Count</option>
        </select>
        <label htmlFor="topN">Top N:</label>
        <input type="number" id="topN" value={topN} min="1" onChange={e => setTopN(e.target.value)} />
        
      </div>
                
              </div>
              <div className="chart-wrapper">
                <TrafficChart
                  trafficData={trafficData}
                  setTrafficData={setTrafficData}
                  intervalSeconds={intervalSeconds}
                  setStartTime={setStartTime}
                  setEndTime={setEndTime}
                  chartComponentRef={chartComponentRef}
                />
              </div>
              <div className="ranking-chart">
                <RankingBarChart
                  rankAttribute={rankAttribute} 
                  topN={topN} 
                  rankingData={rankingResults} // Pass the rankingResults to RankingBarChart
                  startTime={startTime}
                  endTime={endTime}
                  onBarClick={handleBarClick}
                />
              </div>
            </div>
             {isBarClicked && externalFlow && <DataStructure externalFlow={externalFlow} />}
            </React.Fragment>
          } exact />
          <Route path="/alerts" element={<Alerts />} />
    	  <Route path="/data-structure" element={<DataStructure />} />
          
        </Routes>
      </div>
    </div>
  </Router>
);


};

export default Dashboard;
