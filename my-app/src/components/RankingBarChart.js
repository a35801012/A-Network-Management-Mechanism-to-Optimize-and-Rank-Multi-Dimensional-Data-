import React, { useState, useEffect, useRef } from 'react';
import Highcharts from 'highcharts';
import HighchartsReact from 'highcharts-react-official';

// Utility function to format timestamp for API
const formatTimestampForApi = (timestamp) => {
  const date = new Date(timestamp);
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}-${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
};

const RankingBarChart = ({ rankAttribute, topN, startTime, endTime, onBarClick }) => {
  const [rankingData, setRankingData] = useState([]);
  const chartRef = useRef(null); // Create a ref for the chart
  
  const getTitle = () => {
    if (startTime && endTime) {
      return `Time Range Ranking by ${rankAttribute}`;
    }
    return `Ranking by ${rankAttribute}`;
  };

  
  useEffect(() => {
    if (chartRef.current) {
      const chart = chartRef.current.chart;
      chart.series[0].setData(rankingData); 
      chart.setTitle({ text: getTitle() }); // 正确调用 getTitle 并传入参数
    }
  }, [rankingData, startTime, endTime]);
  
  useEffect(() => {
  const fetchData = async () => {
    let url = `http://localhost:8888/api/rank?attribute=${rankAttribute}&topN=${topN}`;
    if (startTime && endTime) {
      url = `http://localhost:8888/api/time-range-ranking?attribute=${rankAttribute}&startTime=${startTime}&endTime=${endTime}&topN=${topN}`;
    }

    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      const json = await response.json();
      
      // 这里我们需要确定json.flows 或 json.rankings 是数组类型
      if (json.flows && Array.isArray(json.flows)) {
        const formattedData = json.flows.map((item) => ({
          name: `${item.srcIP}:${item.srcPort} (${item.srcCountry}) -> ${item.dstIP}:${item.dstPort} (${item.dstCountry})`,
          y: parseFloat(item.totalData || item.flowCount),
          originalData: item
        }));
        setRankingData(formattedData);
      } else if (json.rankings && Array.isArray(json.rankings)) {
        const formattedData = json.rankings.map((item, index) => ({
          name: `Rank ${index + 1}: ${item.value} (${item.country})`,
          y: parseFloat(item.count),
        }));
        setRankingData(formattedData);
      } else {
        // 如果json.flows 或 json.rankings 不是数组或不存在这些字段，设置为空数组
        console.error('Unexpected JSON structure:', json);
        setRankingData([]);
      }
    } catch (error) {
      console.error('Error fetching ranking data:', error);
      setRankingData([]); // 在出现异常时设置为空数组，确保图表不会因错误数据崩溃
    }
  };

  fetchData(); // Fetch data on mount and when rankAttribute or topN changes
  
  if (!startTime && !endTime) {
      const intervalId = setInterval(fetchData, 1000); // 未指定时间时，每5秒刷新数据
      return () => clearInterval(intervalId);
    }
  }, [rankAttribute, topN, startTime, endTime]);



  


  const yAxisTitle = rankAttribute === 'flow' ? 'Total data (bytes)' : 'Count';

  const options = {
    chart: {
      type: 'bar',
    },
    title: {
       text: getTitle() 
    },
    xAxis: {
      categories: rankingData.map(item => item.name),
      crosshair: true
    },
    yAxis: {
      min: 0,
      title: {
        text: yAxisTitle
      }
    },
    tooltip: {
      valueSuffix: ' bytes'
    },
     plotOptions: {
      bar: {
        dataLabels: {
          enabled: true
        },
        point: {
          events: {
            click: function () {
              const pointIndex = this.index;
              const clickedData = rankingData[pointIndex];
              console.log('Clicked data:', clickedData);
              onBarClick(clickedData.originalData, startTime, endTime);
            }
          }
        }
      }
    },
    legend: {
      layout: 'vertical',
      align: 'right',
      verticalAlign: 'top',
      floating: true,
      borderWidth: 1,
      backgroundColor: Highcharts.defaultOptions.legend.backgroundColor || '#FFFFFF',
      shadow: true
    },
    credits: {
      enabled: false
    },
    series: [{
      name: 'Data',
      data: rankingData
    }]
  };

  return (
    <HighchartsReact highcharts={Highcharts} options={options} ref={chartRef} />

  );
};

export default RankingBarChart;

