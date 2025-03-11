import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './DataStructure.css';

const DataStructure = ({ externalFlow }) => {
  const [form, setForm] = useState({
    srcIP: '',
    dstIP: '',
    srcPort: '',
    dstPort: '',
    protocol: '',
    startTime: '',
    endTime: '',
    nicName: '',
    ipAddress: ''
  });

  const [data, setData] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [modalData, setModalData] = useState(null);

  useEffect(() => {
    if (externalFlow) {
      setModalData(externalFlow);
      setShowModal(true);
      setForm((prevForm) => ({
        ...prevForm,
        srcIP: externalFlow.srcIP || '',
        dstIP: externalFlow.dstIP || '',
        srcPort: externalFlow.srcPort || '',
        dstPort: externalFlow.dstPort || '',
        protocol: externalFlow.protocol || ''
      }));
    } else {
      setShowModal(false);
    }
  }, [externalFlow]);
  
  
  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prevForm) => ({
      ...prevForm,
      [name]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    const params = {
      src_ip: form.srcIP || 'ALL',
      dst_ip: form.dstIP || 'ALL',
      src_port: form.srcPort || 'ALL',
      dst_port: form.dstPort || 'ALL',
      protocol: form.protocol || 'ALL',
      start_time: form.startTime || 'start_time',
      end_time: form.endTime || 'end_time',
      nic_name: form.nicName || 'ALL',
      ip_address: form.ipAddress || 'ALL'
    };

    try {
      const response = await axios.get('http://localhost:8888/api/query', { params });
      const filteredData = (response.data.flows || []).filter(flow => flow.data && flow.data.length > 0);
      setData(filteredData);
    } catch (error) {
      console.error('Error querying data:', error);
      setData([]);
    }
  };

  const handleShowModal = (flow) => {
    setModalData(flow);
    setShowModal(true);
  };

  const handleCloseModal = () => {
    setShowModal(false);
    setModalData(null);
  };

  useEffect(() => {
    const fetchNetworkInfo = async () => {
      try {
        const networkResponse = await fetch('http://localhost:8888/');
        const [nicName, ipAddress] = await networkResponse.text().then(text => text.trim().split('\n'));
        setForm((prevForm) => ({
          ...prevForm,
          nicName,
          ipAddress
        }));
      } catch (error) {
        console.error('Error fetching network info:', error);
      }
    };

    fetchNetworkInfo();
  }, []);

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <div className="network-row">
          <div className="input-label">
            <label>NIC :</label>
            <input type="text" name="nicName" value={form.nicName} readOnly />
          </div>
          <div className="input-label">
            <label>Host IP: </label>
            <input type="text" name="ipAddress" value={form.ipAddress} readOnly />
          </div>
        </div>
        <div className="query-params">
          <div className="flow-group">
            <label>Source IP:</label>
            <input type="text" name="srcIP" value={form.srcIP} onChange={handleChange} placeholder="Default is ALL" />
          </div>
          <div className="flow-group">
            <label>Source Port:</label>
            <input type="text" name="srcPort" value={form.srcPort} onChange={handleChange} placeholder="Default is ALL" />
          </div>
          <div className="flow-group">
            <label>Destination IP:</label>
            <input type="text" name="dstIP" value={form.dstIP} onChange={handleChange} placeholder="Default is ALL" />
          </div>
          <div className="flow-group">
            <label>Destination Port:</label>
            <input type="text" name="dstPort" value={form.dstPort} onChange={handleChange} placeholder="Default is ALL" />
          </div>
          <div className="flow-group">
            <label>Protocol:</label>
            <input type="text" name="protocol" value={form.protocol} onChange={handleChange} placeholder="Default is ALL" />
          </div>
        </div>
        <div className="time-row">
          <div className="input-label">
            <label>Start Time: </label>
            <input type="text" name="startTime" value={form.startTime} onChange={handleChange} placeholder="YYYY-MM-DD HH:MM:SS" />
          </div>
          <div className="input-label">
            <label>End Time: </label>
            <input type="text" name="endTime" value={form.endTime} onChange={handleChange} placeholder="YYYY-MM-DD HH:MM:SS" />
          </div>
        </div>
        <div className="button-row">
          <button type="submit">Submit Query</button>
        </div>
      </form>

      <div className="results">
        {data.length > 0 ? (
          <div className="results-scroll">
            {data.map((flow, index) => (
              <div key={index} className="flow-result">
                <button className="flow-button" onClick={() => handleShowModal(flow)}>
                  {`Flow ${index + 1}: ${flow.srcIP}:${flow.srcPort} (${flow.srcCountry}) -> ${flow.dstIP}:${flow.dstPort} (${flow.dstCountry}) [${flow.protocol}]`}
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p>No data available.</p>
        )}
      </div>

      {showModal && (
        <div className="modal">
          <div className="modal-content">
            <span className="close" onClick={handleCloseModal}>&times;</span>
            <h2>Flow Details</h2>
            {modalData && (
              <>
                <p><strong>Source IP:</strong> {modalData.srcIP}</p>
                <p><strong>Source Port:</strong> {modalData.srcPort}</p>
                <p><strong>Source Country:</strong> {modalData.srcCountry}</p>
                <p><strong>Destination IP:</strong> {modalData.dstIP}</p>
                <p><strong>Destination Port:</strong> {modalData.dstPort}</p>
                <p><strong>Destination Country:</strong> {modalData.dstCountry}</p>
                <p><strong>Protocol:</strong> {modalData.protocol}</p>
                <div className="data-points">
                  <h3>Data Points</h3>
                  <div className="data-points-scroll">
                    {modalData.data && modalData.data.length > 0 ? (
                      modalData.data.map((dataPoint, idx) => (
                        <div key={idx} className="data-point">
                          <p><strong>Timestamp:</strong> {dataPoint.timestamp}</p>
                          <p><strong>Data Size:</strong> {dataPoint.singleDataSize} bytes</p>
                        </div>
                      ))
                    ) : (
                      <p>No data points available.</p>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default DataStructure;

