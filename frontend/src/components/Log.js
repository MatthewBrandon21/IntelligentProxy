import React, { useState, useEffect } from "react";
import Navbar from "./Navbar";
import Footer from "./Footer";
import axios from "axios";
import jwt_decode from "jwt-decode";
import { useNavigate } from "react-router-dom";
import { Link } from "react-router-dom";
import _ from "lodash";

const Log = () => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [publicKey, setPublicKey] = useState();
  const [privateKey, setPrivateKey] = useState();
  const [token, setToken] = useState("");
  const [log, setLog] = useState([]);
  const [filterLog, setFilterLog] = useState([]);
  const [search, setSearch] = useState("");
  const [transactionLogs, setTransactionLogs] = useState([]);
  const [assetId, setAssetId] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    getToken();
    getLog();
  }, []);

  const getToken = async () => {
    try {
      let accessToken = localStorage.getItem("accessToken");
      let email = localStorage.getItem("email");
      let publicKey = localStorage.getItem("publicKey");
      let privateKey = localStorage.getItem("privateKey");
      let username = localStorage.getItem("username");
      if (accessToken === null || email === null || publicKey === null || privateKey === null || username === null) {
        navigate("/");
      }
      setUsername(username);
      setEmail(email);
      setToken(accessToken);
      setPublicKey(publicKey);
      setPrivateKey(privateKey);
    } catch (error) {
      if (error.response) {
        navigate("/");
      }
    }
  };

  const axiosJWT = axios.create();

  const getLog = async () => {
    const response = await axiosJWT.get("http://localhost:5000/api/log", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    setLog(response.data.data.data);
    setTransactionLogs(response.data.transactionHistory);
    setAssetId(response.data.id);
  };

  const filterData = (e) => {
    if (e.target.value !== "") {
      setSearch(e.target.value);
      const filterTable = log.filter((o) => o["ipAddress"].toLowerCase().includes(e.target.value.toLowerCase()) || o["source"].toLowerCase().includes(e.target.value.toLowerCase()));
      setFilterLog([...filterTable]);
    } else {
      setSearch(e.target.value);
      setLog([...log]);
    }
  };

  return (
    <>
      <Navbar />
      <section className="mx-6 mt-6" style={{ minHeight: "100vh" }}>
        <div className="container mt-5">
          <h1 className="has-text-centered is-size-3 has-text-weight-bold">Log Data List</h1>
          <p className="has-text-centered">{`(${log.length} data)`}</p>
          <input className="input m-4" type="text" placeholder="Search.." value={search} onChange={filterData}></input>
          <h2 className="has-text-centered is-size-4 has-text-weight-bold">Log Data</h2>
          {!log ? (
            "No data found"
          ) : (
            <table className="table is-striped is-fullwidth is-hoverable mt-6 mb-6">
              <thead>
                <tr>
                  <th>Node Name</th>
                  <th>Message</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tfoot>
                <tr>
                  <th>Node Name</th>
                  <th>Message</th>
                  <th>Timestamp</th>
                </tr>
              </tfoot>
              <tbody>
                {search.length > 0
                  ? filterLog.map((log, index) => (
                      <tr key={log.id}>
                        <td>{log.nodeName}</td>
                        <td>{log.message}</td>
                        <td>{log.timestamp}</td>
                      </tr>
                    ))
                  : log.map((log, index) => (
                      <tr key={log.id}>
                        <td>{log.nodeName}</td>
                        <td>{log.message}</td>
                        <td>{log.timestamp}</td>
                      </tr>
                    ))}
              </tbody>
            </table>
          )}
          <h2 className="has-text-centered is-size-4 has-text-weight-bold">Transaction History</h2>
          <h3 className="has-text-centered is-size-6">Asset ID : {assetId}</h3>
          {!transactionLogs ? (
            "No data found"
          ) : (
            <table className="table is-striped is-fullwidth is-hoverable mt-6 mb-6">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Operation</th>
                  <th>Metadata</th>
                </tr>
              </thead>
              <tfoot>
                <tr>
                  <th>ID</th>
                  <th>Operation</th>
                  <th>Metadata</th>
                </tr>
              </tfoot>
              <tbody>
                {transactionLogs.map((data, index) => (
                  <tr key={data.id}>
                    <td>{data.id}</td>
                    <td>{data.operation}</td>
                    <td>
                      {data.metadata.data.map((data) => (
                        <p>{data.ipAddress}</p>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      <Footer />
    </>
  );
};

export default Log;
