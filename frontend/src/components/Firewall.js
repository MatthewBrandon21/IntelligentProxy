import React, { useState, useEffect } from "react";
import Navbar from "./Navbar";
import Footer from "./Footer";
import axios from "axios";
import jwt_decode from "jwt-decode";
import { useNavigate } from "react-router-dom";
import { Link } from "react-router-dom";
import _ from "lodash";

const Firewall = () => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [publicKey, setPublicKey] = useState();
  const [privateKey, setPrivateKey] = useState();
  const [token, setToken] = useState("");
  const [firewall, setFirewall] = useState([]);
  const [filterFirewall, setFilterFirewall] = useState([]);
  const [search, setSearch] = useState("");
  const [transactionLogs, setTransactionLogs] = useState([]);
  const [assetId, setAssetId] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    getToken();
    getFirewall();
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

  const getFirewall = async () => {
    const response = await axiosJWT.get("http://localhost:5000/api/firewall", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    setFirewall(response.data.data.data);
    setTransactionLogs(response.data.transactionHistory);
    setAssetId(response.data.id);
  };

  const deleteFirewall = async (ipAddress) => {
    const keypair = {
      publicKey: publicKey,
      privateKey: privateKey,
    };
    await axiosJWT.post(
      `http://localhost:5000/api/firewall/delete/${ipAddress}`,
      {
        keypair: keypair,
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );
    getFirewall();
  };

  const filterData = (e) => {
    if (e.target.value !== "") {
      setSearch(e.target.value);
      const filterTable = firewall.filter((o) => o["ipAddress"].toLowerCase().includes(e.target.value.toLowerCase()) || o["source"].toLowerCase().includes(e.target.value.toLowerCase()));
      setFilterFirewall([...filterTable]);
    } else {
      setSearch(e.target.value);
      setFirewall([...firewall]);
    }
  };

  return (
    <>
      <Navbar />
      <section className="mx-6 mt-6" style={{ minHeight: "100vh" }}>
        <div className="container mt-5">
          <h1 className="has-text-centered is-size-3 has-text-weight-bold">Firewall Rule List</h1>
          <p className="has-text-centered">{`(${firewall.length} data)`}</p>
          <div className="container m-3 has-text-right has-text-centered-mobile">
            <Link to="/firewall-add" className="button is-primary">
              Add Firewall Rule
            </Link>
          </div>
          <input className="input m-4" type="text" placeholder="Search.." value={search} onChange={filterData}></input>
          <h2 className="has-text-centered is-size-4 has-text-weight-bold">Firewall Rule</h2>
          {!firewall ? (
            "No data found"
          ) : (
            <table className="table is-striped is-fullwidth is-hoverable mt-6 mb-6">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Source</th>
                  <th>Timestamp</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tfoot>
                <tr>
                  <th>IP Address</th>
                  <th>Source</th>
                  <th>Timestamp</th>
                  <th>Action</th>
                </tr>
              </tfoot>
              <tbody>
                {search.length > 0
                  ? filterFirewall.map((firewall, index) => (
                      <tr key={firewall.id}>
                        <td>{firewall.ipAddress}</td>
                        <td>{firewall.source}</td>
                        <td>{firewall.timestamp}</td>
                        <td>
                          <button onClick={() => deleteFirewall(firewall.ipAddress)} className="button is-warning m-1">
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))
                  : firewall.map((firewall, index) => (
                      <tr key={firewall.id}>
                        <td>{firewall.ipAddress}</td>
                        <td>{firewall.source}</td>
                        <td>{firewall.timestamp}</td>
                        <td>
                          <button onClick={() => deleteFirewall(firewall.ipAddress)} className="button is-warning m-1">
                            Delete
                          </button>
                        </td>
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

export default Firewall;
