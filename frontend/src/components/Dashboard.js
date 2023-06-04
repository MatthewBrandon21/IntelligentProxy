import React, { useState, useEffect } from "react";
import Navbar from "./Navbar";
import Footer from "./Footer";
import axios from "axios";
import jwt_decode from "jwt-decode";
import { useNavigate } from "react-router-dom";

const Dashboard = () => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [publicKey, setPublicKey] = useState();
  const [privateKey, setPrivateKey] = useState();
  const [token, setToken] = useState("");
  const [user, setUser] = useState([]);
  const [firewall, setFirewall] = useState([]);
  const [log, setLog] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    getToken();
    getUser();
    getFirewall();
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

  const getUser = async () => {
    const response = await axiosJWT.get("http://localhost:5000/api/user", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    setUser(response.data.data.data);
  };

  const getFirewall = async () => {
    const response = await axiosJWT.get("http://localhost:5000/api/firewall", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    setFirewall(response.data.data.data);
  };

  const getLog = async () => {
    const response = await axiosJWT.get("http://localhost:5000/api/log", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    setLog(response.data.data.data);
  };

  return (
    <>
      <Navbar />
      <section className="mx-6	mb-6" style={{ minHeight: "100vh" }}>
        <div className="container mt-6 has-text-centered">
          <h1 className="is-size-3">Welcome Back!</h1>
          <h2>
            {email} - {username}
          </h2>
        </div>
        <div className="container">
          <div className="is-centered columns mt-6 has-text-centered">
            <div className="column">
              <div className="box has-background-info">
                <h2 className="is-size-5 has-text-weight-bold">{user.length}</h2>
                <p>Users</p>
              </div>
            </div>
            <div className="column">
              <div className="box has-background-success">
                <h2 className="is-size-5 has-text-weight-bold">{firewall.length}</h2>
                <p>Firewall Rules</p>
              </div>
            </div>
            <div className="column">
              <div className="box has-background-warning">
                <h2 className="is-size-5 has-text-weight-bold">{log.length}</h2>
                <p>Logs</p>
              </div>
            </div>
          </div>
          <div className="box mt-6">
            <h2 className="is-size-5 has-text-weight-bold">System Documentation</h2>
            <a className="button mt-3" href="https://github.com/MatthewBrandon21/IntelligentProxy">
              {" "}
              Github{" "}
            </a>
            <h2 className="is-size-6 has-text-weight-bold mt-4">This is your credentials for setup your nodes</h2>
            <h3>publicKey : {publicKey}</h3>
            <h3>privateKey : {privateKey}</h3>
          </div>
        </div>
      </section>
      <Footer />
    </>
  );
};

export default Dashboard;
