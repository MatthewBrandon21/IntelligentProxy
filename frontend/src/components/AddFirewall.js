import React, { useState, useEffect } from "react";
import Footer from "./Footer";
import Navbar from "./Navbar";
import axios from "axios";
import jwt_decode from "jwt-decode";
import { useNavigate } from "react-router-dom";

const AddFirewall = () => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [publicKey, setPublicKey] = useState();
  const [privateKey, setPrivateKey] = useState();
  const [ipAddress, setIpAddress] = useState("");
  const [source, setSource] = useState("");
  const [token, setToken] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    getToken();
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

  const saveFirewall = async (e) => {
    e.preventDefault();
    const keypair = {
      publicKey: publicKey,
      privateKey: privateKey,
    };
    await axiosJWT.post(
      "http://localhost:5000/api/firewall",
      {
        keypair: keypair,
        ipAddress: ipAddress,
        source: source,
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );
    navigate("/firewall");
  };

  return (
    <>
      <Navbar />
      <section className="mx-6 mt-6" style={{ minHeight: "100vh" }}>
        <div className="container mt-5">
          <h1 className="has-text-centered is-size-3 has-text-weight-bold">Add Firewall</h1>
          <div>
            <form onSubmit={saveFirewall}>
              <div className="field">
                <label className="label">IP Address</label>
                <input className="input" type="text" placeholder="IP Address (192.168.1.1)" value={ipAddress} required onChange={(e) => setIpAddress(e.target.value)} />
              </div>
              <div className="field">
                <label className="label">Source</label>
                <input className="input" type="text" placeholder="Source (Node 1)" value={source} required onChange={(e) => setSource(e.target.value)} />
              </div>
              <div className="field mt-6">
                <button className="button is-danger">Submit</button>
              </div>
            </form>
          </div>
        </div>
      </section>
      <Footer />
    </>
  );
};

export default AddFirewall;
