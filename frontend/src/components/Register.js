import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const Register = () => {
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");
  const navigate = useNavigate();

  const Register = async (e) => {
    e.preventDefault();
    try {
      await axios.post("http://localhost:5000/api/auth/signup", {
        username: username,
        email: email,
        password: password,
      });
      navigate("/");
    } catch (error) {
      if (error.response) {
        setMsg("Register Not Valid");
      }
    }
  };

  return (
    <section className="hero has-background-dark is-fullheight is-fullwidth">
      <div className="hero-body">
        <div className="container">
          <div className="columns is-centered">
            <div className="column is-4-desktop">
              <form onSubmit={Register} className="box">
                <h1 className="has-text-centered is-size-5">
                  <strong>Intelligent Proxy Admin Panel</strong>
                </h1>
                <p className="has-text-centered">{msg}</p>
                <div className="field mt-5">
                  <label className="label">Email</label>
                  <div className="controls">
                    <input type="text" className="input" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
                  </div>
                </div>
                <div className="field mt-5">
                  <label className="label">Username</label>
                  <div className="controls">
                    <input type="text" className="input" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
                  </div>
                </div>
                <div className="field mt-5">
                  <label className="label">Password</label>
                  <div className="controls">
                    <input type="password" className="input" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
                  </div>
                </div>
                <div className="field mt-5">
                  <button className="button is-info is-fullwidth">Register</button>
                </div>
                <div className="field mt-5">
                  <p className="has-text-centered">
                    Have account? <a href="/">Login</a>
                  </p>
                </div>
                <div className="field mt-5">
                  <p className="has-text-centered is-size-7">Matthew Brandon Dani - 2023</p>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Register;
