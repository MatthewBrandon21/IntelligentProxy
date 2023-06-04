import React, { useState, useEffect } from "react";
import Navbar from "./Navbar";
import Footer from "./Footer";
import axios from "axios";
import jwt_decode from "jwt-decode";
import { useNavigate } from "react-router-dom";
import _ from "lodash";

const Users = () => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [publicKey, setPublicKey] = useState();
  const [privateKey, setPrivateKey] = useState();
  const [token, setToken] = useState("");
  const [users, setUsers] = useState([]);
  const [filterUsers, setFilterUsers] = useState([]);
  const [search, setSearch] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    getToken();
    getUsers();
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

  const getUsers = async () => {
    const response = await axiosJWT.get("http://localhost:5000/api/user", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    setUsers(response.data.data.data);
  };

  const deleteUser = async (username) => {
    await axiosJWT.get(`http://localhost:5000/api/user/delete/${username}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    getUsers();
  };

  const filterData = (e) => {
    if (e.target.value !== "") {
      setSearch(e.target.value);
      const filterTable = users.filter((o) => o["email"].toLowerCase().includes(e.target.value.toLowerCase()) || o["username"].toLowerCase().includes(e.target.value.toLowerCase()));
      setFilterUsers([...filterTable]);
    } else {
      setSearch(e.target.value);
      setUsers([...users]);
    }
  };

  return (
    <>
      <Navbar />
      <section className="mx-6 mt-6" style={{ minHeight: "100vh" }}>
        <div className="container mt-5">
          <h1 className="has-text-centered is-size-3 has-text-weight-bold">User List</h1>
          <p className="has-text-centered">{`(${users.length} data)`}</p>
          <input className="input m-4" type="text" placeholder="Search.." value={search} onChange={filterData}></input>
          {!users ? (
            "No data found"
          ) : (
            <table className="table is-striped is-fullwidth is-hoverable mt-6 mb-6">
              <thead>
                <tr>
                  <th>email</th>
                  <th>username</th>
                  <th>publicKey</th>
                  <th>privateKey</th>
                </tr>
              </thead>
              <tfoot>
                <tr>
                  <th>email</th>
                  <th>username</th>
                  <th>publicKey</th>
                  <th>privateKey</th>
                </tr>
              </tfoot>
              <tbody>
                {search.length > 0
                  ? filterUsers.map((user, index) => (
                      <tr key={user.id}>
                        <td>{user.email}</td>
                        <td>{user.username}</td>
                        <td>{user.publicKey}</td>
                        <td>{user.privateKey}</td>
                      </tr>
                    ))
                  : users.map((user, index) => (
                      <tr key={user.id}>
                        <td>{user.email}</td>
                        <td>{user.username}</td>
                        <td>{user.publicKey}</td>
                        <td>{user.privateKey}</td>
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

export default Users;
