import { BrowserRouter, Route, Routes } from "react-router-dom";
import AddFirewall from "./components/AddFirewall";
import Dashboard from "./components/Dashboard";
import Firewall from "./components/Firewall";
import Log from "./components/Log";
import Login from "./components/Login";
import Register from "./components/Register";
import Users from "./components/Users";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route exact path="/" element={<Login />}></Route>
        <Route path="/register" element={<Register />}></Route>
        <Route path="/dashboard" element={<Dashboard />}></Route>
        <Route path="/users" element={<Users />}></Route>
        <Route path="/firewall" element={<Firewall />}></Route>
        <Route path="/firewall-add" element={<AddFirewall />}></Route>
        <Route path="/log" element={<Log />}></Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
