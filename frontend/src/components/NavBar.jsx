import React from "react";
import { Navbar, Container, Dropdown, Nav } from "react-bootstrap";
import { ShieldShaded, PersonCircle } from "react-bootstrap-icons";

const NavBar = ({ user, profile, onLogout, onNavigateProfile, onNavigateHistory }) => {
  const displayName = profile?.displayName || user?.fullName || user?.email || "Người dùng";

  return (
    <Navbar bg="dark" variant="dark" expand="lg" className="mb-4 shadow-sm">
      <Container>
        <Navbar.Brand href="/" className="d-flex align-items-center gap-2">
          <ShieldShaded size={24} className="me-2" />
          Ransomware Threat Intelligence Portal
        </Navbar.Brand>

        <Navbar.Toggle aria-controls="vt-main-nav" />
        <Navbar.Collapse id="vt-main-nav" className="justify-content-end">
          {user && (
            <Nav className="me-3">
              <Nav.Link onClick={() => onNavigateHistory?.()}>Lịch sử quét</Nav.Link>
              <Nav.Link onClick={() => onNavigateProfile?.()}>Hồ sơ</Nav.Link>
            </Nav>
          )}

          {user && (
            <Dropdown align="end">
              <Dropdown.Toggle variant="outline-light" className="d-flex align-items-center gap-2">
                <PersonCircle size={22} />
                <span>{displayName}</span>
              </Dropdown.Toggle>
              <Dropdown.Menu className="shadow nav-user-menu" style={{ zIndex: 1050, position: 'absolute' }}>
                <Dropdown.Item onClick={() => onNavigateProfile?.()} style={{ cursor: 'pointer' }}>
                  User Profile
                </Dropdown.Item>
                <Dropdown.Item onClick={() => onNavigateHistory?.()} style={{ cursor: 'pointer' }}>
                  Scan History
                </Dropdown.Item>
                <Dropdown.Divider />
                <Dropdown.Item onClick={() => onLogout?.()} style={{ cursor: 'pointer' }}>
                  Logout
                </Dropdown.Item>
              </Dropdown.Menu>
            </Dropdown>
          )}
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
};

export default NavBar;
