import React from "react";
import { Navbar, Container, Dropdown, Nav, Button } from "react-bootstrap";
import { ShieldShaded, PersonCircle } from "react-bootstrap-icons";

const NavBar = ({
  user,
  profile,
  onLogout,
  onNavigateProfile,
  onNavigateHistory,
  onNavigateCommunity,
  onNavigateLogin,
}) => {
  const displayName = profile?.displayName || user?.fullName || user?.email || "User";
  const isAuthenticated = Boolean(user);

  return (
    <Navbar bg="dark" variant="dark" expand="lg" className="mb-4 shadow-sm">
      <Container>
        <Navbar.Brand href="/" className="d-flex align-items-center gap-2">
          <ShieldShaded size={24} className="me-2" />
          Ransomware Threat Intelligence Portal
        </Navbar.Brand>

        <Navbar.Toggle aria-controls="vt-main-nav" />
        <Navbar.Collapse id="vt-main-nav" className="justify-content-end">
          <Nav className="me-auto align-items-lg-center">
            <Nav.Link className="fw-semibold" onClick={() => onNavigateCommunity?.()}>
              Community
            </Nav.Link>
            {isAuthenticated && (
              <>
                <Nav.Link className="fw-semibold" onClick={() => onNavigateHistory?.()}>
                  Scan History
                </Nav.Link>
                <Nav.Link className="fw-semibold" onClick={() => onNavigateProfile?.()}>
                  Profile
                </Nav.Link>
              </>
            )}
          </Nav>

          {isAuthenticated ? (
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
          ) : (
            <Button variant="outline-light" className="fw-semibold" onClick={() => onNavigateLogin?.()}>
              Log in
            </Button>
          )}
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
};

export default NavBar;
