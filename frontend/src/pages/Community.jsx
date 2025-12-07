import React, { useCallback, useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import {
  Container,
  Row,
  Col,
  Card,
  Form,
  Badge,
  Button,
  InputGroup,
  Spinner,
  Modal,
  Alert,
  ButtonGroup,
  ToggleButton,
} from 'react-bootstrap';
import {
  Search,
  CheckCircleFill,
  PlusLg,
  ArrowClockwise,
  Hash,
  SuitHeart,
} from 'react-bootstrap-icons';

import { useNavigate } from 'react-router-dom';

import './Community.css';

const DEFAULT_CATEGORY_OPTIONS = [
  { slug: 'news-alerts', name: 'News & Alerts', description: 'Latest threat intelligence updates.' },
  { slug: 'help-and-decrypt', name: 'Help & Decrypt', description: 'Assistance and decrypt guidance.' },
  { slug: 'prevention-tips', name: 'Prevention Tips', description: 'Defense best practices & hardening tips.' },
  { slug: 'incident-reports', name: 'Incident Reports', description: 'Real-world incident reports.' },
  { slug: 'tools-and-scanners', name: 'Tools & Scanners', description: 'Community tools, IOC collections & rules.' },
];

const slugToVariant = {
  'news-alerts': 'info',
  'help-and-decrypt': 'success',
  'prevention-tips': 'warning',
  'incident-reports': 'danger',
  'tools-and-scanners': 'primary',
};

const formatDateTime = (value) => {
  if (!value) return '';
  try {
    return new Date(value).toLocaleString();
  } catch (err) {
    return value;
  }
};

const DEFAULT_POST_FORM = {
  title: '',
  summary: '',
  content: '',
  category: '',
  tags: '',
  alias: '',
  email: '',
  organization: '',
};

const CommunityPage = ({
  backendBaseUrl = '',
  currentUser = null,
  isAuthenticated = false,
}) => {
  const [categories, setCategories] = useState(DEFAULT_CATEGORY_OPTIONS);
  const [posts, setPosts] = useState([]);
  const [searchInput, setSearchInput] = useState('');
  const [filters, setFilters] = useState({
    search: '',
    category: 'all',
    sort: 'newest',
    verifiedOnly: false,
    page: 1,
  });
  const [pagination, setPagination] = useState({ page: 1, limit: 10, total: 0, has_next: false });
  const [loadingCategories, setLoadingCategories] = useState(true);
  const [loadingPosts, setLoadingPosts] = useState(false);
  const [fetchError, setFetchError] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [postForm, setPostForm] = useState(() => ({
    ...DEFAULT_POST_FORM,
    alias: currentUser?.fullName || currentUser?.displayName || '',
    email: currentUser?.email || '',
    organization: currentUser?.organization || '',
  }));
  const [formError, setFormError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const navigate = useNavigate();

  const getEndpoint = useCallback(
    (path) => (backendBaseUrl ? `${backendBaseUrl}${path}` : path),
    [backendBaseUrl]
  );

  useEffect(() => {
    setPostForm((prev) => ({
      ...prev,
      alias: currentUser?.fullName || currentUser?.displayName || prev.alias,
      email: currentUser?.email || prev.email,
      organization: currentUser?.organization || prev.organization,
    }));
  }, [currentUser]);

  useEffect(() => {
    let isMounted = true;
    const loadCategories = async () => {
      setLoadingCategories(true);
      try {
        const res = await axios.get(getEndpoint('/api/community/categories'));
        const payload = Array.isArray(res.data?.categories) ? res.data.categories : [];
        if (isMounted && payload.length > 0) {
          setCategories(payload);
        }
      } catch (err) {
        console.error('Failed to fetch community categories', err);
      } finally {
        if (isMounted) {
          setLoadingCategories(false);
        }
      }
    };
    loadCategories();
    return () => {
      isMounted = false;
    };
  }, [getEndpoint]);

  useEffect(() => {
    const timeout = setTimeout(() => {
      setPosts([]);
      setFilters((prev) => ({ ...prev, page: 1, search: searchInput.trim() }));
    }, 400);
    return () => clearTimeout(timeout);
  }, [searchInput]);

  useEffect(() => {
    let isActive = true;
    const controller = new AbortController();

    const loadPosts = async () => {
      setLoadingPosts(true);
      setFetchError('');
      try {
        const params = {
          page: filters.page,
          limit: 8,
          sort: filters.sort,
        };
        if (filters.verifiedOnly) params.verified_only = true;
        if (filters.category && filters.category !== 'all') params.category = filters.category;
        if (filters.search) params.q = filters.search;

        const res = await axios.get(getEndpoint('/api/community/posts'), {
          params,
          signal: controller.signal,
        });
        if (!isActive) return;

        const payloadPosts = Array.isArray(res.data?.posts) ? res.data.posts : [];
        const paginationMeta = res.data?.pagination || {};
        setPagination({
          page: paginationMeta.page || filters.page,
          limit: paginationMeta.limit || params.limit,
          total: paginationMeta.total ?? payloadPosts.length,
          has_next: Boolean(paginationMeta.has_next),
        });
        setPosts((prev) => (filters.page > 1 ? [...prev, ...payloadPosts] : payloadPosts));
      } catch (err) {
        if (!axios.isCancel(err)) {
          console.error('Failed to fetch community posts', err);
          if (isActive) {
            setFetchError(
              err.response?.data?.error ||
                'Unable to load community posts. Please try again.'
            );
          }
        }
      } finally {
        if (isActive) {
          setLoadingPosts(false);
        }
      }
    };

    loadPosts();
    return () => {
      isActive = false;
      controller.abort();
    };
  }, [filters, getEndpoint]);

  const categoryOptions = useMemo(() => {
    const unique = new Map();
    DEFAULT_CATEGORY_OPTIONS.concat(categories).forEach((item) => {
      if (!item || !item.slug) return;
      unique.set(item.slug, item);
    });
    return Array.from(unique.values()).sort((a, b) => a.name.localeCompare(b.name));
  }, [categories]);

  const handleChangeFilter = useCallback((patch) => {
    setFilters((prev) => {
      const shouldResetPage =
        typeof patch.page === 'undefined' &&
        (typeof patch.category !== 'undefined' ||
          typeof patch.sort !== 'undefined' ||
          typeof patch.verifiedOnly !== 'undefined');
      const nextPage =
        typeof patch.page !== 'undefined'
          ? patch.page
          : shouldResetPage
            ? 1
            : prev.page;
      return {
        ...prev,
        ...patch,
        page: nextPage,
      };
    });
    if (
      patch.page === 1 ||
      (typeof patch.page === 'undefined' &&
        (typeof patch.category !== 'undefined' ||
          typeof patch.sort !== 'undefined' ||
          typeof patch.verifiedOnly !== 'undefined'))
    ) {
      setPosts([]);
    }
  }, []);

  const handleToggleVerified = () => {
    handleChangeFilter({ verifiedOnly: !filters.verifiedOnly, page: 1 });
  };

  const handleLoadMore = () => {
    if (pagination.has_next && !loadingPosts) {
      handleChangeFilter({ page: filters.page + 1 });
    }
  };

  const handleOpenModal = () => {
    setFormError('');
    setShowCreateModal(true);
  };

  const handleCloseModal = () => {
    setShowCreateModal(false);
    setFormError('');
    setIsSubmitting(false);
  };

  const handleOpenPost = useCallback(
    (post) => {
      if (!post) return;
      navigate(`/community/${post.id}`);
    },
    [navigate]
  );

  const updatePostForm = (field, value) => {
    setPostForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmitPost = async (event) => {
    event.preventDefault();
    setFormError('');
    setIsSubmitting(true);
    try {
      const payload = {
        title: postForm.title.trim(),
        summary: postForm.summary.trim(),
        content: postForm.content.trim(),
        category: postForm.category || undefined,
        tags: postForm.tags,
        alias: postForm.alias.trim(),
        email: postForm.email.trim(),
        organization: postForm.organization.trim(),
      };

      if (!payload.title || payload.title.length < 6) {
        setFormError('Title must be at least 6 characters.');
        setIsSubmitting(false);
        return;
      }

      if (!payload.summary && !payload.content) {
        setFormError('Please provide a short summary of what you want to share.');
        setIsSubmitting(false);
        return;
      }

      await axios.post(getEndpoint('/api/community/posts'), payload);
      setSuccessMessage('Post published successfully. It will appear in the feed shortly.');
      setPostForm({
        ...DEFAULT_POST_FORM,
        alias: currentUser?.fullName || currentUser?.displayName || '',
        email: currentUser?.email || '',
        organization: currentUser?.organization || '',
      });
      handleCloseModal();
      setPosts([]);
      setFilters((prev) => ({ ...prev, page: 1 }));
    } catch (err) {
      console.error('Failed to submit community post', err);
      setFormError(err.response?.data?.error || 'Unable to publish right now. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const verifiedLabel = filters.verifiedOnly ? 'Verified only' : 'All posts';

  return (
    <Container fluid="lg" className="community-page py-5">
      <header className="community-hero glass-card mb-4">
        <div>
          <div className="community-brand">
            <span className="community-brand-icon" />
            <div>
              <h1 className="community-title">Ransomware Shield · Forum</h1>
              <p className="community-subtitle">Minimal, fast, content-first.</p>
            </div>
          </div>
        </div>
        <div className="d-flex align-items-center gap-3">
          <Button variant="outline-light" size="lg" onClick={handleOpenModal}>
            <PlusLg className="me-2" />
            New Post
          </Button>
        </div>
      </header>

      <section className="community-toolbar glass-card mb-4">
        <Row className="g-3 align-items-center">
          <Col lg={6}>
            <InputGroup>
              <InputGroup.Text>
                <Search size={18} />
              </InputGroup.Text>
              <Form.Control
                value={searchInput}
                onChange={(event) => setSearchInput(event.target.value)}
                placeholder="Search posts, tags, authors..."
                className="community-search-input"
              />
            </InputGroup>
          </Col>
          <Col lg={6}>
            <Row className="g-2">
              <Col sm={4}>
                <Form.Select
                  value={filters.category}
                  onChange={(event) => handleChangeFilter({ category: event.target.value })}
                >
                  <option value="all">All categories</option>
                  {categoryOptions.map((category) => (
                    <option key={category.slug} value={category.slug}>
                      {category.name}
                    </option>
                  ))}
                </Form.Select>
              </Col>
              <Col sm={4}>
                <Form.Select
                  value={filters.sort}
                  onChange={(event) => handleChangeFilter({ sort: event.target.value })}
                >
                  <option value="newest">Newest</option>
                  <option value="popular">Popular</option>
                  <option value="active">Recently active</option>
                </Form.Select>
              </Col>
              <Col sm={4}>
                <ButtonGroup className="w-100">
                  <ToggleButton
                    id="toggle-verified"
                    type="checkbox"
                    variant={filters.verifiedOnly ? 'success' : 'outline-secondary'}
                    value="verified"
                    checked={filters.verifiedOnly}
                    onChange={handleToggleVerified}
                  >
                    {filters.verifiedOnly ? 'Verified only' : 'Verified + All'}
                  </ToggleButton>
                </ButtonGroup>
              </Col>
            </Row>
          </Col>
        </Row>
      </section>

      {successMessage && (
        <Alert
          variant="success"
          onClose={() => setSuccessMessage('')}
          dismissible
          className="glass-card"
        >
          {successMessage}
        </Alert>
      )}

      {fetchError && !loadingPosts && (
        <Alert variant="danger" className="glass-card">
          {fetchError}
        </Alert>
      )}

      <div className="community-layout">
        <div className="community-list">
          {loadingPosts && posts.length === 0 && (
            <div className="community-skeleton-stack">
              {[1, 2, 3, 4].map((item) => (
                <div key={item} className="community-skeleton glass-card" />
              ))}
            </div>
          )}

          {!loadingPosts && posts.length === 0 && !fetchError && (
            <Card className="glass-card text-center py-5">
              <Card.Body>
                <h5 className="mb-2">No posts match these filters</h5>
                <p className="text-muted mb-3">
                  Try broadening the filters or create a new topic for the community.
                </p>
                <Button variant="primary" onClick={handleOpenModal}>
                  <PlusLg className="me-2" />
                  Share the first post
                </Button>
              </Card.Body>
            </Card>
          )}

        {posts.map((post) => {
          const badgeVariant = slugToVariant[post.category?.slug] || 'secondary';
          const createdLabel = post.timestamps?.created_at
            ? new Date(post.timestamps.created_at).toLocaleString()
            : 'Unknown';
          return (
            <Card
              key={post.id}
              className="community-card glass-card"
              role="button"
              tabIndex={0}
              onClick={() => handleOpenPost(post)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  handleOpenPost(post);
                }
              }}
            >
                <Card.Body>
                  <div className="d-flex justify-content-between align-items-start">
                    <div className="d-flex flex-column gap-2">
                      <div className="d-flex flex-wrap align-items-center gap-2">
                        {post.category && (
                          <Badge bg={badgeVariant} pill>
                            {post.category.name}
                          </Badge>
                        )}
                        {post.verified && (
                          <Badge bg="success" pill className="community-verified">
                            <CheckCircleFill size={14} className="me-1" />
                            Verified
                          </Badge>
                        )}
                      </div>
                      <h4 className="mb-1">{post.title}</h4>
                      <p className="community-summary mb-2 text-muted">{post.summary}</p>
                      <div className="d-flex flex-wrap align-items-center gap-3 community-meta">
                        <span className="text-muted">
                          {post.author?.alias || 'Anonymous'} · {createdLabel}
                        </span>
                        <span className="text-muted">
                          {post.reply_count ?? 0} replies · {post.upvotes ?? 0} upvotes
                        </span>
                        {post.tags?.length > 0 && (
                          <div className="community-tags">
                            {post.tags.map((tag) => (
                              <span key={tag} className="community-tag">
                                #{tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </Card.Body>
              </Card>
            );
          })}

          <div className="d-flex justify-content-center mt-4">
            {loadingPosts && posts.length > 0 ? (
              <Button variant="outline-light" disabled>
                <Spinner
                  as="span"
                  animation="border"
                  size="sm"
                  role="status"
                  aria-hidden="true"
                  className="me-2"
                />
                Loading...
              </Button>
            ) : (
              pagination.has_next && (
                <Button variant="outline-light" onClick={handleLoadMore}>
                  <ArrowClockwise className="me-2" />
                  Load more
                </Button>
              )
            )}
          </div>
          <div className="text-center text-muted mt-3 small">{verifiedLabel}</div>
        </div>

        <aside className="community-sidebar">
          <div className="community-sidebar-actions glass-card">
            <button type="button" className="community-action-btn" title="Trending tags">
              <Hash size={18} />
            </button>
            <button type="button" className="community-action-btn" title="Saved posts">
              <SuitHeart size={18} />
            </button>
            <button type="button" className="community-action-btn" title="Create post" onClick={handleOpenModal}>
              <PlusLg size={18} />
            </button>
          </div>
          <div className="community-sidebar-card glass-card">
            <h6 className="mb-2">Featured categories</h6>
            {loadingCategories ? (
              <div className="text-center py-3">
                <Spinner animation="border" size="sm" />
              </div>
            ) : (
              <ul className="community-category-list">
                {categoryOptions.slice(0, 6).map((category) => (
                  <li key={category.slug}>
                    <button
                      type="button"
                      className={`community-category-link${filters.category === category.slug ? ' active' : ''}`}
                      onClick={() => handleChangeFilter({ category: category.slug })}
                    >
                      <span>{category.name}</span>
                      <Badge bg="secondary" pill>
                        {categories.find((item) => item.slug === category.slug)?.post_count ?? 0}
                      </Badge>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </aside>
      </div>

      <Modal 
        show={showCreateModal} 
        onHide={handleCloseModal} 
        centered 
        size="lg"
        className="community-create-modal"
        contentClassName="community-create-modal-content"
      >
        <Modal.Header closeButton className="community-create-modal-header">
          <Modal.Title>Create community post</Modal.Title>
        </Modal.Header>
        <Form onSubmit={handleSubmitPost}>
          <Modal.Body className="community-create-modal-body">
            {formError && (
              <Alert variant="danger" onClose={() => setFormError('')} dismissible>
                {formError}
              </Alert>
            )}
            <Row className="g-3">
              <Col md={8}>
                <Form.Group controlId="communityPostTitle" className="mb-3">
                  <Form.Label>Title</Form.Label>
                  <Form.Control
                    type="text"
                    placeholder="Example: New phishing wave drops LockBit via OneNote"
                    value={postForm.title}
                    onChange={(event) => updatePostForm('title', event.target.value)}
                    required
                    className="vt-input"
                  />
                </Form.Group>
              </Col>
              <Col md={4}>
                <Form.Group controlId="communityPostCategory" className="mb-3">
                  <Form.Label>Category</Form.Label>
                  <Form.Select
                    value={postForm.category}
                    onChange={(event) => updatePostForm('category', event.target.value)}
                    className="vt-input"
                  >
                    <option value="">Select category</option>
                    {categoryOptions.map((category) => (
                      <option key={category.slug} value={category.slug}>
                        {category.name}
                      </option>
                    ))}
                  </Form.Select>
                </Form.Group>
              </Col>
            </Row>
            <Form.Group controlId="communityPostSummary" className="mb-3">
              <Form.Label>Short summary</Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                placeholder="Briefly describe what this post is about..."
                value={postForm.summary}
                onChange={(event) => updatePostForm('summary', event.target.value)}
                className="vt-input"
              />
            </Form.Group>
            <Form.Group controlId="communityPostContent" className="mb-3">
              <Form.Label>Detailed content (optional)</Form.Label>
              <Form.Control
                as="textarea"
                rows={6}
                placeholder="Describe IOC, indicators, and remediation steps..."
                value={postForm.content}
                onChange={(event) => updatePostForm('content', event.target.value)}
                className="vt-input"
              />
            </Form.Group>
            <Row className="g-3">
              <Col md={6}>
                <Form.Group controlId="communityPostTags" className="mb-3">
                  <Form.Label>Tags (comma-separated)</Form.Label>
                  <Form.Control
                    type="text"
                    placeholder="lockbit, phishing, ioc"
                    value={postForm.tags}
                    onChange={(event) => updatePostForm('tags', event.target.value)}
                    className="vt-input"
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group controlId="communityPostOrganization" className="mb-3">
                  <Form.Label>Organization (optional)</Form.Label>
                  <Form.Control
                    type="text"
                    placeholder="Organization or team name"
                    value={postForm.organization}
                    onChange={(event) => updatePostForm('organization', event.target.value)}
                    className="vt-input"
                  />
                </Form.Group>
              </Col>
            </Row>
            <Row className="g-3">
              <Col md={6}>
                <Form.Group controlId="communityPostAlias" className="mb-3">
                  <Form.Label>Display name</Form.Label>
                  <Form.Control
                    type="text"
                    placeholder="SecOpsVN"
                    value={postForm.alias}
                    onChange={(event) => updatePostForm('alias', event.target.value)}
                    className="vt-input"
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group controlId="communityPostEmail" className="mb-3">
                  <Form.Label>Contact email (optional)</Form.Label>
                  <Form.Control
                    type="email"
                    placeholder="you@company.com"
                    value={postForm.email}
                    onChange={(event) => updatePostForm('email', event.target.value)}
                    className="vt-input"
                  />
                </Form.Group>
              </Col>
            </Row>
            <Form.Text className="text-muted">
              Your post will be publicly visible after submission. Content will be moderated before being marked as Verified.
            </Form.Text>
          </Modal.Body>
          <Modal.Footer className="community-create-modal-footer justify-content-between">
            <Button variant="outline-secondary" onClick={handleCloseModal}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" disabled={isSubmitting}>
              {isSubmitting ? (
                <>
                  <Spinner
                    as="span"
                    animation="border"
                    size="sm"
                    role="status"
                    aria-hidden="true"
                    className="me-2"
                  />
                  Posting...
                </>
              ) : (
                'Post'
              )}
            </Button>
          </Modal.Footer>
        </Form>
      </Modal>
    </Container>
  );
};

export default CommunityPage;
