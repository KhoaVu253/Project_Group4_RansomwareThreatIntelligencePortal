import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';
import {
  Container,
  Row,
  Col,
  Badge,
  Button,
  Spinner,
  Alert,
  Card,
  Form,
} from 'react-bootstrap';
import {
  ArrowLeft,
  Share,
  Flag,
  CheckCircleFill,
} from 'react-bootstrap-icons';

import './Community.css';

const formatDateTime = (value) => {
  if (!value) return '';
  try {
    return new Date(value).toLocaleString();
  } catch (err) {
    return value;
  }
};

const slugToVariant = {
  'news-alerts': 'info',
  'help-and-decrypt': 'success',
  'prevention-tips': 'warning',
  'incident-reports': 'danger',
  'tools-and-scanners': 'primary',
};

const defaultCommentForm = (user) => ({
  alias: user?.fullName || user?.displayName || '',
  email: user?.email || '',
  content: '',
});

const CommunityPostDetail = ({
  backendBaseUrl = '',
  currentUser = null,
  isAuthenticated = false,
}) => {
  const { postId } = useParams();
  const navigate = useNavigate();

  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [post, setPost] = useState(null);
  const [comments, setComments] = useState([]);
  const [commentForm, setCommentForm] = useState(defaultCommentForm(currentUser));
  const [commentSubmitting, setCommentSubmitting] = useState(false);
  const [commentError, setCommentError] = useState('');
  const [shareFeedback, setShareFeedback] = useState('');

  const getEndpoint = useMemo(
    () => (path) => (backendBaseUrl ? `${backendBaseUrl}${path}` : path),
    [backendBaseUrl]
  );

  useEffect(() => {
    setCommentForm(defaultCommentForm(currentUser));
  }, [currentUser]);

  useEffect(() => {
    let isMounted = true;
    const controller = new AbortController();

    const loadPost = async () => {
      setIsLoading(true);
      setError('');
      try {
        const res = await axios.get(getEndpoint(`/api/community/posts/${postId}`), {
          signal: controller.signal,
        });
        if (!isMounted) return;
        setPost(res.data?.post || null);
        setComments(Array.isArray(res.data?.comments) ? res.data.comments : []);
      } catch (err) {
        if (axios.isCancel(err)) return;
        console.error('Failed to load community post detail', err);
        setError(err.response?.data?.error || 'Unable to load the post.');
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    };

    loadPost();

    return () => {
      isMounted = false;
      controller.abort();
    };
  }, [getEndpoint, postId]);

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setShareFeedback('Link copied!');
      setTimeout(() => setShareFeedback(''), 2500);
    } catch {
      setShareFeedback('Unable to copy link.');
      setTimeout(() => setShareFeedback(''), 2500);
    }
  };

  const handleReport = () => {
    window.open(
      `mailto:soc@example.com?subject=Report%20post%20${post?.id}&body=Please%20describe%20why%20you're%20reporting%20this%20post.`,
      '_blank',
      'noopener'
    );
  };

  const updateCommentForm = (field) => (event) => {
    setCommentForm((prev) => ({ ...prev, [field]: event.target.value }));
  };

  const handleSubmitComment = async (event) => {
    event.preventDefault();
    setCommentError('');

    if (!isAuthenticated) {
      setCommentError('Please sign in to post a comment.');
      return;
    }

    const content = (commentForm.content || '').trim();
    if (!content) {
      setCommentError('Comment content cannot be empty.');
      return;
    }

    setCommentSubmitting(true);
    try {
      const res = await axios.post(getEndpoint(`/api/community/posts/${postId}/comments`), {
        alias: (commentForm.alias || '').trim(),
        email: (commentForm.email || '').trim(),
        content,
      });
      const newComment = res.data?.comment;
      const updatedPost = res.data?.post;
      if (newComment) {
        setComments((prev) => [...prev, newComment]);
      }
      if (updatedPost) {
        setPost(updatedPost);
      }
      setCommentForm((prev) => ({ ...prev, content: '' }));
    } catch (err) {
      console.error('Failed to submit community comment', err);
      setCommentError(err.response?.data?.error || 'Unable to submit comment.');
    } finally {
      setCommentSubmitting(false);
    }
  };

  const tagBadges = useMemo(() => {
    return post?.tags?.map((tag) => (
      <span key={tag} className="community-tag">
        #{tag}
      </span>
    ));
  }, [post?.tags]);

  if (isLoading) {
    return (
      <div className="community-post-page loading-state">
        <Spinner animation="border" role="status" />
      </div>
    );
  }

  if (error || !post) {
    return (
      <div className="community-post-page">
        <Container className="py-5">
          <Button variant="outline-light" onClick={() => navigate(-1)} className="mb-3">
            <ArrowLeft className="me-2" />
            Back
          </Button>
          <Alert variant="danger">{error || 'Post not found.'}</Alert>
        </Container>
      </div>
    );
  }

  return (
    <div className="community-post-page">
      <Container className="py-5">
        <div className="community-post-breadcrumb mb-3">
          <Button variant="link" className="p-0" onClick={() => navigate('/community')}>
            <ArrowLeft className="me-2" />
            Back / {post.category?.name || 'Community'}
          </Button>
          {shareFeedback && <span className="community-share-feedback">{shareFeedback}</span>}
        </div>

        <Card className="glass-card community-post-header mb-4">
          <Card.Body>
            <div className="d-flex flex-wrap align-items-center gap-3 mb-3">
              {post.category?.name && (
                <Badge bg={slugToVariant[post.category.slug] || 'secondary'} pill>
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

            <h1 className="community-post-title mb-3">{post.title}</h1>

            <div className="community-post-meta mb-3">
              <span>{post.author?.alias || 'Anonymous'}</span>
              <span>{formatDateTime(post.timestamps?.created_at)}</span>
              <span>{post.read_time || '7 min'}</span>
              <span>{post.views ?? 0} views</span>
            </div>

            {post.summary && <p className="community-post-summary">{post.summary}</p>}

            <div className="community-post-actions">
              <div className="community-tag-group">{tagBadges}</div>
              <div className="d-flex gap-2">
                <Button variant="outline-light" onClick={handleCopyLink}>
                  <Share className="me-2" />
                  Share
                </Button>
                <Button variant="outline-warning" onClick={handleReport}>
                  <Flag className="me-2" />
                  Report IOC
                </Button>
              </div>
            </div>
          </Card.Body>
        </Card>

        <Row className="g-4 align-items-start">
          <Col lg={8}>
            <Card className="glass-card community-post-body mb-4">
              <Card.Body>
                <section className="community-post-section">
                  <h4>Overview</h4>
                  <p>{post.content || 'No overview available.'}</p>
                </section>

                {post.sections?.map((section) => (
                  <section key={section.title} className="community-post-section">
                    <h4>{section.title}</h4>
                    <p>{section.body}</p>
                  </section>
                ))}
              </Card.Body>
            </Card>

            <Card className="glass-card community-comments-card mb-4">
              <Card.Body>
                <h4 className="mb-3">
                  Comments ({post.reply_count ?? comments.length})
                </h4>
                {comments.length === 0 ? (
                  <p className="text-muted mb-0">No discussions yet. Start the conversation!</p>
                ) : (
                  <div className="community-comment-list">
                    {comments.map((comment) => (
                      <div key={comment.id} className="community-comment glass-card">
                        <div className="community-comment-author">
                          <strong>{comment.author?.alias || 'Anonymous'}</strong>
                          <span>{formatDateTime(comment.timestamps?.created_at)}</span>
                        </div>
                        <p className="community-comment-body">{comment.content}</p>
                      </div>
                    ))}
                  </div>
                )}
              </Card.Body>
            </Card>

            <Card className="glass-card community-reply-card">
              <Card.Body>
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h5 className="mb-0">Quick reply</h5>
                  {!isAuthenticated && (
                    <small className="text-muted">Please sign in to leave a comment.</small>
                  )}
                </div>
                {commentError && (
                  <Alert variant="danger" onClose={() => setCommentError('')} dismissible>
                    {commentError}
                  </Alert>
                )}
                <Form onSubmit={handleSubmitComment} className="community-comment-form">
                  <Row className="g-3">
                    <Col md={6}>
                      <Form.Group controlId="replyAlias">
                        <Form.Label>Display name</Form.Label>
                        <Form.Control
                          type="text"
                          placeholder="Display name"
                          value={commentForm.alias}
                          onChange={updateCommentForm('alias')}
                          disabled={!isAuthenticated}
                        />
                      </Form.Group>
                    </Col>
                    <Col md={6}>
                      <Form.Group controlId="replyEmail">
                        <Form.Label>Email</Form.Label>
                        <Form.Control
                          type="email"
                          placeholder="you@company.com"
                          value={commentForm.email}
                          onChange={updateCommentForm('email')}
                          disabled={!isAuthenticated}
                        />
                      </Form.Group>
                    </Col>
                  </Row>
                  <Form.Group controlId="replyContent" className="mt-3">
                    <Form.Control
                      as="textarea"
                      rows={4}
                      placeholder="Share your insights, experiences, or questions..."
                      value={commentForm.content}
                      onChange={updateCommentForm('content')}
                      disabled={!isAuthenticated}
                    />
                  </Form.Group>
                  <div className="d-flex justify-content-end mt-3">
                    <Button type="submit" variant="primary" disabled={!isAuthenticated || commentSubmitting}>
                      {commentSubmitting ? (
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
                        'Post comment'
                      )}
                    </Button>
                  </div>
                </Form>
              </Card.Body>
            </Card>

            <div className="community-post-nav mt-4">
              <Button variant="outline-light" onClick={() => navigate('/community')}>
                ◀ Previous
              </Button>
              <Button variant="outline-light" onClick={() => navigate('/community')}>
                Next ▶
              </Button>
            </div>
          </Col>

          <Col lg={4}>
            <Card className="glass-card community-author-card">
              <Card.Body>
                <h5 className="mb-3">Author</h5>
                <div className="community-author-avatar">
                  {post.author?.alias?.slice(0, 2)?.toUpperCase() || 'AN'}
                </div>
                <p className="community-author-name">{post.author?.alias || 'Anonymous'}</p>
                <p className="text-muted mb-0">Security Engineer</p>
              </Card.Body>
            </Card>
          </Col>
        </Row>
      </Container>
    </div>
  );
};

export default CommunityPostDetail;

