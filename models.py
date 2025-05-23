from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB

db = SQLAlchemy()

class AnalysisResult(db.Model):
    __tablename__ = 'analysis_results'
    
    id = db.Column(db.Integer, primary_key=True)
    repository_name = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='pending')
    results = db.Column(JSONB)
    error = db.Column(db.Text)
    user_id = db.Column(db.String(255))
    rerank = db.Column(JSONB)
    
    def to_dict(self):
        return {
            'id': self.id,
            'repository_name': self.repository_name,
            'user_id': self.user_id,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'results': self.results,
            'error': self.error
        }

class CloudScan(db.Model):
    __tablename__ = 'cloud_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), nullable=False)
    cloud_provider = db.Column(db.String(50), nullable=False)
    account_id = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    findings = db.Column(JSONB)
    rerank = db.Column(JSONB)
    error = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'cloud_provider': self.cloud_provider,
            'account_id': self.account_id,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'findings': self.findings,
            'rerank': self.rerank,
            'error': self.error
        }

class GitLabAnalysisResult(db.Model):
    """Model for storing GitLab repository analysis results"""
    __tablename__ = 'gitlab_analysis_results'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), nullable=False)  # Frontend user ID
    project_id = db.Column(db.String(255), nullable=False)  # Keep this for compatibility
    project_url = db.Column(db.String(500), nullable=False)
    gitlab_user_id = db.Column(db.String(255), nullable=False)  # GitLab's user ID
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)
    results = db.Column(JSONB)
    rerank = db.Column(JSONB)
    error = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'project_url': self.project_url,
            'gitlab_user_id': self.gitlab_user_id, 
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'results': self.results,
            'rerank': self.rerank,
            'error': self.error
        }