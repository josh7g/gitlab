from app import app, db
from sqlalchemy import text
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_table_exists(table_name):
    """Check if a table exists in the database"""
    with app.app_context():
        # Use parameterized query instead of string interpolation
        result = db.session.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public'
                AND table_name = :table_name
            );
        """), {"table_name": table_name})
        return result.scalar()

def add_gitlab_table():
    """Add GitLab analysis results table if it doesn't exist"""
   
    
    with app.app_context():
        try:
            # Check if table exists
            result = db.session.execute(text("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public'
                    AND table_name = 'gitlab_analysis_results'
                );
            """))
            table_exists = result.scalar()
            
            if not table_exists:
                logger.info("Creating GitLab analysis results table...")
                # Import the model to ensure it's registered with SQLAlchemy
                from models import GitLabAnalysisResult
                db.create_all()
                logger.info("GitLab analysis results table created successfully")
            else:
                logger.info("GitLab analysis results table already exists")
                
            # Check and add any missing columns if the table already exists
            add_gitlab_table_columns()
            
        except Exception as e:
            logger.error(f"Error creating GitLab analysis results table: {str(e)}")
            db.session.rollback()
            raise

def add_gitlab_table_columns():
    """Add any missing columns to the GitLab analysis results table"""
    from sqlalchemy import text
    
    with app.app_context():
        try:
            # Check for project_url column
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'gitlab_analysis_results' AND column_name = 'project_url'
            """))
            project_url_exists = bool(result.scalar())
            
            if not project_url_exists:
                logger.info("Adding project_url column to gitlab_analysis_results...")
                db.session.execute(text("""
                    ALTER TABLE gitlab_analysis_results
                    ADD COLUMN IF NOT EXISTS project_url VARCHAR(500) NOT NULL DEFAULT ''
                """))
                db.session.commit()
                logger.info("Added project_url column to gitlab_analysis_results")
            
            # Check for user_id column (renamed from project_id)
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'gitlab_analysis_results' AND column_name = 'user_id'
            """))
            user_id_exists = bool(result.scalar())
            
            if not user_id_exists:
                # Check if we need to rename project_id to user_id
                result = db.session.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'gitlab_analysis_results' AND column_name = 'project_id'
                """))
                project_id_exists = bool(result.scalar())
                
                if project_id_exists:
                    logger.info("Renaming project_id column to user_id in gitlab_analysis_results...")
                    db.session.execute(text("""
                        ALTER TABLE gitlab_analysis_results
                        RENAME COLUMN project_id TO user_id
                    """))
                    db.session.commit()
                    logger.info("Renamed project_id column to user_id in gitlab_analysis_results")
                else:
                    logger.info("Adding user_id column to gitlab_analysis_results...")
                    db.session.execute(text("""
                        ALTER TABLE gitlab_analysis_results
                        ADD COLUMN IF NOT EXISTS user_id VARCHAR(255) NOT NULL DEFAULT ''
                    """))
                    db.session.commit()
                    logger.info("Added user_id column to gitlab_analysis_results")
            
            # Check for gitlab_user_id column (renamed from user_id)
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'gitlab_analysis_results' AND column_name = 'gitlab_user_id'
            """))
            gitlab_user_id_exists = bool(result.scalar())
            
            if not gitlab_user_id_exists:
                # Check if we need to rename user_id to gitlab_user_id
                result = db.session.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'gitlab_analysis_results' AND column_name = 'user_id'
                """))
                old_user_id_exists = bool(result.scalar())
                
                # Only rename if user_id exists and we don't already have gitlab_user_id
                if old_user_id_exists and not user_id_exists:
                    logger.info("Renaming user_id column to gitlab_user_id in gitlab_analysis_results...")
                    db.session.execute(text("""
                        ALTER TABLE gitlab_analysis_results
                        RENAME COLUMN user_id TO gitlab_user_id
                    """))
                    db.session.commit()
                    logger.info("Renamed user_id column to gitlab_user_id in gitlab_analysis_results")
                else:
                    logger.info("Adding gitlab_user_id column to gitlab_analysis_results...")
                    db.session.execute(text("""
                        ALTER TABLE gitlab_analysis_results
                        ADD COLUMN IF NOT EXISTS gitlab_user_id VARCHAR(255) NOT NULL DEFAULT ''
                    """))
                    db.session.commit()
                    logger.info("Added gitlab_user_id column to gitlab_analysis_results")
            
            # Check for status column
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'gitlab_analysis_results' AND column_name = 'status'
            """))
            status_exists = bool(result.scalar())
            
            if not status_exists:
                logger.info("Adding status column to gitlab_analysis_results...")
                db.session.execute(text("""
                    ALTER TABLE gitlab_analysis_results
                    ADD COLUMN IF NOT EXISTS status VARCHAR(50) NOT NULL DEFAULT 'pending'
                """))
                db.session.commit()
                logger.info("Added status column to gitlab_analysis_results")
            
            # Check for results column
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'gitlab_analysis_results' AND column_name = 'results'
            """))
            results_exists = bool(result.scalar())
            
            if not results_exists:
                logger.info("Adding results column to gitlab_analysis_results...")
                db.session.execute(text("""
                    ALTER TABLE gitlab_analysis_results
                    ADD COLUMN IF NOT EXISTS results JSONB
                """))
                db.session.commit()
                logger.info("Added results column to gitlab_analysis_results")
            
            # Check for rerank column
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'gitlab_analysis_results' AND column_name = 'rerank'
            """))
            rerank_exists = bool(result.scalar())
            
            if not rerank_exists:
                logger.info("Adding rerank column to gitlab_analysis_results...")
                db.session.execute(text("""
                    ALTER TABLE gitlab_analysis_results
                    ADD COLUMN IF NOT EXISTS rerank JSONB
                """))
                db.session.commit()
                logger.info("Added rerank column to gitlab_analysis_results")
            
            # Check for error column
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'gitlab_analysis_results' AND column_name = 'error'
            """))
            error_exists = bool(result.scalar())
            
            if not error_exists:
                logger.info("Adding error column to gitlab_analysis_results...")
                db.session.execute(text("""
                    ALTER TABLE gitlab_analysis_results
                    ADD COLUMN IF NOT EXISTS error TEXT
                """))
                db.session.commit()
                logger.info("Added error column to gitlab_analysis_results")
            
            # Add an index on user_id and gitlab_user_id for faster queries
            db.session.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_gitlab_analysis_results_user_id
                ON gitlab_analysis_results (user_id);
            """))
            
            db.session.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_gitlab_analysis_results_gitlab_user_id
                ON gitlab_analysis_results (gitlab_user_id);
            """))
            
            db.session.commit()
            logger.info("Ensured indexes on gitlab_analysis_results table")
            
        except Exception as e:
            logger.error(f"Error adding columns to GitLab analysis results table: {str(e)}")
            db.session.rollback()
            raise
            
# Modify the init_tables function to include the GitLab table
def init_tables():
    """Initialize tables if they don't exist and add necessary columns"""
    with app.app_context():
        try:
            # Create all defined tables
            db.create_all()
            logger.info("Database tables created or confirmed to exist")
            
            # Add necessary columns to existing tables
            add_required_columns()
            
            # Add GitLab table and columns
            add_gitlab_table()
            
            logger.info("Database initialization completed successfully!")
            
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            db.session.rollback()
            raise

def add_required_columns():
    """Add required columns if they don't exist"""
    with app.app_context():
        try:
            # Check and add user_id column to analysis_results
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = :table_name AND column_name = :column_name
            """), {"table_name": "analysis_results", "column_name": "user_id"})
            column_exists = bool(result.scalar())
            
            if not column_exists:
                logger.info("Adding user_id column to analysis_results...")
                db.session.execute(text("""
                    ALTER TABLE analysis_results 
                    ADD COLUMN IF NOT EXISTS user_id VARCHAR(255)
                """))
                db.session.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_analysis_results_user_id 
                    ON analysis_results (user_id)
                """))
                db.session.commit()
                logger.info("Added user_id column to analysis_results")

            # Check and add rerank column to analysis_results
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = :table_name AND column_name = :column_name
            """), {"table_name": "analysis_results", "column_name": "rerank"})
            rerank_exists = bool(result.scalar())
            
            if not rerank_exists:
                logger.info("Adding rerank column to analysis_results...")
                db.session.execute(text("""
                    ALTER TABLE analysis_results 
                    ADD COLUMN IF NOT EXISTS rerank JSONB
                """))
                db.session.commit()
                logger.info("Added rerank column to analysis_results")
            
            # Check and add columns to cloud_scans table if it exists
            if check_table_exists('cloud_scans'):
                # Check for completed_at column
                result = db.session.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = :table_name AND column_name = :column_name
                """), {"table_name": "cloud_scans", "column_name": "completed_at"})
                completed_at_exists = bool(result.scalar())
                
                if not completed_at_exists:
                    logger.info("Adding completed_at column to cloud_scans...")
                    db.session.execute(text("""
                        ALTER TABLE cloud_scans 
                        ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP
                    """))
                    db.session.commit()
                    logger.info("Added completed_at column to cloud_scans")
                
                # Check for error column
                result = db.session.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = :table_name AND column_name = :column_name
                """), {"table_name": "cloud_scans", "column_name": "error"})
                error_exists = bool(result.scalar())
                
                if not error_exists:
                    logger.info("Adding error column to cloud_scans...")
                    db.session.execute(text("""
                        ALTER TABLE cloud_scans 
                        ADD COLUMN IF NOT EXISTS error TEXT
                    """))
                    db.session.commit()
                    logger.info("Added error column to cloud_scans")
            
        except Exception as e:
            logger.error(f"Error adding columns: {str(e)}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    logger.info("Starting database initialization...")
    init_tables()
    logger.info("Database initialization process completed")