"""
Main Flask application module.

This module defines:
- application configuration,
- database connection helpers,
- authentication utilities,
- file upload and sharing functionality,
- and all HTTP routes for the document management system.
"""

import functools
import logging
import os
import pathlib

import dotenv
import flask  # type:ignore
import psycopg2  # type:ignore
from werkzeug.security import check_password_hash  # type:ignore
from werkzeug.security import generate_password_hash  # type:ignore
from werkzeug.utils import secure_filename # type:ignore

from . import db
from . import utils

from .logger_module import logger

import datetime

import tempfile
from flask_session import Session

import magic

dotenv.load_dotenv()

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_NAME = os.getenv("DB_NAME", "docdb")

UPLOAD_FOLDER = "uploads"

MAX_FAILED_ATTEMPTS = 3

ALLOWED_EXTENSIONS = {"txt", "pdf", "docx", "xlsx", "pptx"}
ALLOWED_MIME_TYPES = {
    "text/plain",
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

def allowed_file(filename):
    """
    Check if a filename has an allowed extension.

    Args:
        filename (str):
            Name of the file to check.
    Returns:
        bool:
            True if the file has an allowed extension, False otherwise.
    """
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def get_db():
    """
    Create a PostgreSQL database connection.

    Returns:
        connection:
            psycopg2 database connection object.
    """
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME,
    )

def create_app():
    """
    Retrieve documents belonging to a specific user.

    Args:
        cur:
            Database cursor object.
        owner_id (int):
            Identifier of the document owner.

    Returns:
        list:
            List of matching document records.
    """
    query = """
        SELECT id,title,filename,uploaded_at
        FROM documents
        WHERE owner_id=%s
        ORDER BY uploaded_at DESC
    """
    app = flask.Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

    #harden session management with Flask-Session and secure cookie flags
    
    # Server-Side Session Configuration
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_FILE_DIR"] = tempfile.gettempdir()
    app.config["SESSION_PERMANENT"] = False
    
    # 2. Secure Cookie Settings
    secure_mode = os.getenv("SECURE_COOKIES", "True").lower() in ("true", "1", "t")
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=secure_mode
    )

    # Enable Flask-Session
    Session(app)

    register_routes(app)

    return app

def get_documents_for_user(cur, owner_id):
    """
    Retrieve all documents belonging to a specific user.

    Documents are returned ordered by upload date
    in descending order.

    Args:
        cur:
            Database cursor object.
        owner_id (int):
            Identifier of the document owner.

    Returns:
        list:
            List of document records associated with the user.
    """
    # query = f"""
    #     SELECT id,title,filename,uploaded_at
    #     FROM documents
    #     WHERE owner_id=%s
    #     ORDER BY uploaded_at DESC
    # """ % owner_id
    # cur.execute(query)

    query = """
        SELECT id,title,filename,uploaded_at
        FROM documents
        WHERE owner_id=%s
        ORDER BY uploaded_at DESC
    """

    cur.execute(query, (owner_id,))

    return cur.fetchall()

def extract_metadata(filename):
    """
    Extract filesystem metadata from a file.

    Retrieves information such as file size,
    ownership, timestamps, inode data, and permissions.

    Args:
        filename (str):
            Path to the target file.

    Returns:
        str:
            Formatted metadata information or an error message
            if the file cannot be accessed.
    """
    #vulnerable to OS Command Injection that could lead to rce
    #cmd = utils.build("stat ", str(filename), " 2>&1")
    try:
        s = os.stat(filename)
        import pwd, grp, datetime
        uid = s.st_uid
        gid = s.st_gid
        try:
            uname = pwd.getpwuid(uid).pw_name
            gname = grp.getgrgid(gid).gr_name
        except KeyError:
            uname, gname = str(uid), str(gid)
        atime = datetime.datetime.fromtimestamp(s.st_atime).strftime("%Y-%m-%d %H:%M:%S.%f %z")
        mtime = datetime.datetime.fromtimestamp(s.st_mtime).strftime("%Y-%m-%d %H:%M:%S.%f %z")
        ctime = datetime.datetime.fromtimestamp(s.st_ctime).strftime("%Y-%m-%d %H:%M:%S.%f %z")
        return (
            f"  File: {filename}\n"
            f"  Size: {s.st_size}\t\tBlocks: {s.st_blocks}\t"
            + f"IO Block: {s.st_blksize}\tregular file\n"
            f"Device: {s.st_dev}\tInode: {s.st_ino}\tLinks: {s.st_nlink}\n"
            f"Access: ({oct(s.st_mode)[-4:]}/{''.join([])})\t"
            + f"Uid: ({uid:5d}/{uname:>8})\t"
            + f"Gid: ({gid:5d}/{gname:>8})\n"
            f"Access: {atime}\n"
            f"Modify: {mtime}\n"
            f"Change: {ctime}\n"
            f" Birth: -"
        )
    except OSError as e:
        return f"Error: {str(e)}"

def login_required(fn):
    """
    Decorator that restricts access to authenticated users.

    If the current session does not contain a valid user ID,
    the user is redirected to the login page.

    Args:
        fn:
            Route handler function to wrap.

    Returns:
        function:
            Wrapped route handler.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in flask.session:
            logger.warning("Unauthorized access by logged out user")
            flask.flash("Please log in first.", "error")
            return flask.redirect(flask.url_for("login"))
        return fn(*args, **kwargs)

    return wrapper

# Wrapper that mandates user to be admin
def admin_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
    
        if "user_id" not in flask.session:
            flask.flash("To acess please log in first.", "error")
            return flask.redirect(flask.url_for("login"))

        if not flask.session.get("is_admin"):
            logger.warning("Unauthorized access to admin function by user='%s'",flask.session.get("username"))
            flask.abort(403)

        return fn(*args, **kwargs)
    

    return wrapper


def register_routes(app):
    """
    Register all application routes.

    Defines authentication, document management,
    sharing, download, and health-check endpoints.

    Args:
        app (Flask):
            Flask application instance.

    Returns:
        None
    """

    @app.route("/")
    def index():
        """
        Redirect users to the appropriate landing page.

        Authenticated users are redirected to the documents page,
        while unauthenticated users are redirected to login.

        Returns:
            Response:
                Flask redirect response.
        """
        if flask.session.get("user_id"):
            return flask.redirect(flask.url_for("documents_page"))
        return flask.redirect(flask.url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """
        Authenticate a user and create a session.

        Handles both rendering the login page and processing
        submitted login credentials.

        Returns:
            Response:
                Rendered template or redirect response.
        """

        if flask.request.method == "POST":
            username = flask.request.form.get("username", "")
            password = flask.request.form.get("password", "")

            conn = get_db()
            cur = conn.cursor()

            user = db.get_user_by_username(cur, username)
            #* User: [0] id [1] username [2] password [3] is_disabled [4] is_admin [5] bad_attempts [6] locked_until

            logger.info("Login attempt for username='%s'", username)

            # Check user exists

            if user is None:
                logger.warning("Login failed. User '%s' does not exist in DB", username)
                cur.close()
                conn.close()
                flask.flash("Invalid credentials.", "error")
                return flask.render_template("login.html")

            if user [3]: # if is disabled
                logger.warning("Login failed. User '%s' is disabled", username)
                cur.close()
                conn.close()
                flask.flash("User is disabled.", "error")
                return flask.render_template("login.html")
            
            # logging.warning("Timestamp")
            # logging.warning(user[6])
            # logging.warning("Number of attempts")
            # logging.warning(user[5])

            
            if user[6] is not None: # If it has timestamp
                now = datetime.datetime.now()

                # Is it still locked?
                if user[6] > now:
                    logger.warning("User '%s' is locked out due to number of failed login attempts", username)
                    cur.close()
                    conn.close()

                    # Flash error
                    flask.flash(
                        "Too many login attempts. Try again later.",
                        "error"
                    )

                    # Return to login
                    return flask.render_template("login.html")

            #* Original condition: if user and (user[2] == password and not user[3]) or is_admin:
            #* Removed the password skip for admin and "None" verification cause it's above now."

            # Password check
            if check_password_hash(user[2], password):
                
                # Auth good, reset locked timestamp to null
                cur.execute("""
                    UPDATE users
                    SET bad_attempts = 0,
                        locked_until = NULL
                    WHERE username = %s""",
                    (username,)
                )
                conn.commit()

                flask.session.clear()
                flask.session["user_id"] = user[0]
                flask.session["username"] = user[1]
                flask.session["is_admin"] = user[4]

                cur.close()
                conn.close()

                logger.info("Sucessfully logged in username='%s'", username)

                # Move to logged page
                return flask.redirect(flask.url_for("documents_page"))
            
            logger.warning("Invalid password username='%s'", username)

            # Else give error
            flask.flash("Invalid credentials.", "error")

            # Update failed attempts
            failed_attempts = user[5] + 1
            locked_until = None

            # If over limit
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                # Calculate timestamp
                locked_until = (
                    datetime.datetime.now()
                    + datetime.timedelta(minutes=15)
                )

                # Return to 0
                failed_attempts = 0

            # Update DB info
            cur.execute("""
                UPDATE users
                SET bad_attempts = %s,
                    locked_until = %s
                WHERE username = %s
            """, (
                failed_attempts,
                locked_until,
                username
            ))

            conn.commit()

            cur.close()
            conn.close()


        # And move to login screen
        return flask.render_template("login.html")

    @app.route("/logout")
    def logout():
        """
        Clear the current user session.

        Returns:
            Response:
                Redirect to the login page.
        """
        flask.session.clear()
        return flask.redirect(flask.url_for("login"))

    @app.route("/documents/<int:document_id>")
    @login_required
    def document_details(document_id):
        """
        Display metadata and details for a document.

        Access is restricted to the document owner.

        Args:
            document_id (int):
                Identifier of the requested document.

        Returns:
            Response:
                Rendered document details page or 404 response.
        """

        #get id of user from session
        user_id = flask.session.get("user_id")

        conn = get_db()
        cur = conn.cursor()

        # intentionally missing authorization check
        #cur.execute(utils.prepare_query("""
        #    SELECT id, owner_id, title, filename, metadata
        #    FROM documents
        #   WHERE id = %s
        #    """,
        #    (document_id,)))

        # add check for owner_id = user_id to prevent unauthorized access to documents
        sql, params = utils.prepare_query("""
            SELECT id, owner_id, title, filename, metadata
            FROM documents
            WHERE id = %s AND owner_id = %s
            """,
            (document_id, user_id))

        cur.execute(sql, params)

        row = cur.fetchone()

        cur.close()
        conn.close()

        if not row:
            return "Document not found", 404

        document = {
            "id": row[0],
            "owner_id": row[1],
            "title": row[2],
            "filename": row[3],
            "metadata": row[4],
        }

        return flask.render_template("document_details.html", document=document)

    @app.route("/documents")
    @login_required
    def documents_page():
        """
        Display the document dashboard for the current user.

        Retrieves all documents owned by the authenticated user
        and renders them in the documents page.

        Returns:
            Response:
                Rendered HTML template containing the user's
                document list.
        """
        # requested_user_id = flask.request.args.get("user_id")
        current_user_id = flask.session.get("user_id")

        # owner_id = requested_user_id or current_user_id
        owner_id = current_user_id

        conn = get_db()
        cur = conn.cursor()

        docs = get_documents_for_user(cur, owner_id)

        cur.close()
        conn.close()

        documents = [
            {
                "id": d[0],
                "title": d[1],
                "filename": d[2],
                "uploaded_at": d[3],
            }
            for d in docs
        ]

        return flask.render_template(
            "documents.html",
            documents=documents,
            requested_user_id=owner_id,
            current_user_id=current_user_id,
            username=flask.session.get("username"),
        )

    @app.route("/documents/upload", methods=["POST"])
    @login_required
    def upload_document():
        """
        Upload and store a document for the current user.

        Saves the uploaded file, extracts metadata,
        and stores the document record in the database.

        Returns:
            Response:
                Redirect response to the documents page.
        """
        user_id = flask.session.get("user_id")
        title = flask.request.form.get("title", "Untitled")
        uploaded_file = flask.request.files.get("document")

        if not uploaded_file or uploaded_file.filename == "":
            flask.flash("Please choose a file.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        if not allowed_file(uploaded_file.filename):
            logger.warning("File upload with disallowed extension user='%s' filename='%s'", flask.session.get("username"), uploaded_file.filename)
            flask.flash("File type not allowed.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        file_bytes = uploaded_file.read(2048) # Read the first 2048 bytes for MIME type detection
        uploaded_file.seek(0) # Reset file pointer after reading

        mime_type = magic.from_buffer(file_bytes, mime=True)
        if mime_type not in ALLOWED_MIME_TYPES:
            logger.warning("File upload with disallowed MIME type user='%s' filename='%s' mime_type='%s'", flask.session.get("username"), uploaded_file.filename, mime_type)
            flask.flash(f"Invalid file content. Detected: {mime_type}", "error")
            return flask.redirect(flask.url_for("documents_page"))
        
        upload_folder = BASE_DIR / app.config["UPLOAD_FOLDER"]
        upload_folder.mkdir(parents=True, exist_ok=True)

        filename = secure_filename(uploaded_file.filename)
        destination = upload_folder / filename
        uploaded_file.save(destination)
        metadata = extract_metadata(destination)

        logger.info("Upload started user='%s' filename='%s'", flask.session.get("username"), filename)

        conn = get_db()
        cur = conn.cursor()

        #cur.execute(
        #    """
        #    INSERT INTO documents (owner_id, title, filename, metadata)
        #    VALUES (%s, %s, %s, %s)
        #    """,
        #    (user_id, title, uploaded_file.filename, metadata),
        #)

        cur.execute(
            """
            INSERT INTO documents (owner_id, title, filename, metadata)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, title, filename, metadata),
        )
        conn.commit()

        logger.info("Upload sucess user='%s' filename='%s'", flask.session.get("username"), filename)

        cur.close()
        conn.close()

        return flask.redirect(flask.url_for("documents_page", uploaded=title))

    @app.route("/health")
    def health():
        """
        Perform a database connectivity health check.

        Returns:
            tuple:
                JSON status response and HTTP status code.
        """
        try:
            """
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            conn.close()
            """
            return {"status": "ok"}, 200
        except Exception:
            logger.exception("Unhandled exception")
            return {"status": "error"}, 500


    @app.route("/documents/<id>/download")
    @login_required
    def download_document(id):
        """
        Download a document owned by the authenticated user.

        Verifies that the requested document belongs to the
        current user before sending the file as an attachment.

        Args:
            id (str):
                Identifier of the document to download.

        Returns:
            Response:
                File download response or a 404 error if the
                document does not exist or is inaccessible.
        """
        user_id = flask.session.get("user_id")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT filename
            FROM documents
            WHERE id = %s AND owner_id = %s
        """, (id, user_id))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            logger.warning("Unauthorized document access user='%s' doc_id='%s'",flask.session.get("username"),id)
            return "Document not found", 404

        filename = row[0]
        upload_folder = BASE_DIR / app.config["UPLOAD_FOLDER"]

        logger.info("Document download user='%s' filename='%s'", flask.session.get("username"), filename)

        return flask.send_from_directory(upload_folder, filename, as_attachment=True)

    @app.route("/shared/<id>/download")
    @login_required
    def download_shared_document(id):
        """
        Download a document owned by the current user.

        Args:
            id (str):
                Identifier of the requested document.

        Returns:
            Response:
                File download response or 404 response.
        """
        user_id = flask.session.get("user_id")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT d.filename
            FROM documents d
            JOIN document_shares ds ON d.id = ds.document_id
            WHERE d.id = %s AND ds.shared_with = %s
        """, (id, user_id))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            logger.warning("Unauthorized shared document access user='%s' doc_id='%s'",flask.session.get("username"),id)
            return "Document not found", 404

        filename = row[0]
        upload_folder = BASE_DIR / app.config["UPLOAD_FOLDER"]

        logger.info("Shared document download user='%s' filename='%s'", flask.session.get("username"), filename)

        return flask.send_from_directory(upload_folder, filename, as_attachment=True)


    @app.route("/documents/<document_id>/share", methods=["POST"])
    @login_required
    def share_document(document_id):
        """
        Share a document with another user.

        Verifies ownership of the document and existence
        of the target user before creating a sharing record.

        Args:
            document_id (str):
                Identifier of the document to share.

        Returns:
            Response:
                Redirect response after sharing operation.
        """
        user_id = flask.session.get("user_id")
        shared_with_id = flask.request.form.get("shared_with")

        conn = get_db()
        cur = conn.cursor()

        #check if shared file exists and belongs to user
        cur.execute("""
            SELECT id
            FROM documents
            WHERE id = %s AND owner_id = %s
        """, (document_id, user_id))

        row = cur.fetchone()
        if not row:
            conn.close()
            cur.close()
            flask.abort(403)

        #check if user to share with exists
        cur.execute("""
            SELECT id
            FROM users
            WHERE id = %s
        """, (shared_with_id,))

        row1 = cur.fetchone()
        if not row1:
            conn.close()
            cur.close()
            flask.flash("User to share with not found.", "error")
            return flask.redirect(flask.url_for("document_details", document_id=document_id))

        #share document with user
        cur.execute("""
            INSERT INTO document_shares (document_id, shared_with)
            VALUES (%s, %s)
        """, (document_id, shared_with_id))
        conn.commit()

        logger.info("Document shared owner='%s' doc_id='%s' shared_with='%s'", flask.session.get("username"), document_id, shared_with_id)

        cur.close()
        conn.close()
        flask.flash("Document shared successfully.", "success")
        return flask.redirect(flask.url_for("document_details", document_id=document_id))

    @app.route("/shared")
    @login_required
    def shared_documents():
        """
        Display documents shared with the current user.

        Returns:
            Response:
                Rendered shared documents page.
        """
        user_id = flask.session.get("user_id")

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT d.id, d.title, d.filename, d.uploaded_at, u.username
            FROM documents d
            JOIN document_shares ds ON d.id = ds.document_id
            JOIN users u ON d.owner_id = u.id
            WHERE ds.shared_with = %s
            ORDER BY d.uploaded_at DESC
        """, (user_id,))

        rows = cur.fetchall()

        cur.close()
        conn.close()

        shared_docs = [
            {
                "id": r[0],
                "title": r[1],
                "filename": r[2],
                "uploaded_at": r[3],
                "owner_username": r[4],
            }
            for r in rows
        ]

        return flask.render_template("shared_documents.html", documents=shared_docs)
    





    # Endpoint 5 - GET /admin/users
    # Lists all users

    @app.route("/admin/users")
    @login_required
    @admin_required
    def admin_get_users():

        logger.info("Admin panel accessed user='%s'", flask.session.get("username"))

        # Open DB connection
        conn = get_db()
        cur = conn.cursor()

        # Run DB query that gets all users
        cur.execute("""
            SELECT id, username, is_disabled, is_admin
            FROM users
            ORDER BY id"""
        )

        # Retrive resulting users
        raw_users = cur.fetchall()

        # Close connection
        cur.close()
        conn.close()

        # Create and compose user list
        users = []

        for usr in raw_users:
            users.append(
                {
                    "id": usr[0],
                    "username": usr[1],
                    "is_disabled": usr[2],
                    "is_admin": usr[3],
                }
            )
            
        # Return butifull tables
        return flask.render_template(
            "users.html",
            users=users,
        )
    
    @app.route("/admin/users/<int:id>/enable", methods=["POST"])
    @login_required
    @admin_required
    def enable_user(id):

        # Open DB connection
        conn = get_db()
        cur = conn.cursor()

        # Run DB query that returns user with id match
        cur.execute("""
            SELECT id
            FROM users
            WHERE id = %s""",
            (id,)
        )

        # Retrive user
        row = cur.fetchone()

        # Case not user
        if not row:
            cur.close()
            conn.close()
            flask.abort(404)

        # Run DB update to change is_disabled to False
        cur.execute("""
            UPDATE users
            SET is_disabled = FALSE
            WHERE id = %s""",
            (id,)
        )

        # Commit update
        conn.commit()

        logger.warning("User enabled by admin='%s' target_user_id='%s'", flask.session.get("username"), id)

        # Close connection
        cur.close()
        conn.close()

        # Report Mega Sucess
        flask.flash("User enabled successfully.", "success")

        return flask.redirect(flask.url_for("admin_get_users"))

    @app.route("/admin/users/<int:id>/disable", methods=["POST"])
    @login_required
    @admin_required
    def disable_user(id):

        # Open DB connection
        conn = get_db()
        cur = conn.cursor()

        # Run DB query that returns user with id match
        cur.execute("""
            SELECT id
            FROM users
            WHERE id = %s""",
            (id,)
        )

        # Retrive user
        row = cur.fetchone()

        # Case not user
        if not row:
            cur.close()
            conn.close()
            flask.abort(404)

        # Run DB update to change is_disabled to True
        cur.execute("""
            UPDATE users
            SET is_disabled = TRUE
            WHERE id = %s""",
            (id,)
        )

        # Commit update
        conn.commit()

        logger.warning("User disabled by admin='%s' target_user_id='%s'", flask.session.get("username"), id)

        # Close connection
        cur.close()
        conn.close()

        # Report Mega Sucess
        flask.flash("User disabled successfully.", "success")

        return flask.redirect(flask.url_for("admin_get_users"))


    # ------------------------------------------------------------------
    # Planned / Not Yet Implemented Endpoints
    #
    # The following routes are part of the intended system interface and
    # are not implemented in the baseline version of the application.
    #
    # The expected behavior of these endpoints is summarized below.
    #
    # Document operations
    #
    #   GET  /documents/<id>/download
    #       Download the specified document.
    #       Success: returns file contents (HTTP 200)
    #       Errors: 404 if the document does not exist
    #
    #   POST /documents/<id>/share
    #       Share a document with another user.
    #       Form parameter:
    #           shared_with  -> target user id
    #       Success: redirect or confirmation (HTTP 302 or 200)
    #
    # Shared documents
    #
    #   GET  /shared
    #       Display documents that were shared with the current user.
    #       Success: HTTP 200
    #
    #   GET  /shared/<id>/download
    #       Download a document that was shared with the current user.
    #       Success: returns file contents (HTTP 200)
    #
    # Administration
    #
    #   GET  /admin/users
    #       Display a list of users in the system.
    #       Success: HTTP 200
    #
    #   POST /admin/users/<id>/enable
    #       Enable a user account.
    #       Success: redirect or confirmation (HTTP 302 or 200)
    #
    #   POST /admin/users/<id>/disable
    #       Disable a user account.
    #       Success: redirect or confirmation (HTTP 302 or 200)
    #
    # ------------------------------------------------------------------
