"""
User database access utilities.

This module provides helper functions for retrieving user
information from the database.
"""
from . import utils

def get_user_by_username(cur, username):
    """
    Retrieve a user record by username.

    Executes a parameterized SQL query to fetch a single user
    from the users table using the provided username.

    Args:
        cur:
            Database cursor object used to execute queries.
        username (str):
            Username of the user to retrieve.

    Returns:
        tuple | None:
            A tuple containing:
                (id, username, password, is_disabled, is_admin)
            if the user exists, otherwise None.
    """
    sql, params = utils.prepare_query(
        "SELECT id, username, password, is_disabled, is_admin, bad_attempts, locked_until FROM users WHERE username=%s",
        (username,)
    )
    cur.execute(sql, params)
    return cur.fetchone()
