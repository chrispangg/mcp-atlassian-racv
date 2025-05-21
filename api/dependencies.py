"""Dependency providers for JiraFetcher and ConfluenceFetcher with context awareness.

Provides get_jira_fetcher and get_confluence_fetcher for use in tool functions.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from mcp_atlassian.confluence import ConfluenceConfig, ConfluenceFetcher
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.jira import JiraConfig, JiraFetcher

if TYPE_CHECKING:
    pass

logger = logging.getLogger("mcp-atlassian.servers.dependencies")

security = HTTPBasic()

# --- Configuration ---
JIRA_ORG_URL_ENV = "JIRA_URL"
CONFLUENCE_ORG_URL_ENV = "CONFLUENCE_URL"


# --- App Context ---
class AppContext:
    def __init__(
        self,
        jira_config: JiraConfig | None = None,
        confluence_config: ConfluenceConfig | None = None,
        read_only: bool = False,
        enabled_tools: list[str] | None = None,
        current_user_jira_client: JiraFetcher | None = None,
        current_user_confluence_client: ConfluenceFetcher | None = None,
    ):
        self.jira_config = jira_config
        self.confluence_config = confluence_config
        self.read_only = read_only
        self.enabled_tools = enabled_tools
        self.current_user_jira_client = current_user_jira_client
        self.current_user_confluence_client = current_user_confluence_client


async def get_current_user_context(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
) -> AppContext:
    """
    Validates username (email) and API key (password field) against Jira/Confluence.
    Creates user-specific Jira/Confluence clients upon successful authentication.
    Returns an AppContext populated with user-specific details.
    """
    username_email = credentials.username
    api_key = credentials.password

    # Get global app_context from request.app.state
    global_app_context: AppContext | None = getattr(
        request.app.state, "app_context", None
    )

    if not global_app_context:
        logger.error(
            "Global application context (request.app.state.app_context) not found during user authentication."
        )
        raise HTTPException(
            status_code=500,
            detail="Server configuration error: Global context missing.",
        )

    user_jira_config: JiraConfig | None = None
    user_jira_client: JiraFetcher | None = None
    jira_authenticated = False

    user_confluence_config: ConfluenceConfig | None = None
    user_confluence_client: ConfluenceFetcher | None = None
    confluence_authenticated = False

    jira_org_url = os.getenv(JIRA_ORG_URL_ENV)
    confluence_org_url = os.getenv(CONFLUENCE_ORG_URL_ENV)

    # print(f"Jira org URL: {jira_org_url}") # Keep for debugging if necessary
    # print(f"Confluence org URL: {confluence_org_url}") # Keep for debugging if necessary

    if jira_org_url:
        try:
            logger.debug(f"Attempting Jira authentication for user: {username_email}")
            temp_jira_config = JiraConfig(
                url=jira_org_url,
                username=username_email,
                api_token=api_key,
                auth_type="basic",
            )
            temp_jira_client = JiraFetcher(config=temp_jira_config)

            current_jira_user = temp_jira_client.get_current_user_account_id()
            if current_jira_user:
                logger.info(
                    f"Jira authentication successful for user: {username_email}. User ID: {current_jira_user}"
                )
                user_jira_config = temp_jira_config
                user_jira_client = temp_jira_client
                jira_authenticated = True
            else:
                logger.warning(
                    f"Jira credential validation returned no user for {username_email}."
                )
        except MCPAtlassianAuthenticationError as e:
            logger.warning(f"Jira authentication failed for user {username_email}: {e}")
        except Exception as e:
            logger.error(
                f"Error during Jira authentication for user {username_email}: {e}",
                exc_info=True,
            )

    if confluence_org_url:
        try:
            logger.debug(
                f"Attempting Confluence authentication for user: {username_email}"
            )
            temp_confluence_config = ConfluenceConfig(
                url=confluence_org_url,
                username=username_email,
                api_token=api_key,
                auth_type="basic",
            )
            temp_confluence_client = ConfluenceFetcher(config=temp_confluence_config)

            current_confluence_user = temp_confluence_client.get_current_user_info()
            if (
                current_confluence_user
                and isinstance(current_confluence_user, dict)
                and current_confluence_user.get("accountId")
            ):
                logger.info(
                    f"Confluence authentication successful for user: {username_email}. User: {current_confluence_user.get('displayName')}"
                )
                user_confluence_config = temp_confluence_config
                user_confluence_client = temp_confluence_client
                confluence_authenticated = True
            else:
                logger.warning(
                    f"Confluence credential validation returned no user or incomplete data for {username_email}."
                )
        except MCPAtlassianAuthenticationError as e:
            logger.warning(
                f"Confluence authentication failed for user {username_email}: {e}"
            )
        except Exception as e:
            logger.error(
                f"Error during Confluence authentication for user {username_email}: {e}",
                exc_info=True,
            )

    if not jira_authenticated and not confluence_authenticated:
        logger.warning(
            f"Authentication failed for user {username_email} against all configured services."
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid username or API key for Jira and/or Confluence.",
            headers={"WWW-Authenticate": "Basic"},
        )

    logger.info(
        f"User {username_email} authenticated. Jira: {jira_authenticated}, Confluence: {confluence_authenticated}"
    )

    return AppContext(
        jira_config=user_jira_config,
        confluence_config=user_confluence_config,
        read_only=global_app_context.read_only,
        enabled_tools=global_app_context.enabled_tools,
        current_user_jira_client=user_jira_client,
        current_user_confluence_client=user_confluence_client,
    )
