import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from dependencies import AppContext, get_current_user_context
from dotenv import load_dotenv
from fastapi import Depends, FastAPI
from fastapi.security import HTTPBasic
from fastapi_mcp import FastApiMCP
from routes import confluence_api, jira_api

from mcp_atlassian.confluence.config import ConfluenceConfig
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.utils.environment import get_available_services
from mcp_atlassian.utils.io import is_read_only_mode
from mcp_atlassian.utils.tools import get_enabled_tools

load_dotenv(dotenv_path=".env", override=True)

logger = logging.getLogger(__name__)

# --- Configuration ---
JIRA_ORG_URL_ENV = "JIRA_URL"
CONFLUENCE_ORG_URL_ENV = "CONFLUENCE_URL"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[dict[str, Any]]:
    logger.info("FastAPI Atlassian MCP server lifespan starting...")
    services = get_available_services()
    read_only = is_read_only_mode()
    enabled_tools_filter = get_enabled_tools()

    global_jira_config: JiraConfig | None = None
    global_confluence_config: ConfluenceConfig | None = None

    jira_org_url = os.getenv(JIRA_ORG_URL_ENV)
    confluence_org_url = os.getenv(CONFLUENCE_ORG_URL_ENV)

    if services.get("jira") and jira_org_url:
        try:
            global_jira_config = JiraConfig(
                url=jira_org_url, username=None, api_token=None, auth_type="basic"
            )
            logger.info(f"Jira service available. Org URL: {jira_org_url}")
        except Exception as e:
            logger.error(
                f"Failed to initialize Jira service config: {e}", exc_info=True
            )

    if services.get("confluence") and confluence_org_url:
        try:
            global_confluence_config = ConfluenceConfig(
                url=confluence_org_url, username=None, api_token=None, auth_type="basic"
            )
            logger.info(f"Confluence service available. Org URL: {confluence_org_url}")
        except Exception as e:
            logger.error(
                f"Failed to initialize Confluence service config: {e}", exc_info=True
            )

    app.state.app_context = AppContext(
        jira_config=global_jira_config,
        confluence_config=global_confluence_config,
        read_only=read_only,
        enabled_tools=enabled_tools_filter,
    )
    logger.info(f"Read-only mode: {'ENABLED' if read_only else 'DISABLED'}")
    logger.info(f"Enabled tools filter: {enabled_tools_filter or 'All tools enabled'}")

    yield {"app_context": app.state.app_context}

    logger.info("FastAPI Atlassian MCP server lifespan shutting down.")


app = FastAPI(
    title="Atlassian MCP API",
    description="MCP integration for Jira and Confluence with FastAPI",
    version="1.0.0",
    lifespan=lifespan,
)
app.openapi_version = "3.0.0"

mcp = FastApiMCP(app)

security = HTTPBasic()


@app.get("/health", tags=["MCP"])
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/me", tags=["MCP"])
async def read_users_me(
    user_context: AppContext = Depends(get_current_user_context),
) -> dict[str, Any]:
    """Returns the authenticated user's context details (for testing auth)."""
    jira_user = "N/A"
    if user_context.current_user_jira_client:
        try:
            if user_context.jira_config and user_context.jira_config.username:
                jira_user = user_context.jira_config.username
        except Exception as e:
            jira_user = f"Error fetching Jira user: {e}"

    confluence_user = "N/A"
    if user_context.current_user_confluence_client:
        try:
            if (
                user_context.confluence_config
                and user_context.confluence_config.username
            ):
                confluence_user = user_context.confluence_config.username
        except Exception as e:
            confluence_user = f"Error fetching Confluence user: {e}"

    return {
        "authenticated_jira_user": jira_user,
        "authenticated_confluence_user": confluence_user,
        "jira_url": user_context.jira_config.url
        if user_context.jira_config
        else "Jira not configured for user",
        "confluence_url": user_context.confluence_config.url
        if user_context.confluence_config
        else "Confluence not configured for user",
        "read_only": user_context.read_only,
        "enabled_tools": user_context.enabled_tools,
    }


# Include the Confluence router
app.include_router(confluence_api.router)
app.include_router(jira_api.router)
mcp.mount()

logger.info("FastAPI application configured. MCP mounting complete.")

# To run this server (example using uvicorn):
# uvicorn src.mcp_atlassian.servers.server:app --reload --port 8000
# Remember to set environment variables for JIRA_ORG_URL, CONFLUENCE_ORG_URL.
# Username and API Key will be provided via Basic Auth.
