"""Dependency providers for JiraFetcher and ConfluenceFetcher with context awareness.

Provides get_jira_fetcher and get_confluence_fetcher for use in tool functions.
"""

from __future__ import annotations

import dataclasses
import logging
import os
from typing import TYPE_CHECKING, Any

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastmcp import Context
from fastmcp.server.dependencies import get_http_request

from mcp_atlassian.confluence import ConfluenceConfig, ConfluenceFetcher
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.jira import JiraConfig, JiraFetcher
from mcp_atlassian.servers.context import AppContext, MainAppContext
from mcp_atlassian.utils.oauth import OAuthConfig

if TYPE_CHECKING:
    from mcp_atlassian.confluence.config import (
        ConfluenceConfig as UserConfluenceConfigType,
    )
    from mcp_atlassian.jira.config import JiraConfig as UserJiraConfigType

logger = logging.getLogger("mcp-atlassian.servers.dependencies")

security = HTTPBasic()

# --- Configuration ---
JIRA_ORG_URL_ENV = "JIRA_URL"
CONFLUENCE_ORG_URL_ENV = "CONFLUENCE_URL"


def _create_user_config_for_fetcher(
    base_config: JiraConfig | ConfluenceConfig,
    auth_type: str,
    credentials: dict[str, Any],
) -> JiraConfig | ConfluenceConfig:
    """Create a user-specific configuration for Jira or Confluence fetchers.

    Args:
        base_config: The base JiraConfig or ConfluenceConfig to clone and modify.
        auth_type: The authentication type ('oauth' or 'pat').
        credentials: Dictionary of credentials (token, email, etc).

    Returns:
        JiraConfig or ConfluenceConfig with user-specific credentials.

    Raises:
        ValueError: If required credentials are missing or auth_type is unsupported.
        TypeError: If base_config is not a supported type.
    """
    if auth_type not in ["oauth", "pat"]:
        raise ValueError(
            f"Unsupported auth_type '{auth_type}' for user-specific config creation. Expected 'oauth' or 'pat'."
        )

    username_for_config: str | None = credentials.get("user_email_context")

    logger.debug(
        f"Creating user config for fetcher. Auth type: {auth_type}, Credentials keys: {credentials.keys()}"
    )

    common_args: dict[str, Any] = {
        "url": base_config.url,
        "auth_type": auth_type,
        "ssl_verify": base_config.ssl_verify,
        "http_proxy": base_config.http_proxy,
        "https_proxy": base_config.https_proxy,
        "no_proxy": base_config.no_proxy,
        "socks_proxy": base_config.socks_proxy,
    }

    if auth_type == "oauth":
        user_access_token = credentials.get("oauth_access_token")
        if not user_access_token:
            raise ValueError(
                "OAuth access token missing in credentials for user auth_type 'oauth'"
            )
        if (
            not base_config
            or not hasattr(base_config, "oauth_config")
            or not getattr(base_config, "oauth_config", None)
            or not getattr(getattr(base_config, "oauth_config", None), "cloud_id", None)
        ):
            raise ValueError(
                f"Global OAuth config (with cloud_id) for {type(base_config).__name__} is missing, "
                "but user auth_type is 'oauth'. Cannot determine cloud_id."
            )
        global_oauth_cfg = base_config.oauth_config
        oauth_config_for_user = OAuthConfig(
            client_id=global_oauth_cfg.client_id if global_oauth_cfg else "",
            client_secret=global_oauth_cfg.client_secret if global_oauth_cfg else "",
            redirect_uri=global_oauth_cfg.redirect_uri if global_oauth_cfg else "",
            scope=global_oauth_cfg.scope if global_oauth_cfg else "",
            access_token=user_access_token,
            refresh_token=None,
            expires_at=None,
            cloud_id=global_oauth_cfg.cloud_id if global_oauth_cfg else "",
        )
        common_args.update(
            {
                "username": username_for_config,
                "api_token": None,
                "personal_token": None,
                "oauth_config": oauth_config_for_user,
            }
        )
    elif auth_type == "pat":
        user_pat = credentials.get("personal_access_token")
        if not user_pat:
            raise ValueError("PAT missing in credentials for user auth_type 'pat'")
        common_args.update(
            {
                "personal_token": user_pat,
                "oauth_config": None,
                "username": None,
                "api_token": None,
            }
        )

    if isinstance(base_config, JiraConfig):
        user_jira_config: UserJiraConfigType = dataclasses.replace(
            base_config, **common_args
        )
        user_jira_config.projects_filter = base_config.projects_filter
        return user_jira_config
    elif isinstance(base_config, ConfluenceConfig):
        user_confluence_config: UserConfluenceConfigType = dataclasses.replace(
            base_config, **common_args
        )
        user_confluence_config.spaces_filter = base_config.spaces_filter
        return user_confluence_config
    else:
        raise TypeError(f"Unsupported base_config type: {type(base_config)}")


async def get_jira_fetcher(ctx: Context) -> JiraFetcher:
    """Returns a JiraFetcher instance appropriate for the current request context.

    Args:
        ctx: The FastMCP context.

    Returns:
        JiraFetcher instance for the current user or global config.

    Raises:
        ValueError: If configuration or credentials are invalid.
    """
    logger.debug(f"get_jira_fetcher: ENTERED. Context ID: {id(ctx)}")
    try:
        request: Request = get_http_request()
        logger.debug(
            f"get_jira_fetcher: In HTTP request context. Request URL: {request.url}. "
            f"State.jira_fetcher exists: {hasattr(request.state, 'jira_fetcher') and request.state.jira_fetcher is not None}. "
            f"State.user_auth_type: {getattr(request.state, 'user_atlassian_auth_type', 'N/A')}. "
            f"State.user_token_present: {hasattr(request.state, 'user_atlassian_token') and request.state.user_atlassian_token is not None}."
        )
        # Use fetcher from request.state if already present
        if hasattr(request.state, "jira_fetcher") and request.state.jira_fetcher:
            logger.debug("get_jira_fetcher: Returning JiraFetcher from request.state.")
            return request.state.jira_fetcher
        user_auth_type = getattr(request.state, "user_atlassian_auth_type", None)
        logger.debug(f"get_jira_fetcher: User auth type: {user_auth_type}")
        # If OAuth or PAT token is present, create user-specific fetcher
        if user_auth_type in ["oauth", "pat"] and hasattr(
            request.state, "user_atlassian_token"
        ):
            user_token = getattr(request.state, "user_atlassian_token", None)
            user_email = getattr(
                request.state, "user_atlassian_email", None
            )  # May be None for PAT
            if not user_token:
                raise ValueError("User Atlassian token found in state but is empty.")
            credentials = {"user_email_context": user_email}
            if user_auth_type == "oauth":
                credentials["oauth_access_token"] = user_token
            elif user_auth_type == "pat":
                credentials["personal_access_token"] = user_token
            lifespan_ctx_dict = ctx.request_context.lifespan_context  # type: ignore
            app_lifespan_ctx: MainAppContext | None = (
                lifespan_ctx_dict.get("app_lifespan_context")
                if isinstance(lifespan_ctx_dict, dict)
                else None
            )
            if not app_lifespan_ctx or not app_lifespan_ctx.full_jira_config:
                raise ValueError(
                    "Jira global configuration (URL, SSL) is not available from lifespan context."
                )
            logger.info(
                f"Creating user-specific JiraFetcher (type: {user_auth_type}) for user {user_email or 'unknown'} (token ...{str(user_token)[-8:]})"
            )
            user_specific_config = _create_user_config_for_fetcher(
                base_config=app_lifespan_ctx.full_jira_config,
                auth_type=user_auth_type,
                credentials=credentials,
            )
            try:
                user_jira_fetcher = JiraFetcher(config=user_specific_config)
                current_user_id = user_jira_fetcher.get_current_user_account_id()
                logger.debug(
                    f"get_jira_fetcher: Validated Jira token for user ID: {current_user_id}"
                )
                request.state.jira_fetcher = user_jira_fetcher
                return user_jira_fetcher
            except Exception as e:
                logger.error(
                    f"get_jira_fetcher: Failed to create/validate user-specific JiraFetcher: {e}",
                    exc_info=True,
                )
                raise ValueError(f"Invalid user Jira token or configuration: {e}")
        else:
            logger.debug(
                f"get_jira_fetcher: No user-specific JiraFetcher. Auth type: {user_auth_type}. Token present: {hasattr(request.state, 'user_atlassian_token')}. Will use global fallback."
            )
    except RuntimeError:
        logger.debug(
            "Not in an HTTP request context. Attempting global JiraFetcher for non-HTTP."
        )
    # Fallback to global fetcher if not in HTTP context or no user info
    lifespan_ctx_dict_global = ctx.request_context.lifespan_context  # type: ignore
    app_lifespan_ctx_global: MainAppContext | None = (
        lifespan_ctx_dict_global.get("app_lifespan_context")
        if isinstance(lifespan_ctx_dict_global, dict)
        else None
    )
    if app_lifespan_ctx_global and app_lifespan_ctx_global.full_jira_config:
        logger.debug(
            "get_jira_fetcher: Using global JiraFetcher from lifespan_context. "
            f"Global config auth_type: {app_lifespan_ctx_global.full_jira_config.auth_type}"
        )
        return JiraFetcher(config=app_lifespan_ctx_global.full_jira_config)
    logger.error("Jira configuration could not be resolved.")
    raise ValueError(
        "Jira client (fetcher) not available. Ensure server is configured correctly."
    )


async def get_confluence_fetcher(ctx: Context) -> ConfluenceFetcher:
    """Returns a ConfluenceFetcher instance appropriate for the current request context.

    Args:
        ctx: The FastMCP context.

    Returns:
        ConfluenceFetcher instance for the current user or global config.

    Raises:
        ValueError: If configuration or credentials are invalid.
    """
    logger.debug(f"get_confluence_fetcher: ENTERED. Context ID: {id(ctx)}")
    try:
        request: Request = get_http_request()
        logger.debug(
            f"get_confluence_fetcher: In HTTP request context. Request URL: {request.url}. "
            f"State.confluence_fetcher exists: {hasattr(request.state, 'confluence_fetcher') and request.state.confluence_fetcher is not None}. "
            f"State.user_auth_type: {getattr(request.state, 'user_atlassian_auth_type', 'N/A')}. "
            f"State.user_token_present: {hasattr(request.state, 'user_atlassian_token') and request.state.user_atlassian_token is not None}."
        )
        if (
            hasattr(request.state, "confluence_fetcher")
            and request.state.confluence_fetcher
        ):
            logger.debug(
                "get_confluence_fetcher: Returning ConfluenceFetcher from request.state."
            )
            return request.state.confluence_fetcher
        user_auth_type = getattr(request.state, "user_atlassian_auth_type", None)
        logger.debug(f"get_confluence_fetcher: User auth type: {user_auth_type}")
        if user_auth_type in ["oauth", "pat"] and hasattr(
            request.state, "user_atlassian_token"
        ):
            user_token = getattr(request.state, "user_atlassian_token", None)
            user_email = getattr(request.state, "user_atlassian_email", None)
            if not user_token:
                raise ValueError("User Atlassian token found in state but is empty.")
            credentials = {"user_email_context": user_email}
            if user_auth_type == "oauth":
                credentials["oauth_access_token"] = user_token
            elif user_auth_type == "pat":
                credentials["personal_access_token"] = user_token
            lifespan_ctx_dict = ctx.request_context.lifespan_context  # type: ignore
            app_lifespan_ctx: MainAppContext | None = (
                lifespan_ctx_dict.get("app_lifespan_context")
                if isinstance(lifespan_ctx_dict, dict)
                else None
            )
            if not app_lifespan_ctx or not app_lifespan_ctx.full_confluence_config:
                raise ValueError(
                    "Confluence global configuration (URL, SSL) is not available from lifespan context."
                )
            logger.info(
                f"Creating user-specific ConfluenceFetcher (type: {user_auth_type}) for user {user_email or 'unknown'} (token ...{str(user_token)[-8:]})"
            )
            user_specific_config = _create_user_config_for_fetcher(
                base_config=app_lifespan_ctx.full_confluence_config,
                auth_type=user_auth_type,
                credentials=credentials,
            )
            try:
                user_confluence_fetcher = ConfluenceFetcher(config=user_specific_config)
                current_user_data = user_confluence_fetcher.get_current_user_info()
                # Try to get email from Confluence if not provided (can happen with PAT)
                derived_email = (
                    current_user_data.get("email")
                    if isinstance(current_user_data, dict)
                    else None
                )
                display_name = (
                    current_user_data.get("displayName")
                    if isinstance(current_user_data, dict)
                    else None
                )
                logger.debug(
                    f"get_confluence_fetcher: Validated Confluence token. User context: Email='{user_email or derived_email}', DisplayName='{display_name}'"
                )
                request.state.confluence_fetcher = user_confluence_fetcher
                if (
                    not user_email
                    and derived_email
                    and current_user_data
                    and isinstance(current_user_data, dict)
                    and current_user_data.get("email")
                ):
                    request.state.user_atlassian_email = current_user_data["email"]
                return user_confluence_fetcher
            except Exception as e:
                logger.error(
                    f"get_confluence_fetcher: Failed to create/validate user-specific ConfluenceFetcher: {e}"
                )
                raise ValueError(f"Invalid user Confluence token or configuration: {e}")
        else:
            logger.debug(
                f"get_confluence_fetcher: No user-specific ConfluenceFetcher. Auth type: {user_auth_type}. Token present: {hasattr(request.state, 'user_atlassian_token')}. Will use global fallback."
            )
    except RuntimeError:
        logger.debug(
            "Not in an HTTP request context. Attempting global ConfluenceFetcher for non-HTTP."
        )
    lifespan_ctx_dict_global = ctx.request_context.lifespan_context  # type: ignore
    app_lifespan_ctx_global: MainAppContext | None = (
        lifespan_ctx_dict_global.get("app_lifespan_context")
        if isinstance(lifespan_ctx_dict_global, dict)
        else None
    )
    if app_lifespan_ctx_global and app_lifespan_ctx_global.full_confluence_config:
        logger.debug(
            "get_confluence_fetcher: Using global ConfluenceFetcher from lifespan_context. "
            f"Global config auth_type: {app_lifespan_ctx_global.full_confluence_config.auth_type}"
        )
        return ConfluenceFetcher(config=app_lifespan_ctx_global.full_confluence_config)
    logger.error("Confluence configuration could not be resolved.")
    raise ValueError(
        "Confluence client (fetcher) not available. Ensure server is configured correctly."
    )


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
