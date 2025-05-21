from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_atlassian.confluence import ConfluenceFetcher
    from mcp_atlassian.confluence.config import ConfluenceConfig
    from mcp_atlassian.jira import JiraFetcher
    from mcp_atlassian.jira.config import JiraConfig


@dataclass(frozen=True)
class MainAppContext:
    """
    Context holding fully configured Jira and Confluence configurations
    loaded from environment variables at server startup.
    These configurations include any global/default authentication details.
    """

    full_jira_config: JiraConfig | None = None
    full_confluence_config: ConfluenceConfig | None = None
    read_only: bool = False
    enabled_tools: list[str] | None = None


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
