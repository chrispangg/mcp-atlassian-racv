import json
import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, Path, Query
from requests.exceptions import HTTPError

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.jira.constants import DEFAULT_READ_JIRA_FIELDS
from mcp_atlassian.servers.context import AppContext
from mcp_atlassian.servers.dependencies import get_current_user_context

router = APIRouter(prefix="/jira", tags=["jira"])
logger = logging.getLogger(__name__)


@router.get("/issue/{issue_key}", tags=["jira"])
async def get_issue(
    issue_key: str = Path(..., description="Jira issue key (e.g., 'PROJ-123')"),
    fields: str = Query(
        ",".join(DEFAULT_READ_JIRA_FIELDS),
        description=(
            "Comma-separated fields to return in the results. "
            "Use '*all' for all fields, or specify individual "
            "fields like 'summary,status,assignee,priority'"
        ),
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Get a Jira issue by key.

    Args:
        issue_key: Jira issue key.
        fields: Comma-separated fields to return.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the issue.
    """
    jira_fetcher = user_context.current_user_jira_client
    fields_list = None
    if fields and fields != "*all":
        fields_list = [f.strip() for f in fields.split(",")]

    issue = jira_fetcher.get_issue(issue_key=issue_key, fields=fields_list)
    return issue.to_simplified_dict()


@router.get("/search", tags=["jira"])
async def search_issues(
    jql: str = Query(
        ...,
        description=(
            "JQL query string (Jira Query Language). Examples:\n"
            '- Find Epics: "issuetype = Epic AND project = PROJ"\n'
            '- Find issues in Epic: "parent = PROJ-123"\n'
            "- Find by status: \"status = 'In Progress' AND project = PROJ\"\n"
            '- Find by assignee: "assignee = currentUser()"\n'
            '- Find recently updated: "updated >= -7d AND project = PROJ"\n'
            '- Find by label: "labels = frontend AND project = PROJ"\n'
        ),
    ),
    fields: str = Query(
        ",".join(DEFAULT_READ_JIRA_FIELDS),
        description=(
            "Comma-separated fields to return in the results. "
            "Use '*all' for all fields, or specify individual "
            "fields like 'summary,status,assignee,priority'"
        ),
    ),
    start_at: int = Query(
        0, ge=0, description="Starting index for pagination (0-based)"
    ),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of results (1-50)"),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Search for Jira issues using JQL.

    Args:
        jql: JQL query string.
        fields: Comma-separated fields to return.
        start_at: Starting index for pagination.
        limit: Maximum number of results.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the search results including pagination info.
    """
    jira_fetcher = user_context.current_user_jira_client
    fields_list = None
    if fields and fields != "*all":
        fields_list = [f.strip() for f in fields.split(",")]

    search_result = jira_fetcher.search_issues(
        jql=jql, fields=fields_list, start=start_at, limit=limit
    )
    return search_result.to_simplified_dict()


@router.get("/project/{project_key}/issues", tags=["jira"])
async def get_project_issues(
    project_key: str = Path(..., description="The project key"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of results (1-50)"),
    start_at: int = Query(
        0, ge=0, description="Starting index for pagination (0-based)"
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Get all issues for a specific Jira project.

    Args:
        project_key: The project key.
        limit: Maximum number of results.
        start_at: Starting index for pagination.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the search results including pagination info.
    """
    jira_fetcher = user_context.current_user_jira_client
    search_result = jira_fetcher.get_project_issues(
        project_key=project_key, start=start_at, limit=limit
    )
    return search_result.to_simplified_dict()


@router.get("/issue/{issue_key}/transitions", tags=["jira"])
async def get_transitions(
    issue_key: str = Path(..., description="Jira issue key (e.g., 'PROJ-123')"),
    user_context: AppContext = Depends(get_current_user_context),
) -> list[dict[str, Any]]:
    """Get available status transitions for a Jira issue.

    Args:
        issue_key: Jira issue key.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing a list of available transitions.
    """
    jira_fetcher = user_context.current_user_jira_client
    # Underlying method returns list[dict] in the desired format
    return jira_fetcher.get_available_transitions(issue_key)


@router.get("/issue/{issue_key}/worklog", tags=["jira"])
async def get_worklog(
    issue_key: str = Path(..., description="Jira issue key (e.g., 'PROJ-123')"),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Get worklog entries for a Jira issue.

    Args:
        issue_key: Jira issue key.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the worklog entries.
    """
    jira_fetcher = user_context.current_user_jira_client
    worklogs = jira_fetcher.get_worklogs(issue_key)
    return {"worklogs": worklogs}


@router.post("/issue/{issue_key}/download-attachments", tags=["jira"])
async def download_attachments(
    issue_key: str = Path(..., description="Jira issue key (e.g., 'PROJ-123')"),
    target_dir: str = Body(
        ..., description="Directory where attachments should be saved"
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Download attachments from a Jira issue.

    Args:
        issue_key: Jira issue key.
        target_dir: Directory to save attachments.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object indicating the result of the download operation.
    """
    jira_fetcher = user_context.current_user_jira_client
    return jira_fetcher.download_issue_attachments(
        issue_key=issue_key, target_dir=target_dir
    )


@router.get("/boards", tags=["jira"])
async def get_agile_boards(
    board_name: str = Query(
        "",
        description="(Optional) The name of board, support fuzzy search",
    ),
    project_key: str = Query(
        "",
        description="(Optional) Jira project key (e.g., 'PROJ')",
    ),
    board_type: str = Query(
        "",
        description="(Optional) The type of jira board (e.g., 'scrum', 'kanban')",
    ),
    start_at: int = Query(
        0, ge=0, description="Starting index for pagination (0-based)"
    ),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of results (1-50)"),
    user_context: AppContext = Depends(get_current_user_context),
) -> list[dict]:
    """Get jira agile boards by name, project key, or type.

    Args:
        board_name: Name of the board (fuzzy search).
        project_key: Project key.
        board_type: Board type ('scrum' or 'kanban').
        start_at: Starting index.
        limit: Maximum results.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing a list of board objects.
    """
    jira_fetcher = user_context.current_user_jira_client
    boards = jira_fetcher.get_all_agile_boards_model(
        board_name=board_name,
        project_key=project_key,
        board_type=board_type,
        start=start_at,
        limit=limit,
    )
    return [board.to_simplified_dict() for board in boards]


@router.get("/boards/{board_id}/issues", tags=["jira"])
async def get_board_issues(
    board_id: str = Path(..., description="The id of the board (e.g., '1001')"),
    jql: str = Query(
        ...,
        description=(
            "JQL query string (Jira Query Language). Examples:\n"
            '- Find Epics: "issuetype = Epic AND project = PROJ"\n'
            '- Find issues in Epic: "parent = PROJ-123"\n'
            "- Find by status: \"status = 'In Progress' AND project = PROJ\"\n"
            '- Find by assignee: "assignee = currentUser()"\n'
            '- Find recently updated: "updated >= -7d AND project = PROJ"\n'
            '- Find by label: "labels = frontend AND project = PROJ"\n'
            '- Find by priority: "priority = High AND project = PROJ"'
        ),
    ),
    fields: str = Query(
        ",".join(DEFAULT_READ_JIRA_FIELDS),
        description=(
            "Comma-separated fields to return in the results. "
            "Use '*all' for all fields, or specify individual "
            "fields like 'summary,status,assignee,priority'"
        ),
    ),
    start_at: int = Query(
        0, ge=0, description="Starting index for pagination (0-based)"
    ),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of results (1-50)"),
    expand: str = Query(
        "version",
        description="Optional fields to expand in the response (e.g., 'changelog').",
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Get all issues linked to a specific board filtered by JQL.

    Args:
        board_id: The ID of the board.
        jql: JQL query string to filter issues.
        fields: Comma-separated fields to return.
        start_at: Starting index for pagination.
        limit: Maximum number of results.
        expand: Optional fields to expand.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the search results including pagination info.
    """
    jira_fetcher = user_context.current_user_jira_client
    fields_list: str | list[str] | None = fields
    if fields and fields != "*all":
        fields_list = [f.strip() for f in fields.split(",")]

    search_result = jira_fetcher.get_board_issues(
        board_id=board_id,
        jql=jql,
        fields=fields_list,
        start=start_at,
        limit=limit,
        expand=expand,
    )
    return search_result.to_simplified_dict()


@router.get("/boards/{board_id}/sprints", tags=["jira"])
async def get_sprints_from_board(
    board_id: str = Path(..., description="The id of board (e.g., '1000')"),
    state: str = Query(
        "", description="Sprint state (e.g., 'active', 'future', 'closed')"
    ),
    start_at: int = Query(
        0, ge=0, description="Starting index for pagination (0-based)"
    ),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of results (1-50)"),
    user_context: AppContext = Depends(get_current_user_context),
) -> list[dict]:
    """Get jira sprints from board by state.

    Args:
        board_id: The ID of the board.
        state: Sprint state ('active', 'future', 'closed'). If empty, returns all sprints.
        start_at: Starting index.
        limit: Maximum results.
        user_context: Application context with user's Jira client.

    Returns:
        JSON array representing a list of sprint objects.
    """
    jira_fetcher = user_context.current_user_jira_client
    sprints = jira_fetcher.get_all_sprints_from_board_model(
        board_id=board_id, state=state, start=start_at, limit=limit
    )
    return [sprint.to_simplified_dict() for sprint in sprints]


@router.get("/sprints/{sprint_id}/issues", tags=["jira"])
async def get_sprint_issues(
    sprint_id: str = Path(..., description="The id of sprint (e.g., '10001')"),
    fields: str = Query(
        ",".join(DEFAULT_READ_JIRA_FIELDS),
        description=(
            "Comma-separated fields to return in the results. "
            "Use '*all' for all fields, or specify individual "
            "fields like 'summary,status,assignee,priority'"
        ),
    ),
    start_at: int = Query(
        0, ge=0, description="Starting index for pagination (0-based)"
    ),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of results (1-50)"),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Get jira issues from sprint.

    Args:
        sprint_id: The ID of the sprint.
        fields: Comma-separated fields to return.
        start_at: Starting index.
        limit: Maximum results.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the search results including pagination info.
    """
    jira_fetcher = user_context.current_user_jira_client
    fields_list: str | list[str] | None = fields
    if fields and fields != "*all":
        fields_list = [f.strip() for f in fields.split(",")]

    search_result = jira_fetcher.get_sprint_issues(
        sprint_id=sprint_id, fields=fields_list, start=start_at, limit=limit
    )
    return search_result.to_simplified_dict()


@router.get("/link-types", tags=["jira"])
async def get_link_types(
    user_context: AppContext = Depends(get_current_user_context),
) -> list[dict]:
    """Get all available issue link types.

    Args:
        user_context: Application context with user's Jira client.

    Returns:
        JSON array representing a list of issue link type objects.
    """
    jira_fetcher = user_context.current_user_jira_client
    link_types = jira_fetcher.get_issue_link_types()
    return [link_type.to_simplified_dict() for link_type in link_types]


@router.get("/user/{user_identifier}", tags=["jira"])
async def get_user_profile(
    user_identifier: str = Path(
        ...,
        description="Identifier for the user (e.g., email address 'user@example.com', username 'johndoe', account ID 'accountid:...', or key for Server/DC).",
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Retrieve profile information for a specific Jira user.

    Args:
        user_identifier: User identifier (email, username, key, or account ID).
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the Jira user profile object, or an error object if not found.
    """
    jira_fetcher = user_context.current_user_jira_client
    try:
        user = jira_fetcher.get_user_profile_by_identifier(user_identifier)
        result = user.to_simplified_dict()
        return {"success": True, "user": result}
    except Exception as e:
        error_message = ""
        log_level = logging.ERROR
        if isinstance(e, ValueError) and "not found" in str(e).lower():
            log_level = logging.WARNING
            error_message = str(e)
        elif isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        else:
            error_message = (
                "An unexpected error occurred while fetching the user profile."
            )
            logger.exception(
                f"Unexpected error in get_user_profile for '{user_identifier}':"
            )
        error_result = {
            "success": False,
            "error": str(e),
            "user_identifier": user_identifier,
        }
        logger.log(
            log_level,
            f"get_user_profile failed for '{user_identifier}': {error_message}",
        )
        return error_result


@router.get("/fields", tags=["jira"])
async def search_fields(
    keyword: str = Query(
        "",
        description="Keyword for fuzzy search. If left empty, lists the first 'limit' available fields in their default order.",
    ),
    limit: int = Query(10, ge=1, description="Maximum number of results"),
    refresh: bool = Query(False, description="Whether to force refresh the field list"),
    user_context: AppContext = Depends(get_current_user_context),
) -> list[dict]:
    """Search Jira fields by keyword with fuzzy match.

    Args:
        keyword: Keyword for fuzzy search.
        limit: Maximum number of results.
        refresh: Whether to force refresh the field list.
        user_context: Application context with user's Jira client.

    Returns:
        JSON array representing a list of matching field definitions.
    """
    jira_fetcher = user_context.current_user_jira_client
    return jira_fetcher.search_fields(keyword, limit=limit, refresh=refresh)


@router.post("/issues/batch-create", tags=["jira"])
async def batch_create_issues(
    issues: str = Body(
        ...,
        description=(
            "JSON array of issue objects. Each object should contain:\n"
            "- project_key (required): The project key (e.g., 'PROJ')\n"
            "- summary (required): Issue summary/title\n"
            "- issue_type (required): Type of issue (e.g., 'Task', 'Bug')\n"
            "- description (optional): Issue description\n"
            "- assignee (optional): Assignee username or email\n"
            "- components (optional): Array of component names\n"
            "Example: [\n"
            '  {"project_key": "PROJ", "summary": "Issue 1", "issue_type": "Task"},\n'
            '  {"project_key": "PROJ", "summary": "Issue 2", "issue_type": "Bug", "components": ["Frontend"]}\n'
            "]"
        ),
    ),
    validate_only: bool = Query(
        False, description="If true, only validates the issues without creating them"
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Create multiple Jira issues in a batch.

    Args:
        issues: JSON array string of issue objects.
        validate_only: If true, only validates without creating.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object indicating success and listing created issues (or validation result).
    """
    jira_fetcher = user_context.current_user_jira_client

    # Parse issues from JSON string
    try:
        issues_list = json.loads(issues)
        if not isinstance(issues_list, list):
            raise ValueError("Input 'issues' must be a JSON array string.")
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON in issues")
    except Exception as e:
        raise ValueError(f"Invalid input for issues: {e}") from e

    # Create issues in batch
    created_issues = jira_fetcher.batch_create_issues(
        issues_list, validate_only=validate_only
    )

    message = (
        "Issues validated successfully"
        if validate_only
        else "Issues created successfully"
    )
    return {
        "message": message,
        "issues": [issue.to_simplified_dict() for issue in created_issues],
    }


@router.post("/issues/batch-changelogs", tags=["jira"])
async def batch_get_changelogs(
    issue_ids_or_keys: list[str] = Body(
        ...,
        description="List of Jira issue IDs or keys, e.g. ['PROJ-123', 'PROJ-124']",
    ),
    fields: list[str] = Body(
        [],
        description="(Optional) Filter the changelogs by fields, e.g. ['status', 'assignee']. Default to [] for all fields.",
    ),
    limit: int = Query(
        -1,
        description=(
            "Maximum number of changelogs to return in result for each issue. "
            "Default to -1 for all changelogs. "
            "Notice that it only limits the results in the response, "
            "the function will still fetch all the data."
        ),
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> list[dict]:
    """Get changelogs for multiple Jira issues (Cloud only).

    Args:
        issue_ids_or_keys: List of issue IDs or keys.
        fields: List of fields to filter changelogs by. None for all fields.
        limit: Maximum changelogs per issue (-1 for all).
        user_context: Application context with user's Jira client.

    Returns:
        JSON array representing a list of issues with their changelogs.
    """
    jira_fetcher = user_context.current_user_jira_client

    # Ensure this runs only on Cloud, as per original function docstring
    if not jira_fetcher.config.is_cloud:
        raise NotImplementedError(
            "Batch get issue changelogs is only available on Jira Cloud."
        )

    # Call the underlying method
    issues_with_changelogs = jira_fetcher.batch_get_changelogs(
        issue_ids_or_keys=issue_ids_or_keys, fields=fields
    )

    # Format the response
    results = []
    limit_val = None if limit == -1 else limit
    for issue in issues_with_changelogs:
        results.append(
            {
                "issue_id": issue.id,
                "changelogs": [
                    changelog.to_simplified_dict()
                    for changelog in issue.changelogs[:limit_val]
                ],
            }
        )
    return results


@router.post("/issue", tags=["jira"])
async def create_issue(
    project_key: str = Body(
        ...,
        description=(
            "The JIRA project key (e.g. 'PROJ', 'DEV', 'SUPPORT'). "
            "This is the prefix of issue keys in your project."
        ),
    ),
    summary: str = Body(..., description="Summary/title of the issue"),
    issue_type: str = Body(
        ...,
        description=(
            "Issue type (e.g. 'Task', 'Bug', 'Story', 'Epic', 'Subtask'). "
            "The available types depend on your project configuration. "
            "For subtasks, use 'Subtask' (not 'Sub-task') and include parent in additional_fields."
        ),
    ),
    assignee: str = Body(
        "",
        description="(Optional) Assignee's user identifier (string): Email, display name, or account ID (e.g., 'user@example.com', 'John Doe', 'accountid:...')",
    ),
    description: str = Body("", description="Issue description"),
    components: str = Body(
        "",
        description="(Optional) Comma-separated list of component names to assign (e.g., 'Frontend,API')",
    ),
    additional_fields: dict[str, Any] = Body(
        {},
        description=(
            "(Optional) Dictionary of additional fields to set. Examples:\n"
            "- Set priority: {'priority': {'name': 'High'}}\n"
            "- Add labels: {'labels': ['frontend', 'urgent']}\n"
            "- Link to parent (for any issue type): {'parent': 'PROJ-123'}\n"
            "- Set Fix Version/s: {'fixVersions': [{'id': '10020'}]}\n"
            "- Custom fields: {'customfield_10010': 'value'}"
        ),
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Create a new Jira issue with optional Epic link or parent for subtasks.

    Args:
        project_key: The JIRA project key.
        summary: Summary/title of the issue.
        issue_type: Issue type (e.g., 'Task', 'Bug', 'Story', 'Epic', 'Subtask').
        assignee: Assignee's user identifier (string): Email, display name, or account ID (e.g., 'user@example.com', 'John Doe', 'accountid:...').
        description: Issue description.
        components: Comma-separated list of component names.
        additional_fields: Dictionary of additional fields.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the created issue object.
    """
    jira_fetcher = user_context.current_user_jira_client

    # Parse components from comma-separated string to list
    components_list = None
    if components and isinstance(components, str):
        components_list = [
            comp.strip() for comp in components.split(",") if comp.strip()
        ]

    # Use additional_fields directly as dict
    extra_fields = additional_fields or {}
    if not isinstance(extra_fields, dict):
        raise ValueError("additional_fields must be a dictionary.")

    issue = jira_fetcher.create_issue(
        project_key=project_key,
        summary=summary,
        issue_type=issue_type,
        description=description,
        assignee=assignee,
        components=components_list,
        **extra_fields,
    )
    result = issue.to_simplified_dict()
    return {"message": "Issue created successfully", "issue": result}


@router.put("/issue/{issue_key}", tags=["jira"])
async def update_issue(
    issue_key: str = Path(..., description="Jira issue key (e.g., 'PROJ-123')"),
    fields: dict[str, Any] = Body(
        ...,
        description=(
            "Dictionary of fields to update. For 'assignee', provide a string identifier (email, name, or accountId). "
            "Example: {'assignee': 'user@example.com', 'summary': 'New Summary'}"
        ),
    ),
    additional_fields: dict[str, Any] = Body(
        {},
        description="(Optional) Dictionary of additional fields to update. Use this for custom fields or more complex updates.",
    ),
    attachments: str = Body(
        "",
        description=(
            "(Optional) JSON string array or comma-separated list of file paths to attach to the issue. "
            "Example: '/path/to/file1.txt,/path/to/file2.txt' or ['/path/to/file1.txt','/path/to/file2.txt']"
        ),
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Update an existing Jira issue including changing status, adding Epic links, updating fields, etc.

    Args:
        issue_key: Jira issue key.
        fields: Dictionary of fields to update.
        additional_fields: Optional dictionary of additional fields.
        attachments: Optional JSON array string or comma-separated list of file paths.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the updated issue object and attachment results.
    """
    jira_fetcher = user_context.current_user_jira_client

    # Use fields directly as dict
    if not isinstance(fields, dict):
        raise ValueError("fields must be a dictionary.")
    update_fields = fields

    # Use additional_fields directly as dict
    extra_fields = additional_fields or {}
    if not isinstance(extra_fields, dict):
        raise ValueError("additional_fields must be a dictionary.")

    # Parse attachments
    attachment_paths = []
    if attachments:
        if isinstance(attachments, str):
            try:
                parsed = json.loads(attachments)
                if isinstance(parsed, list):
                    attachment_paths = [str(p) for p in parsed]
                else:
                    raise ValueError("attachments JSON string must be an array.")
            except json.JSONDecodeError:
                # Assume comma-separated if not valid JSON array
                attachment_paths = [
                    p.strip() for p in attachments.split(",") if p.strip()
                ]
        else:
            raise ValueError(
                "attachments must be a JSON array string or comma-separated string."
            )

    # Combine fields and additional_fields
    all_updates = {**update_fields, **extra_fields}
    if attachment_paths:
        all_updates["attachments"] = attachment_paths

    try:
        issue = jira_fetcher.update_issue(issue_key=issue_key, **all_updates)
        result = issue.to_simplified_dict()
        if (
            hasattr(issue, "custom_fields")
            and "attachment_results" in issue.custom_fields
        ):
            result["attachment_results"] = issue.custom_fields["attachment_results"]
        return {"message": "Issue updated successfully", "issue": result}
    except Exception as e:
        logger.error(f"Error updating issue {issue_key}: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to update issue {issue_key}: {str(e)}")


@router.delete("/issue/{issue_key}", tags=["jira"])
async def delete_issue(
    issue_key: str = Path(..., description="Jira issue key (e.g. PROJ-123)"),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Delete an existing Jira issue.

    Args:
        issue_key: Jira issue key.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object indicating success.
    """
    jira_fetcher = user_context.current_user_jira_client
    jira_fetcher.delete_issue(issue_key)
    return {"message": f"Issue {issue_key} has been deleted successfully."}


@router.post("/issue/{issue_key}/comment", tags=["jira"])
async def add_comment(
    issue_key: str = Path(..., description="Jira issue key (e.g., 'PROJ-123')"),
    comment: str = Body(..., description="Comment text in Markdown format"),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Add a comment to a Jira issue.

    Args:
        issue_key: Jira issue key.
        comment: Comment text in Markdown.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the added comment.
    """
    jira_fetcher = user_context.current_user_jira_client
    # add_comment returns dict
    return jira_fetcher.add_comment(issue_key, comment)


@router.post("/issue/{issue_key}/worklog", tags=["jira"])
async def add_worklog(
    issue_key: str = Path(..., description="Jira issue key (e.g., 'PROJ-123')"),
    time_spent: str = Body(
        ...,
        description=(
            "Time spent in Jira format. Examples: "
            "'1h 30m' (1 hour and 30 minutes), '1d' (1 day), '30m' (30 minutes), '4h' (4 hours)"
        ),
    ),
    comment: str = Body(
        "", description="(Optional) Comment for the worklog in Markdown format"
    ),
    started: str = Body(
        "",
        description=(
            "(Optional) Start time in ISO format. If not provided, the current time will be used. "
            "Example: '2023-08-01T12:00:00.000+0000'"
        ),
    ),
    original_estimate: str = Body(
        "", description="(Optional) New value for the original estimate"
    ),
    remaining_estimate: str = Body(
        "", description="(Optional) New value for the remaining estimate"
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Add a worklog entry to a Jira issue.

    Args:
        issue_key: Jira issue key.
        time_spent: Time spent in Jira format.
        comment: Optional comment in Markdown.
        started: Optional start time in ISO format.
        original_estimate: Optional new original estimate.
        remaining_estimate: Optional new remaining estimate.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the added worklog object.
    """
    jira_fetcher = user_context.current_user_jira_client
    # add_worklog returns dict
    worklog_result = jira_fetcher.add_worklog(
        issue_key=issue_key,
        time_spent=time_spent,
        comment=comment,
        started=started,
        original_estimate=original_estimate,
        remaining_estimate=remaining_estimate,
    )
    return {"message": "Worklog added successfully", "worklog": worklog_result}


@router.post("/issue/{issue_key}/epic/{epic_key}", tags=["jira"])
async def link_to_epic(
    issue_key: str = Path(
        ..., description="The key of the issue to link (e.g., 'PROJ-123')"
    ),
    epic_key: str = Path(
        ..., description="The key of the epic to link to (e.g., 'PROJ-456')"
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Link an existing issue to an epic.

    Args:
        issue_key: The key of the issue to link.
        epic_key: The key of the epic to link to.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the updated issue object.
    """
    jira_fetcher = user_context.current_user_jira_client
    issue = jira_fetcher.link_issue_to_epic(issue_key, epic_key)
    return {
        "message": f"Issue {issue_key} has been linked to epic {epic_key}.",
        "issue": issue.to_simplified_dict(),
    }


@router.post("/issues/link", tags=["jira"])
async def create_issue_link(
    link_type: str = Body(
        ...,
        description="The type of link to create (e.g., 'Duplicate', 'Blocks', 'Relates to')",
    ),
    inward_issue_key: str = Body(
        ..., description="The key of the inward issue (e.g., 'PROJ-123')"
    ),
    outward_issue_key: str = Body(
        ..., description="The key of the outward issue (e.g., 'PROJ-456')"
    ),
    comment: str = Body("", description="(Optional) Comment to add to the link"),
    comment_visibility: dict[str, str] = Body(
        {},
        description="(Optional) Visibility settings for the comment (e.g., {'type': 'group', 'value': 'jira-users'})",
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Create a link between two Jira issues.

    Args:
        link_type: The type of link (e.g., 'Blocks').
        inward_issue_key: The key of the source issue.
        outward_issue_key: The key of the target issue.
        comment: Optional comment text.
        comment_visibility: Optional dictionary for comment visibility.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object indicating success or failure.
    """
    jira_fetcher = user_context.current_user_jira_client
    if not all([link_type, inward_issue_key, outward_issue_key]):
        raise ValueError(
            "link_type, inward_issue_key, and outward_issue_key are required."
        )

    link_data = {
        "type": {"name": link_type},
        "inwardIssue": {"key": inward_issue_key},
        "outwardIssue": {"key": outward_issue_key},
    }

    if comment:
        comment_obj = {"body": comment}
        if comment_visibility and isinstance(comment_visibility, dict):
            if "type" in comment_visibility and "value" in comment_visibility:
                comment_obj["visibility"] = comment_visibility
            else:
                logger.warning("Invalid comment_visibility dictionary structure.")
        link_data["comment"] = comment_obj

    return jira_fetcher.create_issue_link(link_data)


@router.delete("/issues/link/{link_id}", tags=["jira"])
async def remove_issue_link(
    link_id: str = Path(..., description="The ID of the link to remove"),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Remove a link between two Jira issues.

    Args:
        link_id: The ID of the link to remove.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object indicating success.
    """
    jira_fetcher = user_context.current_user_jira_client
    if not link_id:
        raise ValueError("link_id is required")

    return jira_fetcher.remove_issue_link(link_id)


@router.post("/issue/{issue_key}/transition/{transition_id}", tags=["jira"])
async def transition_issue(
    issue_key: str = Path(..., description="Jira issue key (e.g., 'PROJ-123')"),
    transition_id: str = Path(
        ...,
        description=(
            "ID of the transition to perform. Use the get_transitions endpoint first "
            "to get the available transition IDs for the issue. Example values: '11', '21', '31'"
        ),
    ),
    fields: dict[str, Any] = Body(
        {},
        description=(
            "(Optional) Dictionary of fields to update during the transition. "
            "Some transitions require specific fields to be set (e.g., resolution). "
            "Example: {'resolution': {'name': 'Fixed'}}"
        ),
    ),
    comment: str = Body(
        "",
        description=(
            "(Optional) Comment to add during the transition. "
            "This will be visible in the issue history."
        ),
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Transition a Jira issue to a new status.

    Args:
        issue_key: Jira issue key.
        transition_id: ID of the transition.
        fields: Optional dictionary of fields to update during transition.
        comment: Optional comment for the transition.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the updated issue object.
    """
    jira_fetcher = user_context.current_user_jira_client
    if not issue_key or not transition_id:
        raise ValueError("issue_key and transition_id are required.")

    # Use fields directly as dict
    update_fields = fields or {}
    if not isinstance(update_fields, dict):
        raise ValueError("fields must be a dictionary.")

    issue = jira_fetcher.transition_issue(
        issue_key=issue_key,
        transition_id=transition_id,
        fields=update_fields,
        comment=comment,
    )

    return {
        "message": f"Issue {issue_key} transitioned successfully",
        "issue": issue.to_simplified_dict() if issue else None,
    }


@router.post("/boards/{board_id}/sprints", tags=["jira"])
async def create_sprint(
    board_id: str = Path(..., description="The id of board (e.g., '1000')"),
    sprint_name: str = Body(..., description="Name of the sprint (e.g., 'Sprint 1')"),
    start_date: str = Body(..., description="Start time for sprint (ISO 8601 format)"),
    end_date: str = Body(..., description="End time for sprint (ISO 8601 format)"),
    goal: str = Body("", description="(Optional) Goal of the sprint"),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Create Jira sprint for a board.

    Args:
        board_id: Board ID.
        sprint_name: Sprint name.
        start_date: Start date (ISO format).
        end_date: End date (ISO format).
        goal: Optional sprint goal.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the created sprint object.
    """
    jira_fetcher = user_context.current_user_jira_client
    sprint = jira_fetcher.create_sprint(
        board_id=board_id,
        sprint_name=sprint_name,
        start_date=start_date,
        end_date=end_date,
        goal=goal,
    )
    return sprint.to_simplified_dict()


@router.put("/sprints/{sprint_id}", tags=["jira"])
async def update_sprint(
    sprint_id: str = Path(..., description="The id of sprint (e.g., '10001')"),
    sprint_name: str = Body("", description="(Optional) New name for the sprint"),
    state: str = Body(
        "", description="(Optional) New state for the sprint (future|active|closed)"
    ),
    start_date: str = Body("", description="(Optional) New start date for the sprint"),
    end_date: str = Body("", description="(Optional) New end date for the sprint"),
    goal: str = Body("", description="(Optional) New goal for the sprint"),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Update jira sprint.

    Args:
        sprint_id: The ID of the sprint.
        sprint_name: Optional new name.
        state: Optional new state (future|active|closed).
        start_date: Optional new start date.
        end_date: Optional new end date.
        goal: Optional new goal.
        user_context: Application context with user's Jira client.

    Returns:
        JSON object representing the updated sprint object or an error message.
    """
    jira_fetcher = user_context.current_user_jira_client
    sprint = jira_fetcher.update_sprint(
        sprint_id=sprint_id,
        sprint_name=sprint_name,
        state=state,
        start_date=start_date,
        end_date=end_date,
        goal=goal,
    )

    if sprint is None:
        return {
            "error": f"Failed to update sprint {sprint_id}. Check logs for details."
        }
    else:
        return sprint.to_simplified_dict()
