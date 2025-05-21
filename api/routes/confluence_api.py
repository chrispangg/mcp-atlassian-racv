import logging
from typing import Annotated

from dependencies import AppContext, get_current_user_context
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/confluence", tags=["confluence"])


@router.get("/search", operation_id="confluence_search", tags=["confluence"])
async def search(
    query: Annotated[
        str,
        Query(
            description=(
                "Search query - can be either a simple text (e.g. 'project documentation') or a CQL query string. "
                "Simple queries use 'siteSearch' by default, to mimic the WebUI search, with an automatic fallback "
                "to 'text' search if not supported. Examples of CQL:\n"
                "- Basic search: 'type=page AND space=DEV'\n"
                "- Personal space search: 'space=\"~username\"' (note: personal space keys starting with ~ must be quoted)\n"
                "- Search by title: 'title~\"Meeting Notes\"'\n"
                "- Use siteSearch: 'siteSearch ~ \"important concept\"'\n"
                "- Use text search: 'text ~ \"important concept\"'\n"
                "- Recent content: 'created >= \"2023-01-01\"'\n"
                "- Content with specific label: 'label=documentation'\n"
                "- Recently modified content: 'lastModified > startOfMonth(\"-1M\")'\n"
                "- Content modified this year: 'creator = currentUser() AND lastModified > startOfYear()'\n"
                "- Content you contributed to recently: 'contributor = currentUser() AND lastModified > startOfWeek()'\n"
                "- Content watched by user: 'watcher = \"user@domain.com\" AND type = page'\n"
                '- Exact phrase in content: \'text ~ "\\"Urgent Review Required\\"" AND label = "pending-approval"\'\n'
                '- Title wildcards: \'title ~ "Minutes*" AND (space = "HR" OR space = "Marketing")\'\n'
                'Note: Special identifiers need proper quoting in CQL: personal space keys (e.g., "~username"), '
                "reserved words, numeric IDs, and identifiers with special characters."
            ),
        ),
    ],
    limit: Annotated[
        int,
        Query(
            description="Maximum number of results (1-50)",
            ge=1,
            le=50,
        ),
    ] = 10,
    spaces_filter: Annotated[
        str,
        Query(
            description=(
                "(Optional) Comma-separated list of space keys to filter results by. "
                "Overrides the environment variable CONFLUENCE_SPACES_FILTER if provided."
            ),
        ),
    ] = "",
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Search Confluence content using simple terms or CQL.

    Args:
        query: Search query - can be simple text or a CQL query string.
        limit: Maximum number of results (1-50).
        spaces_filter: Comma-separated list of space keys to filter by.
        confluence_fetcher: Confluence client instance (injected).

    Returns:
        JSON object representing a list of simplified Confluence page objects.
    """
    # Check if the query is a simple search term or already a CQL query
    confluence_fetcher = user_context.current_user_confluence_client
    if query and not any(
        x in query for x in ["=", "~", ">", "<", " AND ", " OR ", "currentUser()"]
    ):
        original_query = query
        try:
            query = f'siteSearch ~ "{original_query}"'
            logger.info(
                f"Converting simple search term to CQL using siteSearch: {query}"
            )
            pages = confluence_fetcher.search(
                query, limit=limit, spaces_filter=spaces_filter
            )
        except Exception as e:
            logger.warning(f"siteSearch failed ('{e}'), falling back to text search.")
            query = f'text ~ "{original_query}"'
            logger.info(f"Falling back to text search with CQL: {query}")
            pages = confluence_fetcher.search(
                query, limit=limit, spaces_filter=spaces_filter
            )
    else:
        pages = confluence_fetcher.search(
            query, limit=limit, spaces_filter=spaces_filter
        )

    search_results = [page.to_simplified_dict() for page in pages]
    return {"results": search_results}


@router.get("/page", operation_id="confluence_get_page", tags=["confluence"])
async def get_page(
    page_id: Annotated[
        str,
        Query(
            description=(
                "Confluence page ID (numeric ID, can be found in the page URL). "
                "For example, in the URL 'https://example.atlassian.net/wiki/spaces/TEAM/pages/123456789/Page+Title', "
                "the page ID is '123456789'. "
                "Provide this OR both 'title' and 'space_key'. If page_id is provided, title and space_key will be ignored."
            )
        ),
    ] = "",
    title: Annotated[
        str,
        Query(
            description=(
                "The exact title of the Confluence page. Use this with 'space_key' if 'page_id' is not known."
            )
        ),
    ] = "",
    space_key: Annotated[
        str,
        Query(
            description=(
                "The key of the Confluence space where the page resides (e.g., 'DEV', 'TEAM'). Required if using 'title'."
            )
        ),
    ] = "",
    include_metadata: Annotated[
        bool,
        Query(
            description="Whether to include page metadata such as creation date, last update, version, and labels."
        ),
    ] = True,
    convert_to_markdown: Annotated[
        bool,
        Query(
            description=(
                "Whether to convert page to markdown (true) or keep it in raw HTML format (false). "
                "Raw HTML can reveal macros (like dates) not visible in markdown, but CAUTION: "
                "using HTML significantly increases token usage in AI responses."
            )
        ),
    ] = True,
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Get content of a specific Confluence page by its ID, or by its title and space key.

    Args:
        page_id: Confluence page ID. If provided, 'title' and 'space_key' are ignored.
        title: The exact title of the page. Must be used with 'space_key'.
        space_key: The key of the space. Must be used with 'title'.
        include_metadata: Whether to include page metadata.
        convert_to_markdown: Convert content to markdown (true) or keep raw HTML (false).
        user_context: Application context with user's Confluence client.

    Returns:
        JSON object representing the page content and/or metadata, or an error if not found or parameters are invalid.
    """
    confluence_fetcher = user_context.current_user_confluence_client
    page_object = None

    if page_id:
        if title or space_key:
            logger.warning(
                "page_id was provided; title and space_key parameters will be ignored."
            )
        try:
            page_object = confluence_fetcher.get_page_content(
                page_id, convert_to_markdown=convert_to_markdown
            )
        except Exception as e:
            logger.error(f"Error fetching page by ID '{page_id}': {e}")
            return {"error": f"Failed to retrieve page by ID '{page_id}': {e}"}
    elif title and space_key:
        page_object = confluence_fetcher.get_page_by_title(
            space_key, title, convert_to_markdown=convert_to_markdown
        )
        if not page_object:
            return {
                "error": f"Page with title '{title}' not found in space '{space_key}'."
            }
    else:
        raise ValueError(
            "Either 'page_id' OR both 'title' and 'space_key' must be provided."
        )

    if not page_object:
        return {"error": "Page not found with the provided identifiers."}

    if include_metadata:
        result = {"metadata": page_object.to_simplified_dict()}
    else:
        result = {"content": {"value": page_object.content}}

    return result


@router.get("/page/{page_id}/children", tags=["confluence"])
async def get_page_children(
    page_id: str = Path(
        ..., description="The ID of the parent page whose children you want to retrieve"
    ),
    expand: str = Query(
        "version",
        description="Fields to expand in the response (e.g., 'version', 'body.storage')",
    ),
    limit: int = Query(
        25, ge=1, le=50, description="Maximum number of child pages to return (1-50)"
    ),
    include_content: bool = Query(
        False, description="Whether to include the page content in the response"
    ),
    convert_to_markdown: bool = Query(
        True,
        description="Whether to convert page content to markdown (true) or keep it in raw HTML format (false). Only relevant if include_content is true.",
    ),
    start: int = Query(0, ge=0, description="Starting index for pagination (0-based)"),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Get child pages of a specific Confluence page.

    Args:
        page_id: The ID of the parent page.
        expand: Fields to expand.
        limit: Maximum number of child pages.
        include_content: Whether to include page content.
        convert_to_markdown: Convert content to markdown if include_content is true.
        start: Starting index for pagination.
        user_context: Application context with user's Confluence client.

    Returns:
        JSON object representing a list of child page objects.
    """
    confluence_fetcher = user_context.current_user_confluence_client
    if include_content and "body" not in expand:
        expand = f"{expand},body.storage" if expand else "body.storage"

    try:
        pages = confluence_fetcher.get_page_children(
            page_id=page_id,
            start=start,
            limit=limit,
            expand=expand,
            convert_to_markdown=convert_to_markdown,
        )
        child_pages = [page.to_simplified_dict() for page in pages]
        result = {
            "parent_id": page_id,
            "count": len(child_pages),
            "limit_requested": limit,
            "start_requested": start,
            "results": child_pages,
        }
    except Exception as e:
        logger.error(
            f"Error getting/processing children for page ID {page_id}: {e}",
            exc_info=True,
        )
        result = {"error": f"Failed to get child pages: {e}"}

    return result


@router.get("/page/{page_id}/comments", tags=["confluence"])
async def get_comments(
    page_id: str = Path(
        ...,
        description="Confluence page ID (numeric ID, can be parsed from URL, e.g. from 'https://example.atlassian.net/wiki/spaces/TEAM/pages/123456789/Page+Title' -> '123456789')",
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Get comments for a specific Confluence page.

    Args:
        page_id: Confluence page ID.
        user_context: Application context with user's Confluence client.

    Returns:
        JSON object representing a list of comment objects.
    """
    confluence_fetcher = user_context.current_user_confluence_client
    comments = confluence_fetcher.get_page_comments(page_id)
    formatted_comments = [comment.to_simplified_dict() for comment in comments]
    return {"comments": formatted_comments}


@router.get("/page/{page_id}/labels", tags=["confluence"])
async def get_labels(
    page_id: str = Path(
        ...,
        description="Confluence page ID (numeric ID, can be parsed from URL, e.g. from 'https://example.atlassian.net/wiki/spaces/TEAM/pages/123456789/Page+Title' -> '123456789')",
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Get labels for a specific Confluence page.

    Args:
        page_id: Confluence page ID.
        user_context: Application context with user's Confluence client.

    Returns:
        JSON object representing a list of label objects.
    """
    confluence_fetcher = user_context.current_user_confluence_client
    labels = confluence_fetcher.get_page_labels(page_id)
    formatted_labels = [label.to_simplified_dict() for label in labels]
    return {"labels": formatted_labels}


@router.post("/page/{page_id}/labels", tags=["confluence"])
async def add_label(
    page_id: str = Path(..., description="The ID of the page to update"),
    label_data: dict = Body(
        ..., description="Label data", example={"name": "documentation"}
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Add label to an existing Confluence page.

    Args:
        page_id: The ID of the page to update.
        label_data: The label data containing the name of the label.
        user_context: Application context with user's Confluence client.

    Returns:
        JSON object representing the updated list of label objects for the page.

    Raises:
        HTTPException: If in read-only mode or Confluence client is unavailable.
    """
    if user_context.read_only:
        raise HTTPException(status_code=403, detail="Server is in read-only mode")

    name = label_data.get("name")
    if not name:
        raise HTTPException(status_code=400, detail="Label name is required")

    confluence_fetcher = user_context.current_user_confluence_client
    labels = confluence_fetcher.add_page_label(page_id, name)
    formatted_labels = [label.to_simplified_dict() for label in labels]
    return {"labels": formatted_labels}


@router.post("/pages", tags=["confluence"])
async def create_page(
    page_data: dict = Body(
        ...,
        description="Page data",
        example={
            "space_key": "DEV",
            "title": "New Page Title",
            "content": "# Heading\nThis is the page content in Markdown format.",
            "parent_id": "123456789",
        },
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Create a new Confluence page.

    Args:
        page_data: The page data containing space_key, title, content, and optional parent_id.
        user_context: Application context with user's Confluence client.

    Returns:
        JSON object representing the created page object.

    Raises:
        HTTPException: If in read-only mode or Confluence client is unavailable.
    """
    if user_context.read_only:
        raise HTTPException(status_code=403, detail="Server is in read-only mode")

    space_key = page_data.get("space_key")
    title = page_data.get("title")
    content = page_data.get("content")
    parent_id = page_data.get("parent_id", "")

    if not space_key or not title or not content:
        raise HTTPException(
            status_code=400, detail="space_key, title, and content are required"
        )

    confluence_fetcher = user_context.current_user_confluence_client
    page = confluence_fetcher.create_page(
        space_key=space_key,
        title=title,
        body=content,
        parent_id=parent_id,
        is_markdown=True,
    )
    result = page.to_simplified_dict()
    return {"message": "Page created successfully", "page": result}


@router.put("/page/{page_id}", tags=["confluence"])
async def update_page(
    page_id: str = Path(..., description="The ID of the page to update"),
    page_data: dict = Body(
        ...,
        description="Page data",
        example={
            "title": "Updated Page Title",
            "content": "# Updated Heading\nThis is the updated page content in Markdown format.",
            "is_minor_edit": False,
            "version_comment": "Updated content",
            "parent_id": "123456789",
        },
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Update an existing Confluence page.

    Args:
        page_id: The ID of the page to update.
        page_data: The page data containing title, content, and optional parameters.
        user_context: Application context with user's Confluence client.

    Returns:
        JSON object representing the updated page object.

    Raises:
        HTTPException: If in read-only mode or Confluence client is unavailable.
    """
    if user_context.read_only:
        raise HTTPException(status_code=403, detail="Server is in read-only mode")

    title = page_data.get("title")
    content = page_data.get("content")
    is_minor_edit = page_data.get("is_minor_edit", False)
    version_comment = page_data.get("version_comment", "")
    parent_id = page_data.get("parent_id", "")

    if not title or not content:
        raise HTTPException(status_code=400, detail="title and content are required")

    confluence_fetcher = user_context.current_user_confluence_client
    actual_parent_id = parent_id if parent_id else None

    updated_page = confluence_fetcher.update_page(
        page_id=page_id,
        title=title,
        body=content,
        is_minor_edit=is_minor_edit,
        version_comment=version_comment,
        is_markdown=True,
        parent_id=actual_parent_id,
    )
    page_data = updated_page.to_simplified_dict()
    return {"message": "Page updated successfully", "page": page_data}


@router.delete("/page/{page_id}", tags=["confluence"])
async def delete_page(
    page_id: str = Path(..., description="The ID of the page to delete"),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Delete an existing Confluence page.

    Args:
        page_id: The ID of the page to delete.
        user_context: Application context with user's Confluence client.

    Returns:
        JSON object indicating success or failure.

    Raises:
        HTTPException: If in read-only mode or Confluence client is unavailable.
    """
    if user_context.read_only:
        raise HTTPException(status_code=403, detail="Server is in read-only mode")

    confluence_fetcher = user_context.current_user_confluence_client
    try:
        result = confluence_fetcher.delete_page(page_id=page_id)
        if result:
            response = {
                "success": True,
                "message": f"Page {page_id} deleted successfully",
            }
        else:
            response = {
                "success": False,
                "message": f"Unable to delete page {page_id}. API request completed but deletion unsuccessful.",
            }
    except Exception as e:
        logger.error(f"Error deleting Confluence page {page_id}: {str(e)}")
        response = {
            "success": False,
            "message": f"Error deleting page {page_id}",
            "error": str(e),
        }

    return response


@router.post("/page/{page_id}/comments", tags=["confluence"])
async def add_comment(
    page_id: str = Path(..., description="The ID of the page to add a comment to"),
    comment_data: dict = Body(
        ...,
        description="Comment data",
        example={"content": "This is a comment in Markdown format."},
    ),
    user_context: AppContext = Depends(get_current_user_context),
) -> dict:
    """Add a comment to a Confluence page.

    Args:
        page_id: The ID of the page to add a comment to.
        comment_data: The comment data containing the content.
        user_context: Application context with user's Confluence client.

    Returns:
        JSON object representing the created comment.

    Raises:
        HTTPException: If in read-only mode or Confluence client is unavailable.
    """
    if user_context.read_only:
        raise HTTPException(status_code=403, detail="Server is in read-only mode")

    content = comment_data.get("content")
    if not content:
        raise HTTPException(status_code=400, detail="Comment content is required")

    confluence_fetcher = user_context.current_user_confluence_client
    try:
        comment = confluence_fetcher.add_comment(page_id=page_id, content=content)
        if comment:
            comment_data = comment.to_simplified_dict()
            response = {
                "success": True,
                "message": "Comment added successfully",
                "comment": comment_data,
            }
        else:
            response = {
                "success": False,
                "message": f"Unable to add comment to page {page_id}. API request completed but comment creation unsuccessful.",
            }
    except Exception as e:
        logger.error(f"Error adding comment to Confluence page {page_id}: {str(e)}")
        response = {
            "success": False,
            "message": f"Error adding comment to page {page_id}",
            "error": str(e),
        }

    return response
