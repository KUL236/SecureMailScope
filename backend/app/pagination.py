"""
Pagination for list endpoints that can return a lot of rows for a single
investigation -- session lists especially, since a large PCAP can reconstruct
thousands of TCP sessions and returning them all in one response is what was
blowing up the Sessions page for big captures.

normalize_pagination() is deliberately pure (no DB, no FastAPI) so it can be
unit tested on its own: it just turns whatever page/page_size came in on the
query string into safe, bounded values plus the SQL OFFSET to use.
"""
from typing import Optional, Tuple

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def normalize_pagination(
    page: Optional[int],
    page_size: Optional[int],
    *,
    default_page_size: int = DEFAULT_PAGE_SIZE,
    max_page_size: int = MAX_PAGE_SIZE,
) -> Tuple[int, int, int]:
    """Returns (page, page_size, offset), all clamped to sane bounds.

    - page < 1, missing, or not a number -> 1
    - page_size < 1, missing, or not a number -> default_page_size
    - page_size > max_page_size -> max_page_size (protects the DB and the
      frontend table from someone requesting page_size=999999)
    """
    try:
        page = int(page)
    except (TypeError, ValueError):
        page = 1
    if page < 1:
        page = 1

    try:
        page_size = int(page_size)
    except (TypeError, ValueError):
        page_size = default_page_size
    if page_size < 1:
        page_size = default_page_size
    if page_size > max_page_size:
        page_size = max_page_size

    offset = (page - 1) * page_size
    return page, page_size, offset


def total_pages(total_items: int, page_size: int) -> int:
    if total_items <= 0 or page_size <= 0:
        return 0
    return (total_items + page_size - 1) // page_size
