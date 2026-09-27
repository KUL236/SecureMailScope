"""
Unit tests for app.pagination -- the fix for the "no pagination for large
PCAPs" gap on GET /api/sessions. Pure logic, no DB required.
"""
from app.pagination import normalize_pagination, total_pages


def test_defaults_when_nothing_supplied():
    page, page_size, offset = normalize_pagination(None, None)
    assert (page, page_size, offset) == (1, 50, 0)


def test_second_page_offset():
    page, page_size, offset = normalize_pagination(2, 50)
    assert (page, page_size, offset) == (2, 50, 50)


def test_negative_or_zero_page_clamped_to_one():
    page, _, offset = normalize_pagination(0, 20)
    assert (page, offset) == (1, 0)
    page, _, offset = normalize_pagination(-5, 20)
    assert (page, offset) == (1, 0)


def test_non_numeric_input_falls_back_to_defaults():
    page, page_size, offset = normalize_pagination("not-a-number", "also-not")
    assert (page, page_size, offset) == (1, 50, 0)


def test_page_size_capped_at_max():
    # Someone requesting page_size=999999 for a huge capture shouldn't be
    # able to force the whole table into one response again.
    _, page_size, _ = normalize_pagination(1, 999999)
    assert page_size == 200


def test_zero_or_negative_page_size_falls_back_to_default():
    _, page_size, _ = normalize_pagination(1, 0)
    assert page_size == 50
    _, page_size, _ = normalize_pagination(1, -10)
    assert page_size == 50


def test_total_pages_rounds_up():
    assert total_pages(101, 50) == 3
    assert total_pages(100, 50) == 2
    assert total_pages(1, 50) == 1


def test_total_pages_zero_when_no_rows():
    assert total_pages(0, 50) == 0
