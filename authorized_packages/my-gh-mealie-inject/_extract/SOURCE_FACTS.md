# Source facts ? my-gh-mealie-inject

- Upstream: mealie-recipes/mealie **v3.20.1**
- Path: RepositoryGeneric.page_all(search=...) -> add_search_to_query -> SearchFilter
- Sanitizer: SearchFilter._normalize_search / _build_search_list (query_search.py)
- Query filter: QueryFilterBuilder.filter_query builds SQLAlchemy column binds (builder.py)
- Sink modeled: run_sql (session.execute / Select)
- Control modeled: make_search_string + parameterize / bind_query before sink
- Package models normalize+parameterize-before-query for expected **refute**
