"""GraphQL client handling, including BunnyStream base class."""

from __future__ import annotations

import decimal
import typing as t
from datetime import datetime, timedelta
from typing import Optional, Any, Dict
import argparse
import json

import requests
from singer_sdk.authenticators import OAuthAuthenticator, SingletonMeta
from singer_sdk.streams import GraphQLStream

if t.TYPE_CHECKING:
    from singer_sdk.helpers.typing import Context


class BunnyAuthenticator(OAuthAuthenticator, metaclass=SingletonMeta):
    """Authenticator class for Bunny."""

    def __init__(self, stream, auth_url: str) -> None:
        """Init authenticator."""
        super().__init__(
            stream=stream,
            auth_endpoint=auth_url,
        )
        self._stream = stream
        self._access_token = stream.config.get("access_token")
        self._expires_at = stream.config.get("token_expires_at")
        if not self._access_token or not self._expires_at or datetime.now() >= datetime.fromisoformat(self._expires_at):
            self.update_access_token()

    def is_token_valid(self) -> bool:
        """Check if the current token is valid.
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        if not self._access_token or not self._expires_at:
            return False
        return datetime.now() < datetime.fromisoformat(self._expires_at)

    def handle_401_response(self, response: requests.Response) -> None:
        """Handle 401 Unauthorized response by refreshing the token.
        
        Args:
            response: The HTTP response that returned 401
            
        Raises:
            RuntimeError: If token refresh fails
        """
        if response.status_code == 401:
            self.logger.warning("Received 401 Unauthorized response. Attempting to refresh token...")
            try:
                self.update_access_token()
            except Exception as e:
                raise RuntimeError(f"Failed to refresh token after 401 response: {str(e)}")

    @property
    def oauth_request_body(self) -> dict:
        """Define the OAuth request body."""
        return {
            "grant_type": "client_credentials",
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
            "scope": "standard:read standard:write product:read product:write billing:read billing:write security:read admin:read",
        }

    def update_access_token(self) -> None:
        """Update `access_token` along with: `last_refreshed` and `expires_in`."""
        response = requests.post(
            self.auth_endpoint,
            data=self.oauth_request_body,
        )
        response.raise_for_status()
        auth_data = response.json()
        self._access_token = auth_data["access_token"]
        
        # Calculate expiration time using created_at timestamp
        created_at = datetime.fromtimestamp(auth_data["created_at"])
        expires_at = created_at + timedelta(seconds=auth_data["expires_in"])
        self._expires_at = expires_at.isoformat()
        
        # Update config with new token
        self._stream.update_config({
            "access_token": self._access_token,
            "token_expires_at": self._expires_at
        })

    @property
    def access_token(self) -> str:
        """Return the access token."""
        if not self._access_token or not self._expires_at:
            self.update_access_token()
        else:
            expires_at = datetime.fromisoformat(self._expires_at)
            # Refresh token if it expires in less than 5 minutes
            if datetime.now() + timedelta(minutes=5) >= expires_at:
                self.logger.info("Token expires in less than 5 minutes, refreshing...")
                self.update_access_token()
        return self._access_token

    @access_token.setter
    def access_token(self, value: str) -> None:
        """Set the access token."""
        self._access_token = value


class BunnyStream(GraphQLStream):
    """Bunny stream class."""

    def _request_with_backoff(self, prepared_request: requests.PreparedRequest, context: dict) -> requests.Response:
        """Execute a request with backoff and token refresh handling.
        
        Args:
            prepared_request: The prepared request to execute
            context: The stream context
            
        Returns:
            The HTTP response
            
        Raises:
            RuntimeError: If the request fails after token refresh
        """
        response = super()._request_with_backoff(prepared_request, context)
        
        # If we get a 401, try to refresh the token and retry once
        if response.status_code == 401:
            self.authenticator.handle_401_response(response)
            # Retry the request with the new token
            prepared_request.headers["Authorization"] = f"Bearer {self.authenticator.access_token}"
            response = super()._request_with_backoff(prepared_request, context)
            
        return response

    @property
    def url_base(self) -> str:
        """Return the API URL root, configurable via tap settings."""
        return self.config["api_url"]

    @property
    def authenticator(self) -> BunnyAuthenticator:
        """Return a new authenticator object."""
        # Use the tap's authenticator if available
        if hasattr(self._tap, "_get_authenticator"):
            return self._tap._get_authenticator()
        return BunnyAuthenticator(self, self.config["auth_url"])

    @property
    def http_headers(self) -> dict:
        """Return the http headers needed."""
        headers = {}
        if "user_agent" in self.config:
            headers["User-Agent"] = self.config["user_agent"]
        headers["Authorization"] = f"Bearer {self.authenticator.access_token}"
        headers["Content-Type"] = "application/json"
        return headers

    @property
    def incremental_sync(self) -> bool:
        """Return whether incremental sync is enabled.
        
        This property reads the incremental_sync setting from the config.
        If not specified, it defaults to False.
        """
        return self.config.get("incremental_sync", False)

    def get_starting_replication_key_value(self, context: dict | None) -> str | None:
        """Get starting replication key value based on state and config.

        Uses the Singer SDK's default incremental logic when a replication_key
        is defined and incremental_sync is enabled; otherwise returns ``None``.
        """
        # Only delegate to the base implementation when we actually want
        # incremental behaviour for this stream.
        if self.incremental_sync and getattr(self, "replication_key", None):
            return super().get_starting_replication_key_value(context)
        return None

    def get_starting_timestamp(self, context: dict | None) -> datetime | None:
        """Get starting timestamp based on state and config.

        This will typically use the tap's ``start_date`` plus any stored state
        when a replication_key is defined and incremental_sync is enabled.
        """
        if self.incremental_sync and getattr(self, "replication_key", None):
            return super().get_starting_timestamp(context)
        return None

    def get_next_page_token(
        self,
        response: requests.Response,
        previous_token: Optional[Any],
    ) -> Optional[Any]:
        """Return token for identifying next page or None if no more pages.
        
        This method handles cursor-based pagination for all Bunny streams.
        It extracts the next page token from the GraphQL response's pageInfo.
        
        Args:
            response: The HTTP response object
            previous_token: The previous page token
            
        Returns:
            The next page token if there are more pages, None otherwise
        """
        try:
            data = response.json()
            # Nome do campo conforme camelCase
            field_name = "".join(word.capitalize() for word in self.name.split("_"))
            field_name = field_name[0].lower() + field_name[1:]
            stream_data = data.get("data", {}).get(field_name, {})

            # nodes pode estar em nodes ou edges
            if "nodes" in stream_data:
                nodes = stream_data["nodes"]
            elif "edges" in stream_data:
                nodes = [edge["node"] for edge in stream_data["edges"]]
            else:
                nodes = []

            page_info = stream_data.get("pageInfo", {})
            has_next = page_info.get("hasNextPage")
            end_cursor = page_info.get("endCursor")

            # Dupla validação: se hasNextPage ou se nodes == 100
            if (has_next or (nodes and len(nodes) == 100)) and end_cursor:
                return end_cursor

            return None

        except Exception as e:
            self.logger.error(f"Error parsing pagination info: {str(e)}")
            return None

    def get_url_params(
        self,
        context: Optional[dict],
        next_page_token: Optional[Any],
    ) -> Dict[str, Any]:
        """Return a dictionary of values to be used in URL parameterization.
        
        This method handles the pagination parameters for all Bunny streams.
        It adds the 'after' parameter when a next page token is available.
        
        Args:
            context: The stream context
            next_page_token: The token for the next page
            
        Returns:
            A dictionary of URL parameters
        """
        params: dict = {}
        if next_page_token:
            params["after"] = next_page_token
        return params

    def get_graphql_variables(
        self,
        context: Optional[dict],
        next_page_token: Optional[Any],
    ) -> Dict[str, Any]:
        """Return a dictionary of values to be used in GraphQL variables.
        
        This now also pushes the incremental replication filter down to the API
        whenever possible, so the backend only returns records *after* the last
        synced replication_key rather than a full page which we filter locally.
        
        Args:
            context: The stream context
            next_page_token: The token for the next page
            
        Returns:
            A dictionary of GraphQL variables
        """
        variables: dict = {}
        
        # Add pagination variables
        if next_page_token:
            variables["after"] = next_page_token
            variables["first"] = 100
        else:
            variables["first"] = 100
            
        # Add sort variable if specified in config, else use id
        if getattr(self, "support_sort", True):
            if "sort" in self.config:
                variables["sort"] = self.config["sort"]
            else:
                variables["sort"] = "id"
        
        # ------------------------------------------------------------------
        # Incremental filter pushed down to the API
        # ------------------------------------------------------------------
        rk = getattr(self, "replication_key", None)
        auto_filter: str | None = None

        if rk and self.incremental_sync:
            # Decide which "starting point" helper to use.
            if self.is_timestamp_replication_key:
                start_val = self.get_starting_timestamp(context)
            else:
                start_val = self.get_starting_replication_key_value(context)

            if start_val is not None:
                # Allow streams to override the field used in the filter, e.g.
                # for nested fields like "invoice.updatedAt".
                filter_field = getattr(self, "filter_replication_key", rk)

                if isinstance(start_val, datetime):
                    value_str = start_val.isoformat()
                else:
                    value_str = str(start_val)

                # Bunny's GraphQL API accepts expressions like:
                #   "<field> is after <value>"
                auto_filter = f"{filter_field} is after {value_str}"

        # Add filter variable:
        # - If user provided a static filter, we keep it.
        # - If we also have an auto_filter, we combine them with AND.
        user_filter = self.config.get("filter")
        if user_filter and auto_filter:
            variables["filter"] = f"({user_filter}) and ({auto_filter})"
        elif auto_filter:
            variables["filter"] = auto_filter
        elif user_filter:
            variables["filter"] = user_filter
            
        # Add viewId variable if specified in config
        if "viewId" in self.config:
            variables["viewId"] = self.config["viewId"]
            
        # Add format variable if specified in config
        if "format" in self.config:
            variables["format"] = self.config["format"]
            
        return variables

    def parse_response(self, response: requests.Response) -> t.Generator[dict, None, None]:
        """Parse the response and return an iterator of result rows.
        
        Args:
            response: The HTTP response object
            
        Yields:
            Each record from the response
        """
        try:
            data = response.json()
            # Convert stream name to camelCase for GraphQL field name
            field_name = "".join(word.capitalize() for word in self.name.split("_"))
            field_name = field_name[0].lower() + field_name[1:]
            stream_data = data.get("data", {}).get(field_name, {})

            # Handle both nodes and edges-based pagination
            if "nodes" in stream_data:
                nodes = stream_data["nodes"]
            elif "edges" in stream_data:
                nodes = [edge["node"] for edge in stream_data["edges"]]
            else:
                nodes = []

            for record in nodes:
                yield record

        except Exception as e:
            self.logger.error(f"Error parsing response: {str(e)}")
            raise

    def post_process(
        self,
        row: dict,
        context: Context | None = None,
    ) -> dict | None:
        """Filter records according to replication_key and state.

        This mirrors the Sherpaan tap behaviour: on each run we only emit records
        whose replication_key value is newer than the stored bookmark (or
        ``start_date`` if no bookmark exists yet). Older records are skipped so
        downstream targets don't see full-history replays.

        Args:
            row: An individual record from the stream.
            context: The stream context.

        Returns:
            The updated record dictionary, or ``None`` to skip the record.
        """
        # If incremental sync is disabled or no replication_key is set,
        # just pass records through unchanged.
        rk = getattr(self, "replication_key", None)
        if not rk or not self.incremental_sync:
            return row

        # If the record has no replication_key value, keep it to avoid data loss.
        rk_value = row.get(rk)
        if rk_value is None:
            return row

        # Timestamp-based replication keys: use the SDK's starting timestamp helper.
        if self.is_timestamp_replication_key:
            start_ts = self.get_starting_timestamp(context)
            if start_ts is None:
                return row

            try:
                current_ts = datetime.fromisoformat(rk_value)
            except Exception:
                # If we can't parse the timestamp, don't drop the record.
                return row

            # Skip records older than or equal to the bookmark/start_date so that
            # we only emit records strictly *after* the stored replication_key.
            # This avoids returning the last record from the previous sync.
            if current_ts <= start_ts:
                return None
            return row

        # Non-timestamp replication keys: fall back to lexical comparison.
        start_val = self.get_starting_replication_key_value(context)
        if start_val is None:
            return row

        # Convert both to strings for a stable comparison.
        if str(rk_value) <= str(start_val):
            return None

        return row

    def prepare_request(
        self,
        context: dict,
        next_page_token: Optional[Any] = None,
    ) -> requests.PreparedRequest:
        """Prepare a request object for this stream.
        
        Args:
            context: Stream sync context
            next_page_token: Token for retrieving the next page
            
        Returns:
            A prepared request object
        """
        request = requests.Request(
            "POST",
            self.url_base + self.path,
            headers=self.http_headers,
            json={
                "query": self.query,
                "variables": self.get_graphql_variables(context, next_page_token),
            },
        )
        
        # Debug logging to see the request details
        self.logger.info(f"GraphQL Query for {self.name}: {self.query}")
        self.logger.info(f"GraphQL Variables for {self.name}: {self.get_graphql_variables(context, next_page_token)}")
        
        return request.prepare()
