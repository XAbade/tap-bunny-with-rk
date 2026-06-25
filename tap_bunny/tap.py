"""Bunny tap class."""

from __future__ import annotations

from singer_sdk import Tap
from singer_sdk import typing as th  # JSON schema typing helpers

from tap_bunny import streams
from tap_bunny.client import BunnyAuthenticator

import argparse
import json
from typing import Dict

STREAM_TYPES = [
    streams.AccountsStream,
    streams.SubscriptionsStream,
    streams.ContactsStream,
    streams.AccountBalancesStream,
    streams.EntitiesStream,
    streams.InvoicesStream,
    streams.InvoiceItemsStream,
    streams.InvoiceForecastsStream,
    streams.PaymentsStream,
    streams.PaymentMethodsStream,
    streams.ProductsStream,
    streams.PlansStream,
    streams.QuotesStream,
    streams.QuoteChargesStream,
    streams.RecurringRevenuesStream,
    streams.RevenueMovementsStream,
    streams.SubscriptionChargesStream,
    streams.TransactionsStream,
    streams.TenantsStream,
    streams.FeatureUsagesStream,
    streams.FeaturesStream,
    streams.CreditNotesStream,
    streams.DealsStream,
    streams.UsersStream
]

class TapBunny(Tap):
    """Bunny tap class."""

    name = "tap-bunny"
    tap_name = "tap-bunny"

    config_jsonschema = th.PropertiesList(
        th.Property(
            "client_id",
            th.StringType,
            required=True,
            secret=True,
            title="Client ID",
            description="The OAuth2 client ID for authentication",
        ),
        th.Property(
            "client_secret",
            th.StringType,
            required=True,
            secret=True,
            title="Client Secret",
            description="The OAuth2 client secret for authentication",
        ),
        th.Property(
            "api_url",
            th.StringType,
            title="API URL",
            required=True,
            description="The base URL for the Bunny API service",
        ),
        th.Property(
            "start_date",
            th.DateTimeType,
            description="The earliest record date to sync",
        ),
        th.Property(
            "user_agent",
            th.StringType,
            description=(
                "A custom User-Agent header to send with each request. Default is "
                "'<tap_name>/<tap_version>'"
            ),
        ),
        th.Property(
            "incremental_sync",
            th.BooleanType,
            default=True,
            description="Whether to perform incremental sync (True) or full sync (False)",
        ),
    ).to_dict()

    def discover_streams(self) -> list[streams.BunnyStream]:
        """Return a list of discovered streams.

        Returns:
            A list of discovered streams.
        """
        return [
            streams.AccountsStream(self),
            streams.SubscriptionsStream(self),
            streams.ContactsStream(self),
            streams.AccountBalancesStream(self),
            streams.EntitiesStream(self),
            streams.InvoicesStream(self),
            streams.InvoiceItemsStream(self),
            streams.InvoiceForecastsStream(self),
            streams.PaymentsStream(self),
            streams.PaymentMethodsStream(self),
            streams.ProductsStream(self),
            streams.PlansStream(self),
            streams.QuotesStream(self),
            streams.QuoteChargesStream(self),
            streams.RecurringRevenuesStream(self),
            streams.RevenueMovementsStream(self),
            streams.SubscriptionChargesStream(self),
            streams.TransactionsStream(self),
            streams.TenantsStream(self),
            streams.FeatureUsagesStream(self),
            streams.FeaturesStream(self),
            streams.CreditNotesStream(self),
            streams.DealsStream(self),
            streams.UsersStream(self)
        ]

    def _get_auth_url(self) -> str:
        """Get the auth URL by appending /oauth/token to the API URL."""
        api_url = self.config.get("api_url")
        if not api_url:
            raise ValueError("api_url is required in the configuration")
        return f"{api_url.rstrip('/')}/oauth/token"

    def _get_authenticator(self) -> BunnyAuthenticator:
        """Get the authenticator instance."""
        auth_url = self._get_auth_url()
        return BunnyAuthenticator(self, auth_url=auth_url)

    def update_config(self, new_fields: Dict[str, str]) -> None:
        """Update the config.

        Args:
            new_fields: Dictionary of new fields to update in the config
        """
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', '--config', help='Config file', required=True)
        _args, unknown = parser.parse_known_args()
        config_file = _args.config
        with open(f"{config_file}", 'r') as filetoread:
            data = filetoread.read()
        self.logger.info(f"Config file: {data}")
        config = json.loads(data)
        config.update(new_fields)
        self.logger.info(f"Config: {config}")
        with open(f"{config_file}", 'w') as filetowrite:
            json.dump(config, filetowrite)


if __name__ == "__main__":
    TapBunny.cli()
