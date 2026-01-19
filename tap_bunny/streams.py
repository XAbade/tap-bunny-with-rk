"""Stream type classes for tap-bunny."""

from __future__ import annotations

import typing as t
from importlib import resources
from typing import Any, Dict, Optional
from datetime import datetime, timedelta

from singer_sdk import typing as th  # JSON Schema typing helpers
from singer_sdk.helpers.jsonpath import extract_jsonpath
import requests
import decimal

from tap_bunny.client import BunnyStream

# TODO: Delete this is if not using json files for schema definition
SCHEMAS_DIR = resources.files(__package__) / "schemas"


class GroupsStream(BunnyStream):
    """Define custom stream."""
    name = "groups"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("name", th.StringType),
        th.Property("id", th.StringType),
        th.Property("modified", th.DateTimeType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "modified"

    query = """
    query Groups($after: String, $sort: String) {
        groups(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                name
                modified
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class AccountsStream(BunnyStream):
    """Define custom stream."""

    name = "accounts"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountTypeId", th.StringType),
        th.Property("annualRevenue", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("arr", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("billingCity", th.StringType),
        th.Property("billingContactId", th.StringType),
        th.Property("billingCountry", th.StringType),
        th.Property("billingDay", th.IntegerType),
        th.Property("billingState", th.StringType),
        th.Property("billingStreet", th.StringType),
        th.Property("billingZip", th.StringType),
        th.Property("code", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("currencyId", th.StringType),
        th.Property("description", th.StringType),
        th.Property("duns", th.StringType),
        th.Property("employees", th.IntegerType),
        th.Property("entityId", th.StringType),
        th.Property("entityUseCode", th.StringType),
        th.Property("fax", th.StringType),
        th.Property("groupId", th.StringType),
        th.Property("industryId", th.StringType),
        th.Property("invoiceTemplateId", th.StringType),
        th.Property("linkedinUrl", th.StringType),
        th.Property("mrr", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("mur", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("name", th.StringType),
        th.Property("netPaymentDays", th.IntegerType),
        th.Property("ownerUserId", th.StringType),
        th.Property("payingStatus", th.StringType),
        th.Property("phone", th.StringType),
        th.Property("shippingCity", th.StringType),
        th.Property("shippingCountry", th.StringType),
        th.Property("shippingState", th.StringType),
        th.Property("shippingStreet", th.StringType),
        th.Property("shippingZip", th.StringType),
        th.Property("taxNumber", th.StringType),
        th.Property("taxNumberValidated", th.BooleanType),
        th.Property("timezone", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("website", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query Accounts($after: String, $sort: String) {
        accounts(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                accountTypeId
                annualRevenue
                arr
                billingCity
                billingContactId
                billingCountry
                billingDay
                billingState
                billingStreet
                billingZip
                code
                createdAt
                currencyId
                description
                duns
                employees
                entityId
                entityUseCode
                fax
                groupId
                industryId
                invoiceTemplateId
                linkedinUrl
                mrr
                mur
                name
                netPaymentDays
                ownerUserId
                payingStatus
                phone
                shippingCity
                shippingCountry
                shippingState
                shippingStreet
                shippingZip
                taxNumber
                taxNumberValidated
                timezone
                updatedAt
                website
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class SubscriptionsStream(BunnyStream):
    """Define custom stream."""

    name = "subscriptions"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("name", th.StringType),
        th.Property("period", th.StringType),
        th.Property("evergreen", th.BooleanType),
        th.Property("state", th.StringType),
        th.Property("currencyId", th.StringType),
        th.Property("priceListId", th.StringType),
        th.Property("provisioningRequired", th.BooleanType),
        th.Property("rampIntervalMonths", th.IntegerType),
        th.Property("startDate", th.DateTimeType),
        th.Property("endDate", th.DateTimeType),
        th.Property("trialStartDate", th.DateTimeType),
        th.Property("trialEndDate", th.DateTimeType),
        th.Property("trialPeriod", th.StringType),
        th.Property("cancellationDate", th.DateTimeType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("updatedAt", th.DateTimeType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query Subscriptions($after: String, $sort: String) {
        subscriptions(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                accountId
                name
                period
                evergreen
                state
                currencyId
                priceListId
                provisioningRequired
                rampIntervalMonths
                startDate
                endDate
                trialStartDate
                trialEndDate
                trialPeriod
                cancellationDate
                createdAt
                updatedAt
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class AccountBalancesStream(BunnyStream):
    """Define custom stream."""

    name = "account_balances"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("balance", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("currencyId", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]

    query = """
    query AccountBalances($after: String, $sort: String) {
        accountBalances(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                accountId
                balance
                currencyId
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class EntitiesStream(BunnyStream):
    """Define custom stream."""

    name = "entities"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("abbreviation", th.StringType),
        th.Property("accentColor", th.StringType),
        th.Property("baseCurrencyId", th.StringType),
        th.Property("billingCity", th.StringType),
        th.Property("billingCountry", th.StringType),
        th.Property("billingState", th.StringType),
        th.Property("billingStreet", th.StringType),
        th.Property("billingZip", th.StringType),
        th.Property("brandColor", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("customerServiceEmail", th.StringType),
        th.Property("emailSenderName", th.StringType),
        th.Property("emailTemplate", th.StringType),
        th.Property("fax", th.StringType),
        th.Property("fiscalYearStartMonth", th.IntegerType),
        th.Property("invoiceNumberPrefix", th.StringType),
        th.Property("invoiceNumberSeq", th.IntegerType),
        th.Property("invoicesImageUrl", th.StringType),
        th.Property("isDefault", th.BooleanType),
        th.Property("name", th.StringType),
        th.Property("phone", th.StringType),
        th.Property("privacyUrl", th.StringType),
        th.Property("quoteNumberPrefix", th.StringType),
        th.Property("quoteNumberSeq", th.IntegerType),
        th.Property("quotesImageUrl", th.StringType),
        th.Property("refundPolicyUrl", th.StringType),
        th.Property("taxId", th.StringType),
        th.Property("taxType", th.StringType),
        th.Property("termsUrl", th.StringType),
        th.Property("timezone", th.StringType),
        th.Property("topNavImageUrl", th.StringType),
        th.Property("tzIdentifier", th.StringType),
        th.Property("tzOffset", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("website", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query Entities($after: String, $sort: String) {
        entities(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                abbreviation
                accentColor
                baseCurrencyId
                billingCity
                billingCountry
                billingState
                billingStreet
                billingZip
                brandColor
                createdAt
                customerServiceEmail
                emailSenderName
                emailTemplate
                fax
                fiscalYearStartMonth
                invoiceNumberPrefix
                invoiceNumberSeq
                invoicesImageUrl
                isDefault
                name
                phone
                privacyUrl
                quoteNumberPrefix
                quoteNumberSeq
                quotesImageUrl
                refundPolicyUrl
                taxId
                taxType
                termsUrl
                timezone
                topNavImageUrl
                tzIdentifier
                tzOffset
                updatedAt
                website
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class InvoicesStream(BunnyStream):
    """Define custom stream."""

    name = "invoices"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("amount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("amountDue", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("amountPaid", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("createdAt", th.DateTimeType),
        th.Property("credits", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("currencyId", th.StringType),
        th.Property("description", th.StringType),
        th.Property("dueAt", th.DateTimeType),
        th.Property("issuedAt", th.DateTimeType),
        th.Property("kind", th.StringType),
        th.Property("netPaymentDays", th.IntegerType),
        th.Property("number", th.StringType),
        th.Property("paidAt", th.DateTimeType),
        th.Property("payableId", th.StringType),
        th.Property("poNumber", th.StringType),
        th.Property("quoteId", th.StringType),
        th.Property("smallUnitAmountDue", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("state", th.StringType),
        th.Property("subtotal", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("taxAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("url", th.StringType),
        th.Property("uuid", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query Invoices($after: String, $sort: String) {
        invoices(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                accountId
                amount
                amountDue
                amountPaid
                createdAt
                credits
                currencyId
                description
                dueAt
                issuedAt
                kind
                netPaymentDays
                number
                paidAt
                payableId
                poNumber
                quoteId
                smallUnitAmountDue
                state
                subtotal
                taxAmount
                updatedAt
                url
                uuid
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class InvoiceItemsStream(BunnyStream):
    """Define custom stream."""

    name = "invoice_items"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("amount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("chargeType", th.StringType),
        th.Property("couponId", th.StringType),
        th.Property("currencyId", th.StringType),
        th.Property("discount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("invoiceId", th.StringType),
        th.Property("kind", th.StringType),
        th.Property("lineText", th.StringType),
        th.Property("position", th.IntegerType),
        th.Property("price", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("priceDecimals", th.IntegerType),
        th.Property("prorationRate", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("quantity", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("subtotal", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("taxAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("taxCode", th.StringType),
        th.Property("vatCode", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]

    query = """
    query InvoiceItems($after: String, $sort: String) {
        invoiceItems(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                amount
                chargeType
                couponId
                currencyId
                discount
                invoiceId
                kind
                lineText
                position
                price
                priceDecimals
                prorationRate
                quantity
                subtotal
                taxAmount
                taxCode
                vatCode
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class PaymentsStream(BunnyStream):
    """Define custom stream."""

    name = "payments"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("amount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("amountUnapplied", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("baseCurrencyCash", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("baseCurrencyId", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("currencyId", th.StringType),
        th.Property("description", th.StringType),
        th.Property("isLegacy", th.BooleanType),
        th.Property("memo", th.StringType),
        th.Property("receivedAt", th.DateTimeType),
        th.Property("state", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("completedAt", th.DateTimeType),
        th.Property("conversionRate", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("errorCode", th.StringType),
        th.Property("errorMessage", th.StringType),
        th.Property("fees", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("paymentProcessor", th.StringType),
        th.Property("remoteTransactionId", th.StringType),
        th.Property("startedAt", th.DateTimeType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query Payments($after: String, $sort: String) {
        payments(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                accountId
                amount
                amountUnapplied
                baseCurrencyCash
                baseCurrencyId
                createdAt
                currencyId
                description
                isLegacy
                memo
                receivedAt
                state
                updatedAt
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class PaymentMethodsStream(BunnyStream):
    """Define custom stream."""

    name = "payment_methods"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("disabled", th.BooleanType),
        th.Property("expirationDate", th.DateTimeType),
        th.Property("failureCode", th.StringType),
        th.Property("lastSuccess", th.DateTimeType),
        th.Property("paymentType", th.StringType),
        th.Property("pluginId", th.StringType),
        th.Property("state", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"
    support_sort = False

    query = """
    query PaymentMethods($after: String, $before: String, $first: Int, $last: Int, $filter: String, $sort: String) {
        paymentMethods(after: $after, before: $before, first: $first, last: $last, filter: $filter, sort: $sort) {
            edges {
                cursor
                node {
                    accountId
                    createdAt
                    disabled
                    expirationDate
                    failureCode
                    id
                    lastSuccess
                    pluginId
                    updatedAt
                    paymentType
                    state
                }
            }
            totalCount
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class ProductsStream(BunnyStream):
    """Define custom stream."""

    name = "products"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("code", th.StringType),
        th.Property("description", th.StringType),
        th.Property("everythingInPlus", th.BooleanType),
        th.Property("internalNotes", th.StringType),
        th.Property("name", th.StringType),
        th.Property("platformId", th.StringType),
        th.Property("productCategoryId", th.StringType),
        th.Property("showProductNameOnLineItem", th.BooleanType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]

    query = """
    query Products($after: String, $sort: String) {
        products(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                code
                description
                everythingInPlus
                internalNotes
                name
                platformId
                productCategoryId
                showProductNameOnLineItem
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class PlansStream(BunnyStream):
    """Define custom stream."""

    name = "plans"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("addon", th.BooleanType),
        th.Property("basePrice", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("code", th.StringType),
        th.Property("contactUsLabel", th.StringType),
        th.Property("contactUsUrl", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("description", th.StringType),
        th.Property("internalNotes", th.StringType),
        th.Property("isVisible", th.BooleanType),
        th.Property("name", th.StringType),
        th.Property("position", th.IntegerType),
        th.Property("pricingDescription", th.StringType),
        th.Property("productId", th.StringType),
        th.Property("productPlanName", th.StringType),
        th.Property("selfServiceBuy", th.BooleanType),
        th.Property("selfServiceCancel", th.BooleanType),
        th.Property("selfServiceRenew", th.BooleanType),
        th.Property("updatedAt", th.DateTimeType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query Plans($after: String, $sort: String) {
        plans(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                addon
                basePrice
                code
                contactUsLabel
                contactUsUrl
                createdAt
                description
                internalNotes
                isVisible
                name
                position
                pricingDescription
                productId
                productPlanName
                selfServiceBuy
                selfServiceCancel
                selfServiceRenew
                updatedAt
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class QuotesStream(BunnyStream):
    """Define custom stream."""

    name = "quotes"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("acceptedByName", th.StringType),
        th.Property("acceptedByTitle", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("amount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("applicationDate", th.DateTimeType),
        th.Property("backdatedPeriods", th.CustomType({"type": ["boolean", "null"]})),
        th.Property("backdatedQuote", th.BooleanType),
        th.Property("billingDay", th.IntegerType),
        th.Property("contactId", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("credits", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("currencyId", th.StringType),
        th.Property("dealId", th.StringType),
        th.Property("discount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("discountValue", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("evergreen", th.BooleanType),
        th.Property("invoiceImmediately", th.BooleanType),
        th.Property("invoiceImmediatelyAvailable", th.BooleanType),
        th.Property("message", th.StringType),
        th.Property("name", th.StringType),
        th.Property("netPaymentDays", th.IntegerType),
        th.Property("notes", th.StringType),
        th.Property("number", th.StringType),
        th.Property("ownerId", th.StringType),
        th.Property("payableId", th.StringType),
        th.Property("periodAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("poNumber", th.StringType),
        th.Property("smallUnitAmountDue", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("splitInvoice", th.BooleanType),
        th.Property("state", th.StringType),
        th.Property("subtotal", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("taxAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("taxCode", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("uuid", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query Quotes($after: String, $sort: String) {
        quotes(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                acceptedByName
                acceptedByTitle
                accountId
                amount
                applicationDate
                backdatedPeriods
                backdatedQuote
                billingDay
                contactId
                createdAt
                credits
                currencyId
                dealId
                discount
                discountValue
                evergreen
                invoiceImmediately
                invoiceImmediatelyAvailable
                message
                name
                netPaymentDays
                notes
                number
                ownerId
                payableId
                periodAmount
                poNumber
                smallUnitAmountDue
                splitInvoice
                state
                subtotal
                taxAmount
                taxCode
                updatedAt
                uuid
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class QuoteChargesStream(BunnyStream):
    """Define custom stream."""

    name = "quote_charges"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("amount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("billingPeriod", th.StringType),
        th.Property("chargeType", th.StringType),
        th.Property("couponId", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("currencyId", th.StringType),
        th.Property("currentQuantity", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("discount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("invoiceLineText", th.StringType),
        th.Property("kind", th.StringType),
        th.Property("name", th.StringType),
        th.Property("price", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("priceDecimals", th.IntegerType),
        th.Property("priceListChargeId", th.StringType),
        th.Property("pricingModel", th.StringType),
        th.Property("prorationRate", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("quantity", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("quantityMax", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("quantityMin", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("quoteChangeId", th.StringType),
        th.Property("subtotal", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("taxAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("taxCode", th.StringType),
        th.Property("tieredAveragePrice", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("vatCode", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query QuoteCharges($after: String, $sort: String) {
        quoteCharges(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                amount
                billingPeriod
                chargeType
                couponId
                createdAt
                currencyId
                currentQuantity
                discount
                invoiceLineText
                kind
                name
                price
                priceDecimals
                priceListChargeId
                pricingModel
                prorationRate
                quantity
                quantityMax
                quantityMin
                quoteChangeId
                subtotal
                taxAmount
                taxCode
                tieredAveragePrice
                updatedAt
                vatCode
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class RecurringRevenuesStream(BunnyStream):
    """Define custom stream."""

    name = "recurring_revenues"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("currencyId", th.StringType),
        th.Property("recurringAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("totalAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("usageAmount", th.CustomType({"type": ["number", "string", "null"]})),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]

    query = """
    query RecurringRevenues($after: String, $sort: String) {
        recurringRevenues(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                accountId
                currencyId
                recurringAmount
                totalAmount
                usageAmount
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class RevenueMovementsStream(BunnyStream):
    """Define custom stream."""

    name = "revenue_movements"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("currencyId", th.StringType),
        th.Property("date", th.DateTimeType),
        th.Property("movementType", th.StringType),
        th.Property("recurringAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("totalAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("usageAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("usageMovementType", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]

    query = """
    query RevenueMovements($after: String, $sort: String) {
        revenueMovements(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                accountId
                currencyId
                date
                movementType
                recurringAmount
                totalAmount
                usageAmount
                usageMovementType
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class SubscriptionChargesStream(BunnyStream):
    """Define custom stream."""

    name = "subscription_charges"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("amount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("billingPeriod", th.StringType),
        th.Property("chargeType", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("discount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("discountedPrice", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("invoiceLineText", th.StringType),
        th.Property("kind", th.StringType),
        th.Property("name", th.StringType),
        th.Property("periodPrice", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("price", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("priceDecimals", th.IntegerType),
        th.Property("priceListChargeId", th.StringType),
        th.Property("priceListId", th.StringType),
        th.Property("pricingModel", th.StringType),
        th.Property("prorationRate", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("quantity", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("quantityMax", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("quantityMin", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("selfServiceQuantity", th.BooleanType),
        th.Property("subscriptionId", th.StringType),
        th.Property("tieredAveragePrice", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("updatedAt", th.DateTimeType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query SubscriptionCharges($after: String, $sort: String) {
        subscriptionCharges(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                amount
                billingPeriod
                chargeType
                createdAt
                discount
                discountedPrice
                invoiceLineText
                kind
                name
                periodPrice
                price
                priceDecimals
                priceListChargeId
                priceListId
                pricingModel
                prorationRate
                quantity
                quantityMax
                quantityMin
                selfServiceQuantity
                subscriptionId
                tieredAveragePrice
                updatedAt
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class TransactionsStream(BunnyStream):
    """Define custom stream."""

    name = "transactions"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("amount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("createdAt", th.DateTimeType),
        th.Property("currencyId", th.StringType),
        th.Property("description", th.StringType),
        th.Property("state", th.StringType),
        th.Property("transactionableId", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]

    query = """
    query Transactions($after: String, $sort: String) {
        transactions(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                accountId
                amount
                createdAt
                currencyId
                description
                state
                transactionableId
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class TenantsStream(BunnyStream):
    """Define custom stream."""

    name = "tenants"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("code", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("lastLogin", th.DateTimeType),
        th.Property("name", th.StringType),
        th.Property("platformId", th.StringType),
        th.Property("subdomain", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("userCount", th.IntegerType),
        th.Property("utilizationMetrics", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query Tenants($after: String, $sort: String) {
        tenants(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                accountId
                code
                createdAt
                lastLogin
                name
                platformId
                subdomain
                updatedAt
                userCount
                utilizationMetrics
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class ContactsStream(BunnyStream):
    """Define custom stream."""

    name = "contacts"
    path = "/graphql"
    primary_keys: t.ClassVar[list[str]] = ["id"]

    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("code", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("description", th.StringType),
        th.Property("email", th.StringType),
        th.Property("entityId", th.StringType),
        th.Property("firstName", th.StringType),
        th.Property("fullName", th.StringType),
        th.Property("lastName", th.StringType),
        th.Property("linkedinUrl", th.StringType),
        th.Property("mailingCity", th.StringType),
        th.Property("mailingCountry", th.StringType),
        th.Property("mailingState", th.StringType),
        th.Property("mailingStreet", th.StringType),
        th.Property("mailingZip", th.StringType),
        th.Property("mobile", th.StringType),
        th.Property("phone", th.StringType),
        th.Property("portalAccess", th.BooleanType),
        th.Property("salutation", th.StringType),
        th.Property("title", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query Contacts($after: String, $sort: String) {
        contacts(first: 100, after: $after, sort: $sort) {
            nodes {
                id
                accountId
                code
                createdAt
                description
                email
                entityId
                firstName
                fullName
                lastName
                linkedinUrl
                mailingCity
                mailingCountry
                mailingState
                mailingStreet
                mailingZip
                mobile
                phone
                portalAccess
                salutation
                title
                updatedAt
            }
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
        }
        """


class FeatureUsagesStream(BunnyStream):
    """Define custom stream."""

    name = "feature_usages"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("featureId", th.StringType),
        th.Property("quantity", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("subscriptionChargeId", th.StringType),
        th.Property("subscriptionId", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("usageAt", th.DateTimeType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query FeatureUsages($after: String, $before: String, $first: Int, $last: Int, $filter: String, $sort: String, $viewId: ID, $format: String) {
        featureUsages(after: $after, before: $before, first: $first, last: $last, filter: $filter, sort: $sort, viewId: $viewId, format: $format) {
            edges {
                cursor
                node {
                    accountId
                    createdAt
                    featureId
                    id
                    quantity
                    subscriptionChargeId
                    subscriptionId
                    updatedAt
                    usageAt
                }
            }
            totalCount
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class FeaturesStream(BunnyStream):
    """Define custom stream."""

    name = "features"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("code", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("description", th.StringType),
        th.Property("isProvisioned", th.BooleanType),
        th.Property("isUnit", th.BooleanType),
        th.Property("isVisible", th.BooleanType),
        th.Property("name", th.StringType),
        th.Property("position", th.IntegerType),
        th.Property("productId", th.StringType),
        th.Property("unitName", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query Features($after: String, $before: String, $first: Int, $last: Int, $filter: String, $sort: String, $viewId: ID, $format: String) {
        features(after: $after, before: $before, first: $first, last: $last, filter: $filter, sort: $sort, viewId: $viewId, format: $format) {
            edges {
                cursor
                node {
                    code
                    createdAt
                    description
                    id
                    isProvisioned
                    isUnit
                    isVisible
                    name
                    position
                    productId
                    unitName
                    updatedAt
                }
            }
            totalCount
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class CreditNotesStream(BunnyStream):
    """Define custom stream."""

    name = "credit_notes"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("amount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("amountApplied", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("amountUnapplied", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("createdAt", th.DateTimeType),
        th.Property("creditedInvoiceId", th.StringType),
        th.Property("currencyId", th.StringType),
        th.Property("description", th.StringType),
        th.Property("disputeReasonId", th.StringType),
        th.Property("entityId", th.StringType),
        th.Property("isCredit", th.BooleanType),
        th.Property("isLegacy", th.BooleanType),
        th.Property("issuedAt", th.DateTimeType),
        th.Property("number", th.StringType),
        th.Property("subtotal", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("taxAmount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("uuid", th.StringType),
        th.Property("warrenId", th.StringType),
        th.Property("state", th.StringType),
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query creditNotes ($after: String, $before: String, $first: Int, $last: Int, $filter: String, $sort: String, $viewId: ID, $format: String) {
        creditNotes (after: $after, before: $before, first: $first, last: $last, filter: $filter, sort: $sort, viewId: $viewId, format: $format) {
            edges {
                cursor
                node {
                    accountId
                    amount
                    amountApplied
                    amountUnapplied
                    createdAt
                    creditedInvoiceId
                    currencyId
                    description
                    disputeReasonId
                    entityId
                    id
                    isCredit
                    isLegacy
                    issuedAt
                    number
                    subtotal
                    taxAmount
                    updatedAt
                    uuid
                    warrenId
                }
            }
            totalCount
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class DealsStream(BunnyStream):
    """Define custom stream."""

    name = "deals"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("accountId", th.StringType),
        th.Property("amount", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("closeDate", th.DateTimeType),
        th.Property("code", th.StringType),
        th.Property("contactId", th.StringType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("currencyId", th.StringType),
        th.Property("dealStageId", th.StringType),
        th.Property("description", th.StringType),
        th.Property("entityId", th.StringType),
        th.Property("leadSourceId", th.StringType),
        th.Property("name", th.StringType),
        th.Property("notForRevenue", th.BooleanType),
        th.Property("ownerUserId", th.StringType),
        th.Property("probability", th.CustomType({"type": ["number", "string", "null"]})),
        th.Property("stageDescription", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("viaPortal", th.BooleanType)
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query deals ($after: String, $before: String, $first: Int, $last: Int, $filter: String, $sort: String, $viewId: ID, $format: String) {
        deals (after: $after, before: $before, first: $first, last: $last, filter: $filter, sort: $sort, viewId: $viewId, format: $format) {
            edges {
                cursor
                node {
                    accountId
                    amount
                    closeDate
                    code
                    contactId
                    createdAt
                    currencyId
                    dealStageId
                    description
                    entityId
                    id
                    leadSourceId
                    name
                    notForRevenue
                    ownerUserId
                    probability
                    stageDescription
                    updatedAt
                    viaPortal
                }
            }
            totalCount
            pageInfo {
                startCursor
                endCursor
                hasNextPage
                hasPreviousPage
            }
        }
    }
    """


class UsersStream(BunnyStream):
    """Define custom stream."""

    name = "users"
    path = "/graphql"
    schema = th.PropertiesList(
        th.Property("id", th.StringType),
        th.Property("allowLoginViaEmailLink", th.BooleanType),
        th.Property("createdAt", th.DateTimeType),
        th.Property("email", th.StringType),
        th.Property("enabled", th.BooleanType),
        th.Property("entityId", th.StringType),
        th.Property("firstName", th.StringType),
        th.Property("fullName", th.StringType),
        th.Property("groupId", th.StringType),
        th.Property("imageUrl", th.StringType),
        th.Property("lastLogin", th.DateTimeType),
        th.Property("lastName", th.StringType),
        th.Property("managerUserId", th.StringType),
        th.Property("name", th.StringType),
        th.Property("roleId", th.StringType),
        th.Property("title", th.StringType),
        th.Property("updatedAt", th.DateTimeType),
        th.Property("uuid", th.StringType)
    ).to_dict()
    primary_keys: t.ClassVar[list[str]] = ["id"]
    replication_key = "updatedAt"

    query = """
    query users ($after: String, $before: String, $first: Int, $last: Int, $filter: String, $sort: String, $viewId: ID, $format: String) {
        users (after: $after, before: $before, first: $first, last: $last, filter: $filter, sort: $sort, viewId: $viewId, format: $format) {
            edges {
                cursor
                node {
                    allowLoginViaEmailLink
                    createdAt
                    email
                    enabled
                    entityId
                    firstName
                    fullName
                    groupId
                    id
                    imageUrl
                    lastLogin
                    lastName
                    managerUserId
                    name
                    roleId
                    title
                    updatedAt
                    uuid
                }
                }
                totalCount
                pageInfo {
                    startCursor
                    endCursor
                    hasNextPage
                    hasPreviousPage
                }
            }
        }
    """
