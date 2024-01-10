# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

##########################################################################
# export-usage-to-data-dog.py
#
# @authors: 
# Adi Zohar, Oct 07 2021
# Tony Markel, Oct 31 2023
#
# Supports Python 3
##########################################################################
# Application Command line parameters
#
#   -c config    - OCI CLI Config
#   -t profile   - profile inside the config file
#   -p proxy     - Set Proxy (i.e. www-proxy-server.com:80)
#   -ip          - Use Instance Principals for Authentication
#   -dt          - Use Instance Principals with delegation token for cloud shell
#   -ds date     - Start Date in YYYY-MM-DD format
#   -de date     - End Date in YYYY-MM-DD format (Not Inclusive)
#   -ld days     - Add Days Combined with Start Date (de is ignored if specified)
#
##########################################################################
# Info:
#    List Tenancy Usage
#
# Connectivity:
#    Option 1 - User Authentication
#       $HOME/.oci/config, please follow - https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm
#       OCI user part of ShowUsageGroup group with below Policy rules:
#          Allow group ShowUsageGroup to inspect tenancies in tenancy
#          Allow group ShowUsageGroup to read usage-report in tenancy
#
#    Option 2 - Instance Principle
#       Compute instance part of DynShowUsageGroup dynamic group with policy rules:
#          Allow dynamic group DynShowUsageGroup to inspect tenancies in tenancy
#          Allow dynamic group DynShowUsageGroup to read usage-report in tenancy
#
##########################################################################
# Modules Included:
# - oci.identity.IdentityClient
# - oci.usage_api.UsageapiClient
#
# APIs Used:
# - IdentityClient.get_tenancy               - Policy TENANCY_INSPECT
# - IdentityClient.list_region_subscriptions - Policy TENANCY_INSPECT
# - UsageapiClient.request_summarized_usages - read usage-report
#
##########################################################################

import sys
import argparse
import oci
import os
import platform
import io
import json
import logging
import re
import requests
from time import mktime
from datetime import datetime
from datetime import date
from datetime import timedelta

version = "2023.11.01"

##########################################################################
# Set all registered loggers to the configured log_level
##########################################################################
logging_level = os.getenv('LOGGING_LEVEL', 'INFO')
logging.basicConfig(level=logging_level)
loggers = [logging.getLogger()] + [logging.getLogger(name) for name in logging.root.manager.loggerDict]
[logger.setLevel(logging.getLevelName(logging_level)) for logger in loggers]
# Exception stack trace logging
is_tracing = eval(os.getenv('ENABLE_TRACING', "False"))

##########################################################################
# Create Default String for yesterday's usage data
##########################################################################
today_api = date.today()
yesterday_api = today_api - timedelta(days=1)
today = str(today_api)
yesterday = str(yesterday_api)


##########################################################################
# custom argparse *date* type for user dates
##########################################################################
def valid_date_type(arg_date_str):
    try:
        return datetime.strptime(arg_date_str, "%Y-%m-%d")
    except ValueError:
        msg = "Given Date ({0}) not valid! Expected format, YYYY-MM-DD!".format(arg_date_str)
        raise argparse.ArgumentTypeError(msg)


##########################################################################
# check service error to warn instead of error
##########################################################################
def check_service_error(code):
    return ('max retries exceeded' in str(code).lower() or
            'auth' in str(code).lower() or
            'notfound' in str(code).lower() or
            code == 'Forbidden' or
            code == 'TooManyRequests' or
            code == 'IncorrectState' or
            code == 'LimitExceeded'
            )


##########################################################################
# Create signer for Authentication
# Input - config_profile and is_instance_principals and is_delegation_token
# Output - config and signer objects
##########################################################################
def create_signer(config_file, config_profile, is_instance_principals, is_delegation_token):
    # if instance principals authentications
    if is_instance_principals:
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {'region': signer.region, 'tenancy': signer.tenancy_id}
            return config, signer

        except Exception:
            logging.getLogger().critical("Error obtaining instance principals certificate, aborting", 0)
            raise SystemExit

    # -----------------------------
    # Delegation Token
    # -----------------------------
    elif is_delegation_token:

        try:
            # check if env variables OCI_CONFIG_FILE, OCI_CONFIG_PROFILE exist and use them
            env_config_file = os.environ.get('OCI_CONFIG_FILE')
            env_config_section = os.environ.get('OCI_CONFIG_PROFILE')

            # check if file exist
            if env_config_file is None or env_config_section is None:
                logging.getLogger().critical(
                    "*** OCI_CONFIG_FILE and OCI_CONFIG_PROFILE env variables not found, abort. ***")
                logging.getLogger().critical("")
                raise SystemExit

            config = oci.config.from_file(env_config_file, env_config_section)
            delegation_token_location = config["delegation_token_file"]

            with open(delegation_token_location, 'r') as delegation_token_file:
                delegation_token = delegation_token_file.read().strip()
                # get signer from delegation token
                signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token=delegation_token)
                return config, signer

        except KeyError:
            logging.getLogger().critical("* Key Error obtaining delegation_token_file")
            raise SystemExit

        except Exception:
            raise

    # -----------------------------
    # config file authentication
    # -----------------------------
    else:
        config = oci.config.from_file(
            (config_file if config_file else oci.config.DEFAULT_LOCATION),
            (config_profile if config_profile else oci.config.DEFAULT_PROFILE)
        )
        signer = oci.signer.Signer(
            tenancy=config["tenancy"],
            user=config["user"],
            fingerprint=config["fingerprint"],
            private_key_file_location=config.get("key_file"),
            pass_phrase=oci.config.get_config_value_or_default(config, "pass_phrase"),
            private_key_content=config.get("key_content")
        )
        return config, signer


##########################################################################
# Data Dog Specific Functions
##########################################################################

# create metric names that conform to Data Dog standards
def get_metric_name(type):
    prefix = os.getenv('OCI_DATADOG_METRIC_PREFIX', 'oci')
    return f'{prefix}.{type}'


# strip spaces and special characters to create usable tags
def get_tag_name(sku_name):
    tag_name = re.sub('[^A-Za-z0-9]+', '', sku_name)
    return tag_name


# Usage Daily by Product to Data Dog API Format
def usage_by_product(usage_client, tenant_id, time_usage_started, time_usage_ended):
    data_dog_metric_data = []
    try:
        # Get oke pool tags
        request_summarized_usages_details = oci.usage_api.models.RequestSummarizedUsagesDetails(
            tenant_id=tenant_id,
            granularity='DAILY',
            query_type='COST',
            group_by=['tagNamespace', 'tagKey', 'tagValue'],
            filter=oci.usage_api.models.Filter(operator="AND", tags=[oci.usage_api.models.Tag(namespace='oke', key='pool')]),
            time_usage_started=time_usage_started.strftime('%Y-%m-%dT%H:%M:%SZ'),
            time_usage_ended=time_usage_ended.strftime('%Y-%m-%dT%H:%M:%SZ')
        )

        request_summarized_usages = usage_client.request_summarized_usages(
            request_summarized_usages_details,
            retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY
        )

        node_pool_tags = [i.tags[0] for i in request_summarized_usages.data.items]
        logging.getLogger().debug(f"Found following pool tags: {node_pool_tags}")

        # Since we can't filter by both skuName and tag at the same time, get cost data for each pool tag separately
        node_pool_tags.append({})  # Add empty tag to get cost data for cost metrics without pool tag
        for pool_tag in node_pool_tags:
            pool = pool_tag.value if pool_tag else None

            request_summarized_usages_details = oci.usage_api.models.RequestSummarizedUsagesDetails(
                tenant_id=tenant_id,
                granularity='DAILY',
                query_type='COST',
                filter=oci.usage_api.models.Filter(
                    operator="AND" if pool else "NOT",
                    tags=[oci.usage_api.models.Tag(namespace='oke', key='pool', value=pool)] if pool else [oci.usage_api.models.Tag(namespace='oke', key='pool')]
                ),
                group_by=['skuPartNumber', 'skuName', 'region', 'unit'],
                time_usage_started=time_usage_started.strftime('%Y-%m-%dT%H:%M:%SZ'),
                time_usage_ended=time_usage_ended.strftime('%Y-%m-%dT%H:%M:%SZ')
            )

            # usageClient.request_summarized_usages
            request_summarized_usages = usage_client.request_summarized_usages(
                request_summarized_usages_details,
                retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY
            )

            # print out request_summarized_usages.data.items to file
            logging.getLogger().debug(f"request_summarized_usages: {str(request_summarized_usages.data.items)}")

            min_date = None
            max_date = None
            currency = "USD"

            ################################
            # Add all cost data to Data Dog array - wayneyu (github)
            ################################
            tenancy = tenant_id
            timestamp = datetime.now().timestamp()
            for item in request_summarized_usages.data.items:
                # Usage Data
                name = get_tag_name(item.sku_name) if item.sku_name else "None"
                sku_name = item.sku_name if item.sku_name else "None"
                sku_part_number = item.sku_part_number if item.sku_part_number else "None"
                region = item.region if item.region else "None"
                unit = item.unit if item.unit else "None"
                pool = pool if pool else "Others"
                computed_amount = item.computed_amount if item.computed_amount else 0

                data_dog_metric_data.append({
                    "series": [
                        {
                            "metric": get_metric_name('usage'),
                            "type": 0,
                            "points": [
                                {
                                    "timestamp": int(timestamp),
                                    "value": item.computed_quantity
                                }
                            ],
                            "tags": [
                                "name:" + name,
                                "unit:" + unit,
                                "sku:" + sku_part_number,
                                "displayName:" + sku_name,
                                "region:" + region,
                                "tenancy:" + tenancy,
                                "pool:" + pool
                            ]
                        }
                    ],
                })

                # Cost Data

                data_dog_metric_data.append({
                    "series": [
                        {
                            "metric": get_metric_name('cost'),
                            "type": 0,
                            "unit": item.currency if item.currency else currency,
                            "points": [
                                {
                                    "timestamp": int(timestamp),
                                    "value": round(computed_amount, 2),
                                }
                            ],
                            "tags": [
                                "name:" + name,
                                "unit:" + unit,
                                "sku:" + sku_part_number,
                                "displayName:" + sku_name,
                                "region:" + region,
                                "tenancy:" + tenancy,
                                "pool:" + pool
                            ]
                        }
                    ],
                })

    except oci.exceptions.ServiceError as e:
        logging.getLogger().debug("\nService Error at 'usage_daily_product' - " + str(e))

    except Exception as e:
        logging.getLogger().debug("\nException Error at 'usage_daily_product' - " + str(e))

    # data_dog_metrics_json = json.dumps(data_dog_metric_data, indent=2)
    # logging.getLogger().info(data_dog_metrics_json)
    return data_dog_metric_data


# Upload to Data Dog
def upload_to_data_dog(metrics):
    logging.getLogger().info("Uploading to Data Dog")
    api_endpoint = os.getenv('DATADOG_METRICS_API_ENDPOINT', 'https://api.datadoghq.com/api/v2/series')
    api_key = os.getenv('DATADOG_API_KEY', 'not-configured')
    app_key = os.getenv('DATADOG_APP_KEY', 'not-configured')
    is_forwarding = eval(os.getenv('FORWARD_TO_DATADOG', "False"))

    if is_forwarding is False:
        print(metrics)
        logging.getLogger().error("DataDog forwarding is disabled - nothing sent")
        return

    if 'v2' not in api_endpoint:
        raise RuntimeError('Requires API endpoint version "v2": "{}"'.format(api_endpoint))

    # creating a session and adapter to avoid recreating
    # a new connection pool between each POST call

    try:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
        session.mount('https://', adapter)

        print("Exporting usage and cost metrics to DataDog")
        for series in metrics:
            api_headers = {'Content-type': 'application/json', 'DD-API-KEY': api_key, 'DD-APPLICATION-KEY': app_key}
            print(series)
            response = session.post(api_endpoint, data=json.dumps(series), headers=api_headers)
            print(response)
            if response.status_code != 202:
                raise Exception('error {} sending to DataDog: {}'.format(response.status_code, response.reason))

    finally:
        session.close()


##########################################################################
# Main Process
##########################################################################
def main():
    # Get Command Line Parser
    # parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                     formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80,
                                                                                         width=130))
    parser.add_argument('-c', default="", dest='config_file', help='OCI CLI Config file')
    parser.add_argument('-t', default="", dest='config_profile', help='Config Profile inside the config file')
    parser.add_argument('-p', default="", dest='proxy', help='Set Proxy (i.e. www-proxy-server.com:80) ')
    parser.add_argument('-ip', action='store_true', default=False, dest='is_instance_principals',
                        help='Use Instance Principals for Authentication')
    parser.add_argument('-dt', action='store_true', default=False, dest='is_delegation_token',
                        help='Use Delegation Token for Authentication')
    parser.add_argument("-ds", default=yesterday, dest='date_start', help="Start Date - format YYYY-MM-DD",
                        type=valid_date_type)
    parser.add_argument("-de", default=today, dest='date_end', help="End Date - format YYYY-MM-DD, (Not Inclusive)",
                        type=valid_date_type)
    parser.add_argument("-days", default=None, dest='days',
                        help="Add Days Combined with Start Date (de is ignored if specified)", type=int)
    cmd = parser.parse_args()

    # Log parameters used for debugging
    logging.getLogger().info("Running Export Usage to Data Dog", 0)
    logging.getLogger().debug("Machine         : " + platform.node() + " (" + platform.machine() + ")")
    logging.getLogger().debug("App Version     : " + version)
    logging.getLogger().debug("OCI SDK Version : " + oci.version.__version__)
    logging.getLogger().debug("Python Version  : " + platform.python_version())
    if cmd.is_instance_principals:
        logging.getLogger().debug("Authentication  : Instance Principals")
    elif cmd.is_delegation_token:
        logging.getLogger().debug("Authentication  : Instance Principals With Delegation Token")
    else:
        logging.getLogger().debug("Authentication  : Config File")
    logging.getLogger().debug("Date/Time       : " + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    logging.getLogger().debug("Command Line    : " + ' '.join(x for x in sys.argv[1:]))

    ############################################
    # Date Validation
    ############################################
    time_usage_started = None
    time_usage_ended = None
    report_type = "PRODUCT"

    if cmd.date_start and cmd.date_start > datetime.now():
        logging.getLogger().critical("\n!!! Error, Start date cannot be in the future !!!")
        raise SystemExit

    if cmd.date_start and cmd.date_end and cmd.date_start > cmd.date_end:
        logging.getLogger().critical("\n!!! Error, Start date cannot be greater than End date !!!")
        raise SystemExit

    if cmd.date_start:
        time_usage_started = cmd.date_start

    if cmd.days:
        time_usage_ended = time_usage_started + datetime.timedelta(days=cmd.days)
    elif cmd.date_end:
        time_usage_ended = cmd.date_end
    else:
        time_usage_ended = time_usage_started + datetime.timedelta(days=1)

    logging.getLogger().debug("Start Date      : " + time_usage_started.strftime('%m/%d/%Y'))
    logging.getLogger().debug("End Date        : " + time_usage_ended.strftime('%m/%d/%Y') + " Not Included")

    ############################################
    # Days check
    ############################################
    days = (time_usage_ended - time_usage_started).days

    if days > 93:
        logging.getLogger().critical("\n!!! Error, Max 93 days period allowed, input is " + str(days) + " days, !!!")
        raise SystemExit

    ############################################
    # create signer
    ############################################
    config, signer = create_signer(cmd.config_file, cmd.config_profile, cmd.is_instance_principals,
                                   cmd.is_delegation_token)
    tenant_id = ""

    logging.getLogger().info("Fetching data", 0)
    try:
        logging.getLogger().info("\nConnecting to Identity Service...\n")
        identity = oci.identity.IdentityClient(config, signer=signer)
        if cmd.proxy:
            identity.base_client.session.proxies = {'https': cmd.proxy}

        tenancy = identity.get_tenancy(config["tenancy"]).data
        regions = identity.list_region_subscriptions(tenancy.id).data
        tenant_id = tenancy.id

        # Set home region for connection
        for reg in regions:
            if reg.is_home_region:
                tenancy_home_region = str(reg.region_name)

        config['region'] = tenancy_home_region
        signer.region = tenancy_home_region

        logging.getLogger().debug("Tenant Name  : " + str(tenancy.name))
        logging.getLogger().debug("Tenant Id    : " + tenancy.id)
        logging.getLogger().debug("Home Region  : " + tenancy_home_region)

    except Exception as e:
        logging.getLogger().critical(e)
        raise RuntimeError("\nError fetching tenant information - " + str(e))

    ############################################
    # Get Data from UsageAPI
    ############################################
    try:
        logging.getLogger().info("\nConnecting to OCI UsageAPI Service...")
        usage_client = oci.usage_api.UsageapiClient(config, signer=signer)
        if cmd.proxy:
            usage_client.base_client.session.proxies = {'https': cmd.proxy}
        data_dog_metrics_data = usage_by_product(usage_client, tenant_id, time_usage_started, time_usage_ended)

    except Exception as e:
        logging.getLogger().critical(e)
        raise RuntimeError("\nError at main function - " + str(e))

    ############################################
    # Upload to Data Dog API
    ############################################
    try:
        logging.getLogger().info("\nUploading Data to the DataDog API...")
        upload_to_data_dog(data_dog_metrics_data)

    except Exception as e:
        logging.getLogger().critical(e)
        raise RuntimeError("\nError at main function - " + str(e))


##########################################################################
# Main Process
##########################################################################
main()
