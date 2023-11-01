# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

##########################################################################
# export-usage-to-data-dog.py
#
# @authors: 
# Adi Zohar, Oct 07 2021
# Tony Markel, Oct 31 2021
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
from fdk import response
from time import mktime
from datetime import datetime
from datetime import date
from datetime import timedelta

version = "2023.11.01"

##########################################################################
# Create Default String for yesterday's usage data
##########################################################################
today_api = date.today()
yesterday_api = today_api - timedelta(days = 1)
today = str(today_api)
yesterday = str(yesterday_api)

##########################################################################
# Print header centered
##########################################################################
def print_header(name, category):
    options = {0: 120, 1: 100, 2: 90, 3: 85}
    chars = int(options[category])
    print("")
    print('#' * chars)
    print("#" + name.center(chars - 2, " ") + "#")
    print('#' * chars)

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
            print_header("Error obtaining instance principals certificate, aborting", 0)
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
                print("*** OCI_CONFIG_FILE and OCI_CONFIG_PROFILE env variables not found, abort. ***")
                print("")
                raise SystemExit

            config = oci.config.from_file(env_config_file, env_config_section)
            delegation_token_location = config["delegation_token_file"]

            with open(delegation_token_location, 'r') as delegation_token_file:
                delegation_token = delegation_token_file.read().strip()
                # get signer from delegation token
                signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token=delegation_token)

                return config, signer

        except KeyError:
            print("* Key Error obtaining delegation_token_file")
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
def get_usage_metric(sku_name,type):
    metric_prefix = 'oci.usage.'
    metric_type = type + '.'
    metric_name = re.sub('.$','',re.sub('[ ]+', '.', re.sub('[^A-Za-z0-9\ ]+', '', sku_name))).lower()
    usage_metric= metric_prefix + metric_type + metric_name
    return usage_metric

# strip spaces and special characters to create usable tags  
def get_tag_name(sku_name):
    tag_name = re.sub('[^A-Za-z0-9]+', '', sku_name)
    return tag_name

# Usage Daily by Product to Data Dog API Format
def usage_by_product(usageClient, tenant_id, time_usage_started, time_usage_ended):

    try:
        # oci.usage_api.models.RequestSummarizedUsagesDetails
        requestSummarizedUsagesDetails = oci.usage_api.models.RequestSummarizedUsagesDetails(
            tenant_id=tenant_id,
            granularity='DAILY',
            query_type='COST',
            group_by=['skuPartNumber', 'skuName', 'region', 'unit'],
            time_usage_started=time_usage_started.strftime('%Y-%m-%dT%H:%M:%SZ'),
            time_usage_ended=time_usage_ended.strftime('%Y-%m-%dT%H:%M:%SZ')
        )

        # usageClient.request_summarized_usages
        request_summarized_usages = usageClient.request_summarized_usages(
            requestSummarizedUsagesDetails,
            retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY
        )

        min_date = None
        max_date = None
        currency = "USD"

        ################################
        # Add all cost data to Data Dog array - wayneyu (github)
        ################################
        data_dog_metric_data = []
        tenancy=tenant_id
        # Usage Data
        for item in request_summarized_usages.data.items:
            data_dog_metric_data.append({
                "series" : [
                    {
                        "metric" : get_usage_metric(item.sku_name,'usage'),
                        "type": 0,
                        "points": [
                            {
                                "timestamp": time_usage_started.timestamp(),
                                "value": item.computed_quantity
                            }
                        ],
                        "tags": [
                            "name:"+get_tag_name(item.sku_name),
                            "unit:"+item.unit,
                            "sku:"+item.sku_part_number,
                            "displayName:"+item.sku_name,
                            "region:"+item.region,
                            "tenancy:"+tenancy
                        ]
                    }
                ],
            })
        # Cost Data
        for item in request_summarized_usages.data.items:
            data_dog_metric_data.append({
                "series": [
                    {
                        "metric" : get_usage_metric(item.sku_name,'cost'),
                        "type": 0,
                        "points": [
                            {
                                "timestamp": time_usage_started.timestamp(),
                                "value": item.computed_amount,
                            }
                        ],
                        "tags": [
                            "name:"+get_tag_name(item.sku_name),
                            "unit:"+item.unit,
                            "sku:"+item.sku_part_number,
                            "displayName:"+item.sku_name,
                            "region:"+item.region,
                            "tenancy:"+tenancy
                        ]
                    }
                ],
            })

    except oci.exceptions.ServiceError as e:
        print("\nService Error at 'usage_daily_product' - " + str(e))

    except Exception as e:
        print("\nException Error at 'usage_daily_product' - " + str(e))

    data_dog_metrics_json = json.dumps(data_dog_metric_data, indent=2)
    print(data_dog_metrics_json)
    return data_dog_metrics_json

# Upload to Data Dog
def upload_to_data_dog(metrics):
    print("Uploading to Data Dog")

##########################################################################
# Main Process
##########################################################################
def main():

    # Get Command Line Parser
    # parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser(usage=argparse.SUPPRESS, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80, width=130))
    parser.add_argument('-c', default="", dest='config_file', help='OCI CLI Config file')
    parser.add_argument('-t', default="", dest='config_profile', help='Config Profile inside the config file')
    parser.add_argument('-p', default="", dest='proxy', help='Set Proxy (i.e. www-proxy-server.com:80) ')
    parser.add_argument('-ip', action='store_true', default=False, dest='is_instance_principals', help='Use Instance Principals for Authentication')
    parser.add_argument('-dt', action='store_true', default=False, dest='is_delegation_token', help='Use Delegation Token for Authentication')
    parser.add_argument("-ds", default=yesterday, dest='date_start', help="Start Date - format YYYY-MM-DD", type=valid_date_type)
    parser.add_argument("-de", default=today, dest='date_end', help="End Date - format YYYY-MM-DD, (Not Inclusive)", type=valid_date_type)
    parser.add_argument("-days", default=None, dest='days', help="Add Days Combined with Start Date (de is ignored if specified)", type=int)
    cmd = parser.parse_args()

    # Start print time info
    print_header("Running Export Usage to Data Dog", 0)
    print("Author          : Adi Zohar, Tony Markel")
    print("License         : This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.")
    print("Machine         : " + platform.node() + " (" + platform.machine() + ")")
    print("App Version     : " + version)
    print("OCI SDK Version : " + oci.version.__version__)
    print("Python Version  : " + platform.python_version())
    if cmd.is_instance_principals:
        print("Authentication  : Instance Principals")
    elif cmd.is_delegation_token:
        print("Authentication  : Instance Principals With Delegation Token")
    else:
        print("Authentication  : Config File")
    print("Date/Time       : " + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print("Command Line    : " + ' '.join(x for x in sys.argv[1:]))

    ############################################
    # Date Validation
    ############################################
    time_usage_started = None
    time_usage_ended = None
    report_type = "PRODUCT"

    if cmd.date_start and cmd.date_start > datetime.now():
        print("\n!!! Error, Start date cannot be in the future !!!")
        sys.exit()

    if cmd.date_start and cmd.date_end and cmd.date_start > cmd.date_end:
        print("\n!!! Error, Start date cannot be greater than End date !!!")
        sys.exit()

    if cmd.date_start:
        time_usage_started = cmd.date_start

    if cmd.days:
        time_usage_ended = time_usage_started + datetime.timedelta(days=cmd.days)
    elif cmd.date_end:
        time_usage_ended = cmd.date_end
    else:
        time_usage_ended = time_usage_started + datetime.timedelta(days=1)

    print("Start Date      : " + time_usage_started.strftime('%m/%d/%Y'))
    print("End Date        : " + time_usage_ended.strftime('%m/%d/%Y') + " Not Included")

    ############################################
    # Days check
    ############################################
    days = (time_usage_ended - time_usage_started).days

    if days > 93:
        print("\n!!! Error, Max 93 days period allowed, input is " + str(days) + " days, !!!")
        sys.exit()

    ############################################
    # create signer
    ############################################
    config, signer = create_signer(cmd.config_file, cmd.config_profile, cmd.is_instance_principals, cmd.is_delegation_token)
    tenant_id = ""

    print_header("Fetching data", 0)
    try:
        print("\nConnecting to Identity Service...\n")
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

        print("Tenant Name  : " + str(tenancy.name))
        print("Tenant Id    : " + tenancy.id)
        print("Home Region  : " + tenancy_home_region)

    except Exception as e:
        raise RuntimeError("\nError fetching tenant information - " + str(e))

    ############################################
    # Connection to UsageAPI
    ############################################
    try:
        print("\nConnecting to UsageAPI Service...")
        usage_client = oci.usage_api.UsageapiClient(config, signer=signer)
        if cmd.proxy:
            usage_client.base_client.session.proxies = {'https': cmd.proxy}
        usage_by_product(usage_client, tenant_id, time_usage_started, time_usage_ended)

    except Exception as e:
        raise RuntimeError("\nError at main function - " + str(e))

##########################################################################
# Main Process
##########################################################################
main()
