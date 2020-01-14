# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""This module handles Duo operations."""
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from builtins import (ascii, bytes, chr, dict, filter, hex, input,  # noqa: F401
                      int, list, map, next, object, oct, open, pow, range,
                      round, str, super, zip)
import logging
import time
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup
from future import standard_library
import requests
from tokendito import helpers
from tokendito import settings
standard_library.install_aliases()


def prepare_duo_info(selected_okta_factor):
    """Aggregate most of the parameters needed throughout the Duo authentication process.

    :param selected_okta_factor: dict response describing Duo factor in Okta.
    :return duo_info: dict of parameters for Duo
    """
    duo_info = {}
    okta_factor = selected_okta_factor["_embedded"]["factor"]["_embedded"]["verification"]
    duo_info["okta_factor"] = okta_factor
    duo_info["factor_id"] = selected_okta_factor["_embedded"]["factor"]["id"]

    duo_info["state_token"] = selected_okta_factor["stateToken"]
    duo_info["okta_callback_url"] = okta_factor["_links"]["complete"]["href"]
    duo_info["tx"] = okta_factor["signature"].split(":")[0]
    duo_info["app_sig"] = okta_factor["signature"].split(":")[1]
    version = okta_factor["_links"]["script"]["href"].split("-v")[1]
    duo_info["version"] = version.encode("utf-8").strip(".js")
    duo_info["parent"] = "{}/signin/verify/duo/web".format(
        settings.okta_org)
    duo_info["host"] = okta_factor["host"]
    duo_info["sid"] = ""
    return duo_info


def duo_api_post(url, params={}, headers={}, payload={}):
    """Error handling and response parsing wrapper for Duo POSTs.

    :param url: The URL being connected to.
    :param params: URL query parameters.
    :param headers: Request headers.
    :param payload: Request body.
    :return response: Response to the API request.
    """
    try:
        response = requests.request(
            'POST', url, params=params, headers=headers, data=payload)
    except Exception as request_issue:
        logging.error(
            "There was an error connecting to the Duo API: \n{}".format(request_issue))

    json_message = None
    try:
        json_message = response.json()
    except ValueError:
        logging.debug("Non-json response from Duo API: \n{}".format(response))

    if response.status_code >= 400:
        print("Your Duo authentication has failed with status {}.".format(
            response.status_code))
        if json_message and json_message["stat"].lower() != "ok":
            print("\n{}".format(
                response.status_code, json_message["message"]))
        else:
            print("Please retry with the Debug loglevel to see more information.")
        exit(1)

    return response


def get_duo_sid(duo_info):
    """Perform the initial Duo authentication request to obtain the SID.

    The SID is referenced throughout the authentication process for Duo.

    :param duo_info: dict response describing Duo factor in Okta.
    :return: duo_info with added SID.
    :return: duo_auth_response, contains html content listing available factors.
    """
    params = helpers.prepare_payload(
        tx=duo_info["tx"], v=duo_info["version"], parent=duo_info["parent"])
    # confirm: does settings.okta_org always have https:// prefix?
    # https%3A%2F%2Fdowjonestokendito.okta.com%2Fsignin%2Fverify%2Fduo%2Fweb

    url = "https://{}/frame/web/v1/auth".format(duo_info["host"])
    logging.info("Calling Duo {} with params {}".format(
        urlparse(url).path, params.keys()))
    duo_auth_response = duo_api_post(url, params=params)

    duo_auth_redirect = urlparse("{}".format(
        unquote(duo_auth_response.url))).query
    sid = [d for d in duo_auth_redirect.split("&") if "sid" in d]
    duo_info["sid"] = sid[0].strip("sid=")

    return duo_info, duo_auth_response


def get_duo_devices(duo_auth):
    """Parse Duo auth response to extract user's MFA options.

    The /frame/web/v1/auth API returns an html page that lists
    devices and their mfa options for the user logging in.
    The return data type (list of dicts) is intended to allow us to
    do printout padding and indexing when interacting with the end user.

    :param duo_auth: contains html content listing available factors.
    :return factor_options: list of dict objects describing each MFA option.
    """
    soup = BeautifulSoup(duo_auth.content, "html.parser")

    device_soup = soup.find("select", {"name": "device"}).findAll("option")
    devices = ["{} - {}".format(d["value"], d.text) for d in device_soup]
    factor_options = []
    for device in devices:
        options = soup.find(
            "fieldset", {"data-device-index": device.split(" - ")[0]})
        factors = options.findAll("input", {"name": "factor"})
        for factor in factors:
            factor_option = {}
            factor_option["device"] = device
            factor_option["factor"] = factor["value"]
            factor_options.append(factor_option)
    return factor_options


def duo_mfa_challenge(duo_info, mfa_option, passcode):
    """Poke Duo to challenge the selected factor.

    After the user has selected their device and factor of choice,
    tell Duo to send a challenge. This is where the end user will receive
    a phone call or push.

    :param duo_info: dict of parameters for Duo
    :param mfa_option: the user's selected second factor.
    :return txid: Duo transaction ID used to track this auth attempt.
    """
    url = "https://{}/frame/prompt".format(duo_info["host"])
    device = mfa_option["device"].split(" - ")[0]
    mfa_data = helpers.prepare_payload(factor=mfa_option["factor"],
                                       device=device,
                                       sid=duo_info["sid"],
                                       out_of_date=False,
                                       days_out_of_date=0,
                                       days_to_block=None)
    mfa_data["async"] = True  # async is a reserved keyword
    if passcode is not None:
        mfa_data["passcode"] = passcode
    mfa_challenge = duo_api_post(url, payload=mfa_data)

    if mfa_challenge.json()["stat"].lower() == "fail":
        exit(("Your Duo authentication has failed: \n{}".format(
            mfa_challenge.json()["message"])))

    logging.debug("Sent MFA Challenge and obtained Duo transaction ID.")
    return mfa_challenge.json()["response"]["txid"]


def duo_mfa_verify(duo_info, txid):
    """Verify MFA challenge completion.

    After the user has received the MFA challenge, query the Duo API
    until the challenge is completed.

    :param duo_info: dict of parameters for Duo.
    :param mfa_option: the user's selected second factor.
    :return txid: Duo transaction ID used to track this auth attempt.
    """
    url = "https://{}/frame/status".format(duo_info["host"])
    challenged_mfa = helpers.prepare_payload(txid=txid, sid=duo_info["sid"])

    while True:
        logging.debug("Waiting for MFA challenge response")
        mfa_result = duo_api_post(url, payload=challenged_mfa)
        verify_mfa = mfa_result.json()["response"]

        try:
            print(verify_mfa["status"])
        except KeyError:
            logging.debug("No factor status found.")

        try:
            mfa_result = verify_mfa["result"]
        except KeyError:
            logging.debug("No factor result was found"
                          " in the Duo MFA response: \n{}".format(verify_mfa))
            continue

        if mfa_result.lower() == "success":
            logging.debug("Successful MFA challenge received")
            break
        if mfa_result.lower() == "failure":
            print("MFA challenge has failed for reason:"
                  " {}\nPlease try again.".format(mfa_result, verify_mfa["reason"]))
            continue
        else:
            logging.debug("MFA challenge result: {}"
                          "Reason: {}\n\n".format(mfa_result, verify_mfa["reason"]))
            continue
        time.sleep(1)
    return verify_mfa


def duo_factor_callback(duo_info, verify_mfa):
    """Inform factor callback api of successful challenge.

    This request seems to inform this factor's callback url
    that the challenge process has been completed.

    :param duo_info: dict of parameters for Duo.
    :param verify_mfa: verified mfa challenge response from status api.
    :return sig_response: required to sign final Duo callback request.
    """
    factor_callback_url = "https://{}{}".format(
        duo_info["host"], verify_mfa["result_url"])
    factor_callback = duo_api_post(factor_callback_url, payload={
        "sid": duo_info["sid"]})
    sig_response = "{}:{}".format(
        factor_callback.json()["response"]["cookie"], duo_info["app_sig"])

    logging.debug("Completed factor callback.")
    return sig_response


def authenticate_duo(selected_okta_factor):
    """Accomplish MFA via Duo.

    This is the main function that coordinates the Duo
    multifactor fetching, presentation, selection, challenge,
    and verification until making an Okta callback.

    :param selected_okta_factor: Duo factor information retrieved from Okta.
    :return payload: required payload for Okta callback
    :return headers: required headers for Okta callback
    """
    duo_info = prepare_duo_info(selected_okta_factor)

    # Collect devices, factors, auth params for Duo
    duo_info, duo_auth_response = get_duo_sid(duo_info)
    factor_options = get_duo_devices(duo_auth_response)
    mfa_index = helpers.select_preferred_mfa_index(factor_options, duo=True)
    mfa_option = factor_options[mfa_index]
    logging.debug("Selected MFA is [{}]".format(mfa_option))

    if mfa_option["factor"].lower() == "passcode":
        passcode = helpers.collect_totp()
    else:
        passcode = None

    txid = duo_mfa_challenge(duo_info, mfa_option, passcode)
    verify_mfa = duo_mfa_verify(duo_info, txid)

    # Make factor callback to Duo
    sig_response = duo_factor_callback(duo_info, verify_mfa)

    # Prepare for Okta callback
    payload = helpers.prepare_payload(id=duo_info["factor_id"],
                                      sig_response=sig_response,
                                      stateToken=duo_info["state_token"])
    headers = {}
    headers["content-type"] = "application/json"
    headers["accept"] = "application/json"

    return payload, headers, duo_info["okta_callback_url"]
