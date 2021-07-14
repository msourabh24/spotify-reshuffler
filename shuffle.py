import requests
import logging
import base64
import urllib.parse
import json
import random

client_id = ""
client_secret = ""
redirect_uri = ""
scope = "playlist-modify-private"
OAUTH_AUTHORIZE_URL = "https://accounts.spotify.com/authorize"
OAUTH_TOKEN_URL = "https://accounts.spotify.com/api/token"
PREFIX = "https://api.spotify.com/v1/"

logger = logging.getLogger(__name__)

r = requests.Session()


def get_id(type, id):
    fields = id.split(":")
    if len(fields) >= 3:
        if type != fields[-2]:
            print(
                "Expected id of type {} but found type {} {}".format(
                    type, fields[-2], id
                )
            )
        return fields[-1]
    fields = id.split("/")
    if len(fields) >= 3:
        itype = fields[-2]
        if type != itype:
            print("Expected id of type {} but found type {} {}".format(type, itype, id))
        return fields[-1].split("?")[0]
    return id


def get_auth_response():
    payload = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "show_dialog": True,
    }
    auth_url = "{}?{}".format(OAUTH_AUTHORIZE_URL, urllib.parse.urlencode(payload))
    prompt = (
        "Go to the following URL: {}\n"
        "Enter the URL you were redirected to: ".format(auth_url)
    )
    response = input(prompt)
    q = urllib.parse.urlparse(response).query
    form = dict(urllib.parse.parse_qsl(q))
    if "error" in form:
        logger.error(form["error"])
    code = form["code"]
    return code


def get_access_token(code=None):
    payload = {
        "redirect_uri": redirect_uri,
        "code": code,
        "grant_type": "authorization_code",
    }
    payload["scope"] = scope

    auth_header = base64.b64encode((client_id + ":" + client_secret).encode("ascii"))
    headers = {"Authorization": "Basic {}".format(auth_header.decode("ascii"))}

    try:
        response = r.post(
            OAUTH_TOKEN_URL,
            data=payload,
            headers=headers,
            verify=True,
        )
        response.raise_for_status()
        token_info = response.json()
        return token_info["access_token"]
    except requests.exceptions.HTTPError as http_error:
        logger.error(http_error)


def make_request(method, url, payload, params):
    args = dict(params=params)
    url = PREFIX + url
    headers = {
        "Authorization": "Bearer {}".format(ACCESS_TOKEN),
        "Content-Type": "application/json",
    }
    if payload:
        args["data"] = json.dumps(payload)

    try:
        response = r.request(method, url, headers=headers, **args)

        response.raise_for_status()
        results = response.json()
    except requests.exceptions.HTTPError as http_error:
        logger.error(http_error)
        results = None
    except requests.exceptions.RetryError as retry_error:
        logger.error(retry_error)
        results = None
    except ValueError:
        results = None

    return results


def get_request(url, args=None, payload=None, **kwargs):
    if args:
        kwargs.update(args)

    return make_request("GET", url, payload, kwargs)


def post_request(url, args=None, payload=None, **kwargs):
    if args:
        kwargs.update(args)

    return make_request("POST", url, payload, kwargs)


def put_request(url, args=None, payload=None, **kwargs):
    if args:
        kwargs.update(args)

    return make_request("PUT", url, payload, kwargs)


def playlist_info(
    playlist_id,
    fields=None,
    limit=100,
    offset=0,
    market=None,
    additional_types=("track", "episode"),
):
    plid = get_id("playlist", playlist_id)
    return get_request(
        "playlists/{}/tracks".format(plid),
        limit=limit,
        offset=offset,
        fields=fields,
        market=market,
        additional_types=",".join(additional_types),
    )


def playlist_replace_tracks(playlist_id, items):
    plid = get_id("playlist", playlist_id)
    return post_request(
        "playlists/{}/tracks".format(plid), payload=items, position=None
    )


def playlist_empty_tracks(playlist_id):
    plid = get_id("playlist", playlist_id)
    payload = {"uris": []}
    return put_request("playlists/{}/tracks".format(plid), payload=payload)


ACCESS_TOKEN = get_access_token(code=get_auth_response())

playlist_id = input("Enter the playlist URL to shuffle:")
offset = 0
uris = []
while True:
    items = playlist_info(
        playlist_id=playlist_id,
        offset=offset,
        fields="items.track.uri",
        additional_types=["track"],
    )["items"]

    if len(items) == 0:
        break

    offset = offset + len(items)
    for item in items:
        uris.append(item["track"]["uri"])

random.shuffle(uris)
playlist_empty_tracks(playlist_id=playlist_id)

offset = 0
while True:
    playlist_replace_tracks(playlist_id, uris[offset : offset + 100])
    offset = offset + 100

    if (len(uris[offset : offset + 100])) == 0:
        break

r.close()
