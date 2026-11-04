"""Tests for the guards added from measured ONS behavior (HTTPS order, retries)."""

import argparse
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssl_api_manager as mgr

NOT_READY = {
    "api_response": {
        "result_code": "A404",
        "result_msg": "Request Error : Domain a.example.com staging config status is not success.",
    }
}
OK = {"api_response": {"result_code": "200", "result_msg": "success"}}
OTHER_ERROR = {
    "api_response": {"result_code": "E500", "result_msg": "something else broke"}
}


def _ns(**kwargs):
    defaults = {
        "id": "admin",
        "password": None,
        "api_key": "KEY",
        "domain": "a.example.com",
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _response(body):
    resp = mock.Mock()
    resp.json.return_value = body
    return resp


def _cert_page(domains):
    return {
        "api_response": {
            "result_code": "200",
            "data": {"total_count": 1, "ssl_list": [{"domain_list": domains}]},
        }
    }


class HttpsDeployRetryTests(unittest.TestCase):
    @mock.patch.object(mgr.time, "sleep")
    @mock.patch.object(mgr, "handle_response")
    @mock.patch.object(mgr.requests, "post")
    def test_retries_while_staging_not_ready(self, post, handle, sleep):
        post.side_effect = [_response(NOT_READY), _response(OK)]

        mgr.https_deploy(_ns(max_attempts=6, retry_interval=20))

        self.assertEqual(post.call_count, 2)
        sleep.assert_called_once_with(20)
        handle.assert_called_once()
        self.assertEqual(handle.call_args.args[0].json(), OK)

    @mock.patch.object(mgr.time, "sleep")
    @mock.patch.object(mgr, "handle_response")
    @mock.patch.object(mgr.requests, "post")
    def test_stops_after_max_attempts(self, post, handle, sleep):
        post.side_effect = lambda *a, **k: _response(NOT_READY)

        mgr.https_deploy(_ns(max_attempts=3, retry_interval=1))

        self.assertEqual(post.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(handle.call_args.args[0].json(), NOT_READY)

    @mock.patch.object(mgr.time, "sleep")
    @mock.patch.object(mgr, "handle_response")
    @mock.patch.object(mgr.requests, "post")
    def test_other_errors_are_not_retried(self, post, handle, sleep):
        post.side_effect = [_response(OTHER_ERROR)]

        mgr.https_deploy(_ns(max_attempts=6, retry_interval=20))

        self.assertEqual(post.call_count, 1)
        sleep.assert_not_called()


class HttpsOnPreflightTests(unittest.TestCase):
    @mock.patch.object(mgr.time, "sleep")
    @mock.patch.object(mgr, "_post_domain_form")
    @mock.patch.object(mgr, "_fetch_ssl_list_page")
    def test_blocks_https_on_after_waiting_for_linked_certificate(
        self, fetch, post, sleep
    ):
        fetch.return_value = _cert_page(["other.example.com"])

        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            with self.assertRaises(SystemExit):
                mgr.https_staging(
                    _ns(
                        https="on",
                        http2="off",
                        skip_cert_check=False,
                        max_attempts=3,
                        retry_interval=5,
                    )
                )

        post.assert_not_called()
        self.assertEqual(fetch.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertIn("SSL mapping not found", err.getvalue())

    @mock.patch.object(mgr.time, "sleep")
    @mock.patch.object(mgr, "_post_domain_form")
    @mock.patch.object(mgr, "_fetch_ssl_list_page")
    def test_waits_until_certificate_link_appears(self, fetch, post, sleep):
        """The list reflects a new link a few seconds after the final deploy."""
        fetch.side_effect = [
            _cert_page(["other.example.com"]),
            _cert_page(["a.example.com"]),
        ]

        mgr.https_staging(
            _ns(
                https="on",
                http2="off",
                skip_cert_check=False,
                max_attempts=6,
                retry_interval=5,
            )
        )

        self.assertEqual(fetch.call_count, 2)
        sleep.assert_called_once_with(5)
        post.assert_called_once()

    @mock.patch.object(mgr, "_post_domain_form")
    @mock.patch.object(mgr, "_fetch_ssl_list_page")
    def test_allows_https_on_with_linked_certificate(self, fetch, post):
        fetch.return_value = _cert_page(["a.example.com"])

        mgr.https_staging(_ns(https="on", http2="off", skip_cert_check=False))

        post.assert_called_once()

    @mock.patch.object(mgr, "_post_domain_form")
    @mock.patch.object(mgr, "_fetch_ssl_list_page")
    def test_skip_cert_check_bypasses_lookup(self, fetch, post):
        mgr.https_staging(_ns(https="on", http2="off", skip_cert_check=True))

        fetch.assert_not_called()
        post.assert_called_once()

    @mock.patch.object(mgr, "_post_domain_form")
    @mock.patch.object(mgr, "_fetch_ssl_list_page")
    def test_https_off_never_checks_certificate(self, fetch, post):
        mgr.https_staging(_ns(https="off", http2="off", skip_cert_check=False))

        fetch.assert_not_called()
        post.assert_called_once()


class ReleaseWhileHttpsOnTests(unittest.TestCase):
    def _args(self, **kwargs):
        defaults = {
            "ssl_file_name": "example.com",
            "add_domain_list": None,
            "del_domain_list": "a.example.com",
            "memo": None,
            "ssl_key_password": None,
            "ssl_cert": None,
            "ssl_key": None,
        }
        defaults.update(kwargs)
        return _ns(**defaults)

    @mock.patch.object(mgr, "handle_response")
    @mock.patch.object(mgr.requests, "post")
    @mock.patch.object(mgr.requests, "get")
    def test_warns_when_https_is_on(self, get, post, _handle):
        get.return_value = _response(
            {"api_response": {"result_code": "200", "data": {"https_enabled": True}}}
        )

        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            mgr.staging_update(self._args())

        self.assertIn("a.example.com", err.getvalue())
        self.assertIn("HTTPS is ON", err.getvalue())
        post.assert_called_once()

    @mock.patch.object(mgr, "handle_response")
    @mock.patch.object(mgr.requests, "post")
    @mock.patch.object(mgr.requests, "get")
    def test_silent_when_https_is_off(self, get, post, _handle):
        get.return_value = _response(
            {"api_response": {"result_code": "200", "data": {"https_enabled": False}}}
        )

        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            mgr.staging_update(self._args())

        self.assertEqual(err.getvalue(), "")
        post.assert_called_once()

    @mock.patch.object(mgr, "handle_response")
    @mock.patch.object(mgr.requests, "post")
    @mock.patch.object(mgr.requests, "get")
    def test_no_lookup_when_nothing_is_released(self, get, post, _handle):
        mgr.staging_update(self._args(del_domain_list=None, add_domain_list="b.com"))

        get.assert_not_called()
        post.assert_called_once()


if __name__ == "__main__":
    unittest.main()
