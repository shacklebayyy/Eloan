import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest import mock

import server


class ReferralApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.ADMIN_TOKEN = "test-admin-token-not-for-production"
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        server.DB_PATH = Path(self.temp_dir.name) / "test.sqlite3"
        self.agent_count = 0
        server.initialize_db()

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def request_json(self, path, payload=None, token=None, cookie=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if cookie:
            headers["Cookie"] = cookie
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8") if payload is not None else None,
            headers=headers,
            method="POST" if payload is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                self.last_response_headers = response.headers
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            with error:
                self.last_response_headers = error.headers
                return error.status, json.loads(error.read())

    def create_agent(self, name="Test Agent"):
        self.agent_count += 1
        status, data = self.request_json(
            "/api/admin/agents",
            {"displayName": name, "email": f"agent{self.agent_count}@example.com"},
            token=server.ADMIN_TOKEN,
        )
        self.assertEqual(status, 201)
        return data

    def login_agent(self, agent):
        with mock.patch.object(server, "send_agent_otp") as send_otp:
            status, data = self.request_json(
                "/api/agent/login",
                {"username": agent["username"], "password": agent["temporaryPassword"]},
            )
        code = send_otp.call_args.args[1]
        self.assertEqual(send_otp.call_args.args[0], agent["email"])
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())
        self.assertEqual(data["maskedEmail"], "a***@example.com")
        status, data = self.request_json(
            "/api/agent/verify-otp",
            {"challengeToken": data["challengeToken"], "code": code},
        )
        cookie = self.last_response_headers.get("Set-Cookie").split(";", 1)[0]
        return status, data, cookie

    def replace_temporary_password(self, cookie, temporary_password, new_password):
        return self.request_json(
            "/api/agent/password",
            {"currentPassword": temporary_password, "newPassword": new_password},
            cookie=cookie,
        )

    def application(self, referral_token, consent, submission_id):
        return {
            "firstName": "Ana",
            "lastName": "Matos",
            "phone": "843123456",
            "loanType": "Empréstimo Pessoal",
            "loanAmount": 25000,
            "termMonths": 48,
            "purpose": "Expandir uma pequena loja",
            "employment": "Empregado",
            "annualIncome": 120000,
            "referralToken": referral_token,
            "consentToAgentContact": consent,
            "submissionId": submission_id,
        }

    def test_referral_is_attributed_without_exposing_opted_out_lead(self):
        agent = self.create_agent()
        submission_id = "1a5c4584-465b-4d8f-89f6-504f39128ba1"
        status, _ = self.request_json(
            "/api/applications",
            self.application(agent["referralToken"], False, submission_id),
        )
        self.assertEqual(status, 201)

        with server.connect_db() as db:
            row = db.execute(
                "SELECT agent_id, agent_contact_consent FROM applications WHERE submission_id = ?",
                (submission_id,),
            ).fetchone()
        self.assertEqual(row["agent_id"], agent["agentId"])
        self.assertEqual(row["agent_contact_consent"], 0)

        status, login, cookie = self.login_agent(agent)
        self.assertEqual(status, 200)
        self.assertTrue(login["mustChangePassword"])
        status, _ = self.request_json("/api/agent/leads", cookie=cookie)
        self.assertEqual(status, 403)
        status, _ = self.replace_temporary_password(
            cookie, agent["temporaryPassword"], "new-password-12345"
        )
        self.assertEqual(status, 200)
        status, data = self.request_json("/api/agent/leads", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(data["leads"], [])

    def test_dashboard_auth_and_consent_filter(self):
        agent = self.create_agent("First Agent")
        other_agent = self.create_agent("Second Agent")
        payload = self.application(
            agent["referralToken"], True, "2a5c4584-465b-4d8f-89f6-504f39128ba1"
        )
        status, created = self.request_json("/api/applications", payload)
        self.assertEqual(status, 201)

        status, _ = self.request_json("/api/agent/leads")
        self.assertEqual(status, 401)
        status, login, cookie = self.login_agent(agent)
        self.assertEqual(status, 200)
        self.assertTrue(login["mustChangePassword"])
        self.assertEqual(
            self.replace_temporary_password(
                cookie, agent["temporaryPassword"], "first-agent-password-123"
            )[0],
            200,
        )
        status, leads = self.request_json("/api/agent/leads", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(len(leads["leads"]), 1)
        self.assertEqual(leads["leads"][0]["id"], created["applicationId"])
        self.assertNotIn("purpose", leads["leads"][0])
        self.assertNotIn("annual_income", leads["leads"][0])

        status, _, other_cookie = self.login_agent(other_agent)
        self.assertEqual(
            self.replace_temporary_password(
                other_cookie, other_agent["temporaryPassword"], "second-agent-password-123"
            )[0],
            200,
        )
        status, other_leads = self.request_json("/api/agent/leads", cookie=other_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(other_leads["leads"], [])

    def test_login_password_change_and_logout(self):
        agent = self.create_agent()
        status, _ = self.request_json(
            "/api/agent/login",
            {"username": agent["username"], "password": "wrong-temporary-password"},
        )
        self.assertEqual(status, 401)

        status, login, cookie = self.login_agent(agent)
        self.assertEqual(status, 200)
        self.assertTrue(login["mustChangePassword"])
        status, _ = self.request_json(
            "/api/agent/password",
            {"currentPassword": agent["temporaryPassword"], "newPassword": "short"},
            cookie=cookie,
        )
        self.assertEqual(status, 400)
        status, _ = self.replace_temporary_password(
            cookie, agent["temporaryPassword"], "rotated-agent-password-123"
        )
        self.assertEqual(status, 200)
        status, session = self.request_json("/api/agent/me", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertFalse(session["mustChangePassword"])
        status, _ = self.request_json("/api/agent/logout", payload={}, cookie=cookie)
        self.assertEqual(status, 200)
        status, _ = self.request_json("/api/agent/me", cookie=cookie)
        self.assertEqual(status, 401)

    def test_otp_rejects_wrong_code_and_locks_after_five_attempts(self):
        agent = self.create_agent()
        with mock.patch.object(server, "send_agent_otp"):
            status, challenge = self.request_json(
                "/api/agent/login",
                {"username": agent["username"], "password": agent["temporaryPassword"]},
            )
        self.assertEqual(status, 200)
        self.assertTrue(challenge["otpRequired"])
        for _ in range(5):
            status, _ = self.request_json(
                "/api/agent/verify-otp",
                {"challengeToken": challenge["challengeToken"], "code": "000000"},
            )
            self.assertEqual(status, 401)
        status, _ = self.request_json(
            "/api/agent/verify-otp",
            {"challengeToken": challenge["challengeToken"], "code": "123456"},
        )
        self.assertEqual(status, 401)

    def test_referral_signature_and_submission_idempotency(self):
        agent = self.create_agent()
        token = agent["referralToken"]
        replacement = "A" if token[-1] != "A" else "B"
        invalid_token = token[:-1] + replacement
        status, _ = self.request_json(
            "/api/applications",
            self.application(
                invalid_token, True, "3a5c4584-465b-4d8f-89f6-504f39128ba1"
            ),
        )
        self.assertEqual(status, 400)

        payload = self.application(
            token, True, "4a5c4584-465b-4d8f-89f6-504f39128ba1"
        )
        first_status, first = self.request_json("/api/applications", payload)
        second_status, second = self.request_json("/api/applications", payload)
        self.assertEqual(first_status, 201)
        self.assertEqual(second_status, 200)
        self.assertEqual(first["applicationId"], second["applicationId"])

    def test_malformed_json_shapes_return_bad_request(self):
        status, _ = self.request_json(
            "/api/admin/agents", [], token=server.ADMIN_TOKEN
        )
        self.assertEqual(status, 400)
        payload = self.application(None, False, "5a5c4584-465b-4d8f-89f6-504f39128ba1")
        payload["loanType"] = []
        status, _ = self.request_json("/api/applications", payload)
        self.assertEqual(status, 400)

    def test_start_command_replies_with_chat_id(self):
        update = {
            "update_id": 12,
            "message": {"chat": {"id": 123456}, "text": "/start"},
        }
        calls = []

        def fake_api(method, payload):
            if method == "getUpdates" and not calls:
                return [update]
            if method == "sendMessage":
                calls.append((method, payload))
                return {}
            raise KeyboardInterrupt

        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(server, "telegram_api", side_effect=fake_api):
                with self.assertRaises(KeyboardInterrupt):
                    server.telegram_update_loop()

        self.assertEqual(calls[0][1]["chat_id"], "123456")
        self.assertIn("123456", calls[0][1]["text"])

    def test_agent_pairing_link_connects_private_chat_once(self):
        agent = self.create_agent("Linked Agent")
        start_parameter = parse_qs(urlsplit(agent["telegramPairingUrl"]).query)["start"][0]
        self.assertTrue(start_parameter.startswith("link_"))
        calls = []
        with mock.patch.object(
            server,
            "send_telegram_message",
            side_effect=lambda chat_id, text: calls.append((chat_id, text)),
        ):
            server.handle_telegram_message(
                {
                    "chat": {"id": 777001, "type": "private"},
                    "text": f"/start {start_parameter}",
                }
            )
            server.handle_telegram_message(
                {
                    "chat": {"id": 777002, "type": "private"},
                    "text": f"/start {start_parameter}",
                }
            )

        self.assertIn("Linked Agent", calls[0][1])
        self.assertIn("invalid, expired, or already used", calls[1][1])
        with server.connect_db() as db:
            paired = db.execute(
                "SELECT telegram_chat_id, telegram_pair_token_hash FROM agents WHERE id = ?",
                (agent["agentId"],),
            ).fetchone()
        self.assertEqual(paired["telegram_chat_id"], "777001")
        self.assertIsNone(paired["telegram_pair_token_hash"])

    def test_agent_alert_routes_in_english_to_paired_chat_only_with_consent(self):
        agent = self.create_agent("Private Agent")
        start_parameter = parse_qs(urlsplit(agent["telegramPairingUrl"]).query)["start"][0]
        with mock.patch.object(server, "send_telegram_message"):
            server.handle_telegram_message(
                {
                    "chat": {"id": 777003, "type": "private"},
                    "text": f"/start {start_parameter}",
                }
            )
        consented = self.application(
            agent["referralToken"], True, "7a5c4584-465b-4d8f-89f6-504f39128ba1"
        )
        opted_out = self.application(
            agent["referralToken"], False, "8a5c4584-465b-4d8f-89f6-504f39128ba1"
        )
        with mock.patch.dict(
            os.environ,
            {
                "EMOLA_TELEGRAM_BOT_TOKEN": "fake-test-token",
                "EMOLA_TELEGRAM_CHAT_ID": "-100123456",
            },
        ):
            for payload in (consented, opted_out):
                status, _ = self.request_json("/api/applications", payload)
                self.assertEqual(status, 201)
            with mock.patch.object(server, "send_telegram_message") as send_message:
                with mock.patch.object(server.time, "sleep", side_effect=KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        server.telegram_notification_loop()

        self.assertEqual(send_message.call_count, 2)
        self.assertTrue(all(call.args[0] == "777003" for call in send_message.call_args_list))
        agent_messages = [
            call.args[1]
            for call in send_message.call_args_list
            if call.args[0] == "777003"
        ]
        self.assertEqual(len(agent_messages), 2)
        message = agent_messages[0]
        self.assertIn("New E-Mola application", message)
        self.assertIn("Ana Matos", message)
        self.assertIn("+258 843123456", message)
        with server.connect_db() as db:
            agent_events = db.execute(
                "SELECT COUNT(*) AS count FROM telegram_agent_outbox"
            ).fetchone()["count"]
        self.assertEqual(agent_events, 2)

    def test_application_alert_is_queued_and_minimizes_personal_data(self):
        payload = self.application(
            None, True, "6a5c4584-465b-4d8f-89f6-504f39128ba1"
        )
        with mock.patch.dict(
            os.environ,
            {
                "EMOLA_TELEGRAM_BOT_TOKEN": "fake-test-token",
                "EMOLA_TELEGRAM_CHAT_ID": "-100123456",
            },
        ):
            status, _ = self.request_json("/api/applications", payload)
            self.assertEqual(status, 201)
            with mock.patch.object(server, "send_telegram_message") as send_message:
                with mock.patch.object(server.time, "sleep", side_effect=KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        server.telegram_notification_loop()

        self.assertEqual(send_message.call_count, 1)
        chat_id, message = send_message.call_args.args
        self.assertEqual(chat_id, "-100123456")
        self.assertIn("New E-Mola application", message)
        self.assertNotIn(payload["phone"], message)
        self.assertNotIn(payload["firstName"], message)
        with server.connect_db() as db:
            event = db.execute("SELECT sent_at FROM telegram_outbox").fetchone()
        self.assertIsNotNone(event["sent_at"])

    def test_admin_settings_and_agent_with_chat_id(self):
        with mock.patch.object(server, "ensure_telegram_threads_running", return_value=True):
            # Update settings via API
            status, data = self.request_json(
                "/api/admin/settings",
                {"botToken": "test-bot-token-123456", "adminChatId": "998877", "botUsername": "myemolabot"},
                token=server.ADMIN_TOKEN,
            )
            self.assertEqual(status, 200)
            self.assertTrue(data["ok"])

            # Fetch settings via API
            status, settings_data = self.request_json(
                "/api/admin/settings",
                token=server.ADMIN_TOKEN,
            )
            self.assertEqual(status, 200)
            self.assertTrue(settings_data["hasBotToken"])
            self.assertEqual(settings_data["adminChatId"], "998877")
            self.assertEqual(settings_data["botUsername"], "myemolabot")

            # Create agent with direct Telegram chat ID
            status, agent_data = self.request_json(
                "/api/admin/agents",
                {"displayName": "Direct Chat Agent", "telegramChatId": "554433"},
                token=server.ADMIN_TOKEN,
            )
            self.assertEqual(status, 201)
            self.assertEqual(agent_data["telegramChatId"], "554433")
            self.assertIn("ref=", agent_data["referralUrl"])

            with server.connect_db() as db:
                row = db.execute(
                    "SELECT telegram_chat_id, display_name FROM agents WHERE id = ?",
                    (agent_data["agentId"],),
                ).fetchone()
            self.assertEqual(row["telegram_chat_id"], "554433")
            self.assertEqual(row["display_name"], "Direct Chat Agent")

    def test_application_stage_update_and_callback(self):
        agent = self.create_agent("Stage Agent")
        app_payload = self.application(agent["referralToken"], True, "9a5c4584-465b-4d8f-89f6-504f39128ba1")
        status, app_res = self.request_json("/api/applications", app_payload)
        self.assertEqual(status, 201)
        app_id = app_res["applicationId"]

        # Update stage via Admin API
        status, stage_res = self.request_json(
            "/api/admin/applications/stage",
            {"applicationId": app_id, "stage": "under_review"},
            token=server.ADMIN_TOKEN,
        )
        self.assertEqual(status, 200)
        self.assertEqual(stage_res["stage"], "under_review")

        with server.connect_db() as db:
            row = db.execute("SELECT status FROM applications WHERE id = ?", (app_id,)).fetchone()
        self.assertEqual(row["status"], "under_review")

        # Update stage via Telegram callback query
        callback_query = {
            "id": "cb_123",
            "data": f"stage:approved:{app_id}",
            "message": {
                "message_id": 101,
                "chat": {"id": 12345},
                "text": "New E-Mola application\nStatus: Under Review",
            },
        }
        with mock.patch.object(server, "telegram_api", return_value={"ok": True}):
            server.handle_telegram_callback(callback_query)

        with server.connect_db() as db:
            row = db.execute("SELECT status FROM applications WHERE id = ?", (app_id,)).fetchone()
        self.assertEqual(row["status"], "approved")

    def test_application_public_status_endpoint(self):
        agent = self.create_agent("Status Check Agent")
        app_payload = self.application(agent["referralToken"], True, "4b5d6e7f-8a9b-4c0d-1e2f-3a4b5c6d7e8f")
        status, app_res = self.request_json("/api/applications", app_payload)
        self.assertEqual(status, 201)
        app_id = app_res["applicationId"]

        # Initial status should be pending
        status, data = self.request_json(f"/api/applications/{app_id}/status")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "pending")
        self.assertEqual(data["amount"], 25000)
        self.assertEqual(data["termMonths"], 48)
        self.assertEqual(data["purpose"], "Expandir uma pequena loja")

        # Update to under_review
        self.request_json(
            "/api/admin/applications/stage",
            {"applicationId": app_id, "stage": "under_review"},
            token=server.ADMIN_TOKEN,
        )
        status, data = self.request_json(f"/api/applications/{app_id}/status")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "under_review")

        # Update to approved
        self.request_json(
            "/api/admin/applications/stage",
            {"applicationId": app_id, "stage": "approved"},
            token=server.ADMIN_TOKEN,
        )
        status, data = self.request_json(f"/api/applications/{app_id}/status")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "approved")

        # Invalid UUID format should return 400
        status, err = self.request_json("/api/applications/invalid-uuid-format/status")
        self.assertEqual(status, 400)

        # Non-existent UUID should return 404
        status, err = self.request_json("/api/applications/00000000-0000-0000-0000-000000000000/status")
        self.assertEqual(status, 404)

    def test_verification_flow(self):
        agent = self.create_agent("Verify Agent")
        # Approve the application first
        app_payload = self.application(agent["referralToken"], True, "aabb0011-2233-4455-6677-8899aabbccdd")
        status, app_res = self.request_json("/api/applications", app_payload)
        self.assertEqual(status, 201)
        app_id = app_res["applicationId"]

        # Approve the application
        self.request_json(
            "/api/admin/applications/stage",
            {"applicationId": app_id, "stage": "approved"},
            token=server.ADMIN_TOKEN,
        )

        # Submit ZIP+phone verification (Step 1)
        status, ver1 = self.request_json(
            f"/api/applications/{app_id}/verify",
            {"step": "zip_phone", "zipCode": "1234", "phone": "843111222"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(ver1["step"], "zip_phone")
        self.assertEqual(ver1["status"], "pending")
        ver1_id = ver1["verificationId"]

        # Cannot submit duplicate pending step
        status, dup = self.request_json(
            f"/api/applications/{app_id}/verify",
            {"step": "zip_phone", "zipCode": "5678", "phone": "843333444"},
        )
        self.assertEqual(status, 409)

        # Approve ZIP via Telegram callback
        callback = {
            "id": "cb_v1",
            "data": f"verify:approve:{ver1_id}",
            "message": {
                "message_id": 200,
                "chat": {"id": 99999},
                "text": "Verificação ZIP",
            },
        }
        with mock.patch.object(server, "telegram_api", return_value={"ok": True}):
            server.handle_telegram_callback(callback)

        with server.connect_db() as db:
            row = db.execute("SELECT status FROM verifications WHERE id = ?", (ver1_id,)).fetchone()
        self.assertEqual(row["status"], "approved")

        # Status endpoint should include verifications
        status, data = self.request_json(f"/api/applications/{app_id}/status")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["verifications"]), 1)
        self.assertEqual(data["verifications"][0]["status"], "approved")

        # Submit ID document verification (Step 2)
        status, ver2 = self.request_json(
            f"/api/applications/{app_id}/verify",
            {"step": "id_document", "idNumber": "1234567890A"},
        )
        self.assertEqual(status, 201)
        ver2_id = ver2["verificationId"]

        # Reject ID via Telegram callback
        callback2 = {
            "id": "cb_v2",
            "data": f"verify:reject:{ver2_id}",
            "message": {
                "message_id": 201,
                "chat": {"id": 99999},
                "text": "Verificação ID",
            },
        }
        with mock.patch.object(server, "telegram_api", return_value={"ok": True}):
            server.handle_telegram_callback(callback2)

        with server.connect_db() as db:
            row = db.execute("SELECT status, reject_reason FROM verifications WHERE id = ?", (ver2_id,)).fetchone()
        self.assertEqual(row["status"], "rejected")
        self.assertIsNotNone(row["reject_reason"])

        # Should be able to resubmit after rejection
        status, ver3 = self.request_json(
            f"/api/applications/{app_id}/verify",
            {"step": "id_document", "idNumber": "0987654321B"},
        )
        self.assertEqual(status, 201)
        ver3_id = ver3["verificationId"]

        # Approve the resubmitted ID
        callback3 = {
            "id": "cb_v3",
            "data": f"verify:approve:{ver3_id}",
            "message": {
                "message_id": 202,
                "chat": {"id": 99999},
                "text": "Verificação ID reenvio",
            },
        }
        with mock.patch.object(server, "telegram_api", return_value={"ok": True}):
            server.handle_telegram_callback(callback3)

        # Both steps should now be approved
        status, final = self.request_json(f"/api/applications/{app_id}/status")
        self.assertEqual(status, 200)
        vers = final["verifications"]
        zip_vers = [v for v in vers if v["step"] == "zip_phone" and v["status"] == "approved"]
        id_vers = [v for v in vers if v["step"] == "id_document" and v["status"] == "approved"]
        self.assertEqual(len(zip_vers), 1)
        self.assertEqual(len(id_vers), 1)

        # Cannot verify before approval
        agent2 = self.create_agent("Pending Agent")
        app2_payload = self.application(agent2["referralToken"], True, "ccdd0011-2233-4455-6677-8899aabbccdd")
        status, app2_res = self.request_json("/api/applications", app2_payload)
        self.assertEqual(status, 201)
        status, err = self.request_json(
            f"/api/applications/{app2_res['applicationId']}/verify",
            {"step": "zip_phone", "zipCode": "1234", "phone": "843555666"},
        )
        self.assertEqual(status, 400)
        self.assertIn("approved", err["error"])

    def test_admin_message_agents(self):
        with mock.patch.object(server, "telegram_bot_token", return_value="fake-token"):
            with mock.patch.object(server, "send_telegram_message") as mock_send:
                # 1. Test create agent with telegram chat sends welcome message with referral link
                status, agent = self.request_json(
                    "/api/admin/agents",
                    {"displayName": "TG Agent", "telegramChatId": "88776655"},
                    token=server.ADMIN_TOKEN,
                )
                self.assertEqual(status, 201)
                self.assertTrue(mock_send.called)
                mock_send.assert_any_call("88776655", mock.ANY)
                welcome_text = mock_send.call_args[0][1]
                self.assertIn(agent["referralUrl"], welcome_text)

                # 2. Test send direct message to agent
                mock_send.reset_mock()
                status, res = self.request_json(
                    "/api/admin/agents/message",
                    {"target": agent["agentId"], "message": "Importante: novas regras."},
                    token=server.ADMIN_TOKEN,
                )
                self.assertEqual(status, 200)
                self.assertEqual(res["sent"], 1)
                mock_send.assert_called_once_with("88776655", "Importante: novas regras.")

                # 3. Test send broadcast to all agents
                mock_send.reset_mock()
                status, res = self.request_json(
                    "/api/admin/agents/message",
                    {"target": "all", "message": "Aviso geral para todos."},
                    token=server.ADMIN_TOKEN,
                )
                self.assertEqual(status, 200)
                self.assertGreaterEqual(res["sent"], 1)

    def test_telegram_admin_commands(self):
        with mock.patch.object(server, "telegram_bot_token", return_value="fake-token"):
            with mock.patch.object(server, "send_telegram_message") as mock_send:
                # 1. Unauthorized user
                server.handle_telegram_message({"chat": {"id": 99999999}, "text": "/start"})
                self.assertTrue(mock_send.called)
                unauth_reply = mock_send.call_args[0][1]
                self.assertIn("do not have administrator access", unauth_reply)

                # 2. Register an agent with a Telegram Chat ID
                status, agent = self.request_json(
                    "/api/admin/agents",
                    {"displayName": "ikt", "username": "ADMIN144", "telegramChatId": "77665544"},
                    token=server.ADMIN_TOKEN,
                )
                self.assertEqual(status, 201)

                # 3. Authorized /start
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 77665544, "first_name": "ikt"},
                    "text": "/start"
                })
                start_reply = mock_send.call_args[0][1]
                self.assertIn("Welcome ikt!", start_reply)
                self.assertIn("ADMIN144", start_reply)
                self.assertIn("Role: 👤 Admin", start_reply)
                self.assertIn("?ref=ADMIN144", start_reply)
                self.assertIn("/mylink", start_reply)
                self.assertIn("/stats", start_reply)
                self.assertIn("/pending", start_reply)
                self.assertIn("/myinfo", start_reply)

                # 4. Authorized /mylink
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 77665544},
                    "text": "/mylink"
                })
                mylink_reply = mock_send.call_args[0][1]
                self.assertIn("Your Personal Link", mylink_reply)
                self.assertIn("?ref=ADMIN144", mylink_reply)

                # 4b. Test asking with plain word "link"
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 77665544},
                    "text": "link"
                })
                plain_link_reply = mock_send.call_args[0][1]
                self.assertIn("Your Personal Link", plain_link_reply)
                self.assertIn("?ref=ADMIN144", plain_link_reply)

                # 5. Authorized /stats
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 77665544},
                    "text": "/stats"
                })
                stats_reply = mock_send.call_args[0][1]
                self.assertIn("Your Statistics", stats_reply)
                self.assertIn("Admin ID: ADMIN144", stats_reply)
                self.assertIn("Total Applications:", stats_reply)

                # 6. Authorized /pending
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 77665544},
                    "text": "/pending"
                })
                pending_reply = mock_send.call_args[0][1]
                self.assertIn("Pending Applications", pending_reply)

                # 7. Authorized /myinfo
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 77665544},
                    "text": "/myinfo"
                })
                myinfo_reply = mock_send.call_args[0][1]
                self.assertIn("Your Information", myinfo_reply)
                self.assertIn("Admin ID: ADMIN144", myinfo_reply)
                self.assertIn("Role: 👤 Admin", myinfo_reply)
                self.assertIn("Status: Active", myinfo_reply)

                # 8. Unknown command
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 77665544},
                    "text": "/foobar"
                })
                unknown_reply = mock_send.call_args[0][1]
                self.assertIn("Unknown command", unknown_reply)

    def test_telegram_payment_methods_and_topup(self):
        with mock.patch.object(server, "send_telegram_message") as mock_send:
            with mock.patch.dict(os.environ, {"TELEGRAM_ADMIN_CHAT_ID": "111222333"}):
                # 1. Register an agent
                status, agent = self.request_json(
                    "/api/admin/agents",
                    {"displayName": "Agent TopUp", "username": "AGENT99", "telegramChatId": "888777666"},
                    token=server.ADMIN_TOKEN,
                )
                self.assertEqual(status, 201)

                # 2. Agent checks /topup before payment methods are set
                server.handle_telegram_message({
                    "chat": {"id": 888777666, "first_name": "Agent TopUp"},
                    "text": "/topup"
                })
                reply = mock_send.call_args[0][1]
                self.assertIn("Top-Up Payment Methods", reply)
                self.assertIn("M-Pesa Till", reply)
                self.assertIn("Airtel Money", reply)

                # 3. Agent attempts /setpayment -> denied
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 888777666},
                    "text": "/setpayment till 12345"
                })
                reply = mock_send.call_args[0][1]
                self.assertIn("Only the administrator", reply)

                # 4. Global admin configures payment methods via Telegram chat
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 111222333, "first_name": "SuperAdmin"},
                    "text": "/setpayment till 5544332"
                })
                reply = mock_send.call_args[0][1]
                self.assertIn("5544332", reply)

                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 111222333},
                    "text": "/setpayment paybill 889900 EMOLA-ACCT"
                })
                reply = mock_send.call_args[0][1]
                self.assertIn("889900", reply)
                self.assertIn("EMOLA-ACCT", reply)

                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 111222333},
                    "text": "/setpayment airtel +258871234567"
                })
                reply = mock_send.call_args[0][1]
                self.assertIn("+258871234567", reply)

                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 111222333},
                    "text": "/setpayment crypto TQn9Y2khEsLJW1ChVWFMSMe TRC20"
                })
                reply = mock_send.call_args[0][1]
                self.assertIn("TQn9Y2khEsLJW1ChVWFMSMe", reply)
                self.assertIn("TRC20", reply)

                # 5. Agent sends /start or /topup -> sees configured methods
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 888777666, "first_name": "Agent TopUp"},
                    "text": "/start"
                })
                reply = mock_send.call_args[0][1]
                self.assertIn("5544332", reply)
                self.assertIn("889900", reply)
                self.assertIn("+258871234567", reply)
                self.assertIn("TQn9Y2khEsLJW1ChVWFMSMe", reply)

                # 6. Admin API also reflects payment methods
                status, settings = self.request_json("/api/admin/settings", token=server.ADMIN_TOKEN)
                self.assertEqual(status, 200)
                pm = settings.get("paymentMethods", {})
                self.assertEqual(pm.get("mpesaTill"), "5544332")
                self.assertEqual(pm.get("mpesaPaybill"), "889900")
                self.assertEqual(pm.get("mpesaAccount"), "EMOLA-ACCT")
                self.assertEqual(pm.get("airtelMoney"), "+258871234567")
                self.assertEqual(pm.get("cryptoAddress"), "TQn9Y2khEsLJW1ChVWFMSMe")

                # 7. Update via Admin API
                status, upd = self.request_json(
                    "/api/admin/settings",
                    {"paymentMethods": {"mpesaTill": "999888", "airtelMoney": "+258870000000"}},
                    token=server.ADMIN_TOKEN,
                )
                self.assertEqual(status, 200)
                pm = server.get_payment_methods()
                self.assertEqual(pm["mpesaTill"], "999888")
                self.assertEqual(pm["airtelMoney"], "+258870000000")

    def test_telegram_callbacks_and_buttons_in_english(self):
        # 1. Test stage_buttons text
        btn_dict = server.stage_buttons("app-123", "pending")
        buttons = btn_dict["inline_keyboard"][0]
        btn_labels = [b["text"] for b in buttons]
        self.assertIn("🔍 Under Review", btn_labels)
        self.assertIn("✅ Approve Loan", btn_labels)
        self.assertIn("❌ Reject", btn_labels)

        # 2. Test handle_telegram_callback
        agent = self.create_agent("Callback Agent")
        app_payload = self.application(agent["referralToken"], True, "9a5c4584-465b-4d8f-89f6-504f39128ba2")
        status, app_res = self.request_json("/api/applications", app_payload)
        self.assertEqual(status, 201)
        app_id = app_res["applicationId"]

        with mock.patch.object(server, "answer_telegram_callback") as mock_answer:
            with mock.patch.object(server, "edit_telegram_message") as mock_edit:
                server.handle_telegram_callback({
                    "id": "q123",
                    "data": f"stage:approved:{app_id}",
                    "message": {
                        "message_id": 999,
                        "chat": {"id": 12345},
                        "text": f"New E-Mola application\nApplication reference: {app_id}\nStatus: Pending",
                    }
                })
                self.assertTrue(mock_answer.called)
                ans_text = mock_answer.call_args[1]["text"]
                self.assertIn("Decision recorded: ✅ Approved", ans_text)

                self.assertTrue(mock_edit.called)
                edited_text = mock_edit.call_args[0][2]
                self.assertIn("📋 Decision: ✅ Approved", edited_text)

        # 3. Test handle_verify_callback
        status, v_res = self.request_json(
            f"/api/applications/{app_id}/verify",
            {"step": "zip_phone", "zipCode": "1234", "phone": "841234567"},
        )
        self.assertEqual(status, 201)
        ver_id = v_res["verificationId"]

        with mock.patch.object(server, "answer_telegram_callback") as mock_answer:
            with mock.patch.object(server, "edit_telegram_message") as mock_edit:
                server.handle_telegram_callback({
                    "id": "q456",
                    "data": f"verify:approve:{ver_id}",
                    "message": {
                        "message_id": 1000,
                        "chat": {"id": 12345},
                        "text": "📋 Identity Verification — 📍 PIN + Phone",
                    }
                })
                self.assertTrue(mock_answer.called)
                ans_text = mock_answer.call_args[1]["text"]
                self.assertIn("Verification PIN + Phone: ✅ Approved", ans_text)

                self.assertTrue(mock_edit.called)
                edited_text = mock_edit.call_args[0][2]
                self.assertIn("📋 Decision: ✅ Approved", edited_text)

    def test_mylink_matches_admin_generated_link(self):
        with mock.patch.object(server, "send_telegram_message") as mock_send:
            with mock.patch.dict(os.environ, {"TELEGRAM_ADMIN_CHAT_ID": "444555666"}):
                # 1. Update settings with public domain
                status, s_res = self.request_json(
                    "/api/admin/settings",
                    {"publicAppUrl": "https://z-pgx8.onrender.com"},
                    token=server.ADMIN_TOKEN,
                )
                self.assertEqual(status, 200)

                # 2. Admin creates an agent on the admin dashboard
                status, agent = self.request_json(
                    "/api/admin/agents",
                    {"displayName": "Link Match Agent", "telegramChatId": "999111222"},
                    token=server.ADMIN_TOKEN,
                )
                self.assertEqual(status, 201)
                admin_gen_url = agent["referralUrl"]
                self.assertTrue(admin_gen_url.startswith("https://z-pgx8.onrender.com/?ref="))

                # 3. Agent checks /mylink on Telegram
                server.handle_telegram_message({
                    "chat": {"id": 999111222, "first_name": "Link Match Agent"},
                    "text": "/mylink"
                })
                reply = mock_send.call_args[0][1]
                # The link sent in Telegram must EXACTLY match the link generated in the admin
                self.assertIn(admin_gen_url, reply)

                # 4. Agent checks /start on Telegram -> also includes the exact link
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 999111222, "first_name": "Link Match Agent"},
                    "text": "/start"
                })
                start_reply = mock_send.call_args[0][1]
                self.assertIn(admin_gen_url, start_reply)

                # 5. Global Admin uses /seturl directly in Telegram
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 444555666, "first_name": "Admin"},
                    "text": "/seturl https://custom-domain.com"
                })
                seturl_reply = mock_send.call_args[0][1]
                self.assertIn("https://custom-domain.com", seturl_reply)

                # 6. Now agent asks for /mylink again -> uses new domain!
                mock_send.reset_mock()
                server.handle_telegram_message({
                    "chat": {"id": 999111222},
                    "text": "/mylink"
                })
                updated_reply = mock_send.call_args[0][1]
                self.assertIn(f"https://custom-domain.com/?ref={agent['referralToken']}", updated_reply)


if __name__ == "__main__":
    unittest.main()