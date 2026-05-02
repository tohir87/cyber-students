from datetime import datetime, timezone
from tornado.escape import json_decode

from .base import BaseHandler
from ..crypto import encrypt, hash_password


class RegistrationHandler(BaseHandler):

    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
            full_name = body.get('fullName')
            if full_name is None:
                full_name = email
            if not isinstance(full_name, str):
                raise Exception('Full name must be a string')
            consent_given = body.get('consentGiven', False)
        except Exception:
            self.send_error(400, message='You must provide an email address, password and full name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not full_name:
            self.send_error(400, message='The full name is invalid!')
            return

        if consent_given is not True:
            self.send_error(400, message='You must provide consent to process your personal data (GDPR).')
            return

        user = await self.db.users.find_one({
          'email': email
        })

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        await self.db.users.insert_one({
            'email': email,
            'password': hash_password(password),
            'fullName': encrypt(full_name),
            'consentGiven': True,
            'consentTimestamp': datetime.now(timezone.utc).isoformat(),
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['fullName'] = full_name

        self.write_json()
