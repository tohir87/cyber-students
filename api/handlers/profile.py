from tornado.escape import json_decode
from tornado.web import authenticated

from .auth import AuthHandler
from ..crypto import encrypt, decrypt


class ProfileHandler(AuthHandler):

    @authenticated
    async def get(self):
        user = await self.db.users.find_one(
            {'email': self.current_user['email']},
            {'profile': 1}
        )
        profile = (user.get('profile') or {}) if user else {}

        result = {}
        for field in ('address', 'dateOfBirth', 'phoneNumber'):
            raw = profile.get(field)
            result[field] = decrypt(raw) if raw else None

        disabilities_enc = profile.get('disabilities') or []
        result['disabilities'] = [decrypt(d) for d in disabilities_enc]

        self.set_status(200)
        self.response.update(result)
        self.write_json()

    @authenticated
    async def post(self):
        await self._upsert_profile()

    @authenticated
    async def put(self):
        await self._upsert_profile()

    async def _upsert_profile(self):
        try:
            body = json_decode(self.request.body)
        except Exception:
            self.send_error(400, message='Unable to parse JSON.')
            return

        profile = {}
        for field in ('address', 'dateOfBirth', 'phoneNumber'):
            if field in body:
                profile[field] = encrypt(str(body[field]))

        disabilities = body.get('disabilities', [])
        if not isinstance(disabilities, list):
            self.send_error(400, message='disabilities must be a list.')
            return
        profile['disabilities'] = [encrypt(str(d)) for d in disabilities]

        await self.db.users.update_one(
            {'email': self.current_user['email']},
            {'$set': {'profile': profile}}
        )

        self.set_status(200)
        self.write_json()
