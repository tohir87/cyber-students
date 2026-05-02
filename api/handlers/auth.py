from datetime import datetime, timezone

from .base import BaseHandler
from ..crypto import decrypt, hash_token


class AuthHandler(BaseHandler):

    async def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except Exception:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        user = await self.db.users.find_one({
            'token': hash_token(token)
        }, {
            'email': 1,
            'fullName': 1,
            'expiresIn': 1
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = datetime.now(timezone.utc).timestamp()
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        full_name_enc = user.get('fullName')
        self.current_user = {
            'email': user['email'],
            'full_name': decrypt(full_name_enc) if full_name_enc else None,
        }
