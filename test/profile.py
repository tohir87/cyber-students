from json import dumps
from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.profile import ProfileHandler
from api.crypto import encrypt, hash_password, hash_token

from .base import BaseTest


class ProfileHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/profile', ProfileHandler)])
        super().setUpClass()

    async def register(self):
        await self.get_app().db.users.insert_one({
            'email': self.email,
            'password': hash_password(self.password),
            'fullName': encrypt(self.full_name),
            'consentGiven': True,
        })

    async def login(self):
        await self.get_app().db.users.update_one(
            {'email': self.email},
            {'$set': {'token': hash_token(self.token), 'expiresIn': 2147483647}}
        )

    def setUp(self):
        super().setUp()
        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.full_name = 'testFullName'
        self.token = 'testToken'
        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_create_profile(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {
            'address': '123 Test Street',
            'dateOfBirth': '1990-01-01',
            'phoneNumber': '555-1234',
            'disabilities': ['dyslexia'],
        }
        response = self.fetch('/profile', method='POST', body=dumps(body), headers=headers)
        self.assertEqual(200, response.code)

    def test_get_profile(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {
            'address': '123 Test Street',
            'dateOfBirth': '1990-01-01',
            'phoneNumber': '555-1234',
            'disabilities': ['dyslexia'],
        }
        self.fetch('/profile', method='POST', body=dumps(body), headers=headers)

        response = self.fetch('/profile', headers=headers)
        self.assertEqual(200, response.code)

        result = json_decode(response.body)
        self.assertEqual('123 Test Street', result['address'])
        self.assertEqual('1990-01-01', result['dateOfBirth'])
        self.assertEqual('555-1234', result['phoneNumber'])
        self.assertEqual(['dyslexia'], result['disabilities'])

    def test_update_profile(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {
            'address': '123 Test Street',
            'dateOfBirth': '1990-01-01',
            'phoneNumber': '555-1234',
            'disabilities': [],
        }
        self.fetch('/profile', method='POST', body=dumps(body), headers=headers)

        body['address'] = '456 New Avenue'
        response = self.fetch('/profile', method='PUT', body=dumps(body), headers=headers)
        self.assertEqual(200, response.code)

        response = self.fetch('/profile', headers=headers)
        result = json_decode(response.body)
        self.assertEqual('456 New Avenue', result['address'])

    def test_profile_without_token(self):
        response = self.fetch('/profile')
        self.assertEqual(400, response.code)

    def test_profile_without_consent(self):
        no_consent_email = 'noconsent@test.com'
        no_consent_token = 'noConsentToken'

        async def setup():
            await self.get_app().db.users.insert_one({
                'email': no_consent_email,
                'password': hash_password('testPassword'),
                'fullName': encrypt('No Consent User'),
                'consentGiven': False,
                'token': hash_token(no_consent_token),
                'expiresIn': 2147483647,
            })

        IOLoop.current().run_sync(setup)

        headers = HTTPHeaders({'X-Token': no_consent_token})
        body = {
            'address': '1 Secret Lane',
            'dateOfBirth': '2000-01-01',
            'phoneNumber': '000-0000',
            'disabilities': [],
        }
        response = self.fetch('/profile', method='POST', body=dumps(body), headers=headers)
        self.assertEqual(403, response.code)
