from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth.models import User

class JWTTokenTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.token_url = '/api/token/'  # JWT-tokenin hakupolku
        self.refresh_url = '/api/token/refresh/'  # JWT-tokenin päivityspolku
        self.protected_url = '/api/posts/'  

    def test_obtain_token(self):
        data = {"username": "testuser", "password": "testpassword"}
        response = self.client.post(self.token_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

        # Tallennetaan token
        self.access_token = response.data["access"]
        self.refresh_token = response.data["refresh"]

    def test_access_protected_view(self):
        # Hae JWT-token
        data = {"username": "testuser", "password": "testpassword"}
        response = self.client.post(self.token_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        access_token = response.data["access"]

       
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_refresh_token(self):
        # JWT-tokenin haku
        data = {"username": "testuser", "password": "testpassword"}
        response = self.client.post(self.token_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        refresh_token = response.data["refresh"]

        
        response = self.client.post(self.refresh_url, {"refresh": refresh_token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_invalid_token_access(self):
        # Testataan tokenia joka on invalid
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalidtoken')
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)