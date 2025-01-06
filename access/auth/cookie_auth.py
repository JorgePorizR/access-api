from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.authtoken.admin import User

def set_cookie(response, key, value, expires):
    response.set_cookie(
        key,
        value,
        httponly=True,
        secure=True,
        samesite='None',
        max_age=expires,
    )

class CookieTokenObtainPairView(APIView):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user is None:
            return Response({'error': 'Unauthenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        tokens = RefreshToken.for_user(user)
        tokens['iss'] = 'http://localhost:8000'
        tokens['aud'] = 'http://localhost:8000'
        tokens['user_id'] = user.id
        tokens['username'] = user.username
        tokens['email'] = user.email
        tokens['groups'] = [group.name for group in user.groups.all()]
        print(tokens)
        response = Response({
            'message': 'Token Created Successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'is_admin_usuario': user.groups.filter(id=1).exists(),
                'is_cliente': user.groups.filter(id=2).exists(),
                'is_admin_recarga': user.groups.filter(id=3).exists(),
                'is_admin_partido': user.groups.filter(id=4).exists(),
            }
        }, status=status.HTTP_200_OK)

        set_cookie(response, 'access', str(tokens.access_token), 5 * 60 * 60)  # Access token expires in 5 hour
        set_cookie(response, 'refresh', str(tokens), 24 * 60 * 60)       # Refresh token expires in 1 day
        return response

class CookieTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh')

        if not refresh_token:
            return Response({'detail': 'Refresh token not found in cookies'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data={'refresh': refresh_token})

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        access_token = serializer.validated_data['access']

        response = Response({'message': 'Token Refreshed Successfully'}, status=status.HTTP_200_OK)
        set_cookie(response, 'access', str(access_token),  5 * 60 * 60)
        return response

class CookieTokenLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        response = Response({'message': 'Logout Successful'}, status=status.HTTP_200_OK)
        response.delete_cookie('access')
        response.delete_cookie('refresh')
        return response

class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        groups = [{"id": group.id, "name": group.name} for group in user.groups.all()]
        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "groups": groups,
            'is_admin_usuario': user.groups.filter(id=1).exists(),
            'is_cliente': user.groups.filter(id=2).exists(),
            'is_admin_recarga': user.groups.filter(id=3).exists(),
            'is_admin_partido': user.groups.filter(id=4).exists(),
        })