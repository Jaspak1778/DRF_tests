from rest_framework.permissions import IsAuthenticated, AllowAny, BasePermission
from rest_framework.authentication import SessionAuthentication
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist

from .models import Post, Comment, Like, User
from .serializers import (
    PostSerializer, CommentSerializer, LikeSerializer, 
    SignupSerializer, UserSerializer
)
#parantaa yhteensopivuutta kun siirretään moduli alemmaksi
from rest_framework.decorators import api_view, permission_classes

class MyTokenObtainPairView(TokenObtainPairView):
    permission_classes = (AllowAny,)

class MyTokenRefreshView(TokenRefreshView):
    permission_classes = (AllowAny,)

@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token_view(request):
    refresh_token = request.COOKIES.get('refresh_token')
    if not refresh_token:
        return Response({'error': 'Refresh token missing'}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        refresh = RefreshToken(refresh_token)
        access_token = str(refresh.access_token)
    except Exception:
        return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
    response = Response({'message': 'Token refreshed'}, status=status.HTTP_200_OK)
    response.set_cookie('access_token', access_token, httponly=True, secure=True, samesite='Lax')
    return response

class IsSuperuserOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        if request.method == 'PATCH' and 'is_superuser' in request.data:
            return request.user.is_superuser
        return True

class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.all().order_by('-updated')
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        post = get_object_or_404(Post, id=self.request.data.get('post'))
        serializer.save(commenter=self.request.user, post=post)

class LikeViewSet(viewsets.ModelViewSet):
    queryset = Like.objects.all()
    serializer_class = LikeSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        post = get_object_or_404(Post, id=self.request.data.get('post'))
        serializer.save(liker=self.request.user, post=post)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsSuperuserOrReadOnly]
    
    def get_queryset(self):
        user = self.request.user
        return User.objects.all() if user.is_staff or user.is_superuser else User.objects.filter(id=user.id)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile_view(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(request, username=username, password=password)
    if user:
        refresh = RefreshToken.for_user(user)
        response = Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        response.set_cookie('access_token', str(refresh.access_token), httponly=True, secure=True, samesite='Lax')
        response.set_cookie('refresh_token', str(refresh), httponly=True, secure=True, samesite='Lax')
        return response
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    if User.objects.filter(username=request.data.get('username')).exists():
        return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
    if User.objects.filter(email=request.data.get('email')).exists():
        return Response({'error': 'Email already in use'}, status=status.HTTP_400_BAD_REQUEST)
    
    serializer = SignupSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({'message': 'User created successfully!'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def logout_view(request):
    response = Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)
    response.set_cookie('access_token', '', httponly=True, secure=True, samesite='Lax')
    response.set_cookie('refresh_token', '', httponly=True, secure=True, samesite='Lax')
    try:
        refresh_token = request.COOKIES.get('refresh_token')
        if refresh_token:
            RefreshToken(refresh_token).blacklist()
    except Exception:
        pass
    return response
