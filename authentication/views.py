from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import SignupSerializer

# Create your views here.

# THE SIGNUP VIEW
class SignupView(APIView):
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg": "User Created!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# THE LOGIN VIEW
class LoginView(APIView):
    def post(self, request):
        # 1. Grab username/password from the Postman request
        username = request.data.get('username')
        password = request.data.get('password')

        # 2. Check if they match a user in the database
        user = authenticate(username=username, password=password)

        if user:
            # 3. Success! Generate the Tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),  # The long-term token
                'access': str(refresh.access_token),  # The short-term token
            })

        # 4. Fail!
        return Response({"error": "Wrong credentials"}, status=status.HTTP_401_UNAUTHORIZED)